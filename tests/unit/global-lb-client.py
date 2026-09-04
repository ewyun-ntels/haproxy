#!/usr/bin/env python3
"""Test the real HAProxy fd/task transport using a test-only EXTRA_OBJS driver.

Usage: python3 tests/unit/global-lb-client.py DRIVER_BINARY [STORE_IMAGE]
The optional locally available Docker image is tested in a disposable container.
No connection is made to an existing Redis/Valkey deployment.
UD-007 r6-async-client-20260904 / UD-011 r4-worker-identity-20260904.
"""
import contextlib
import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid


def listener(family=socket.AF_INET, listen=True, backlog=10):
    sock = socket.socket(family)
    sock.bind(("::1" if family == socket.AF_INET6 else "127.0.0.1", 0))
    if listen:
        sock.listen(backlog)
    sock.settimeout(5)
    return sock


def read(stream):
    line = stream.readline()
    if not line.endswith(b"\r\n"):
        raise AssertionError(f"incomplete RESP: {line!r}")
    kind, data = line[:1], line[1:-2]
    if kind == b"*":
        return [read(stream) for _ in range(int(data))]
    if kind == b"$":
        length = int(data)
        if length == -1:
            return None
        result = stream.read(length)
        assert len(result) == length and stream.read(2) == b"\r\n"
        return result
    if kind == b":":
        return int(data)
    if kind == b"+":
        return data
    raise AssertionError(f"unexpected RESP: {line!r}")


def encode(args):
    return b"*%d\r\n" % len(args) + b"".join(
        b"$%d\r\n" % len(x) + x + b"\r\n" for x in args
    )


def fixture(store, plan, errors):
    try:
        count = 2 if plan == "reconnect" else 1
        for attempt in range(count):
            peer, _ = store.accept()
            with peer:
                peer.settimeout(5)
                if plan == "stop-ready":
                    assert peer.recv(1) == b""
                    continue
                if plan == "idle":
                    peer.sendall(b"+unsolicited\r\n")
                    assert peer.recv(1) == b""
                    continue
                with peer.makefile("rb") as stream:
                    if plan == "large":
                        time.sleep(0.05)  # tiny SO_SNDBUF in C driver => EAGAIN
                    command = read(stream)
                    assert command[0] == b"ECHO"
                    assert command[1] == (b"first" if attempt == 0 else b"fresh") or plan == "large"
                    if plan == "reconnect" and attempt == 0:
                        continue  # unconfirmed command must not be replayed
                    if plan == "eof":
                        continue
                    if plan == "stop-pending":
                        assert peer.recv(1) == b""
                        continue
                    if plan == "reset":
                        peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                        continue
                    if plan == "timeout":
                        peer.sendall(b"$5\r\nf")
                        time.sleep(0.35)  # fragments must not reset command deadline
                        assert peer.recv(1) == b""
                        continue
                    if plan == "malformed":
                        reply = b":not-an-integer\r\n"
                    elif plan == "extra":
                        reply = b"$5\r\nfirst\r\n+extra\r\n"
                    elif plan == "rxlimit":
                        reply = b"$1000000\r\n"
                    elif plan == "error":
                        reply = b"-ERR test-command-error\r\n"
                    else:
                        reply = b"$%d\r\n" % len(command[1]) + command[1] + b"\r\n"
                    if plan == "fragment":
                        for byte in reply:
                            peer.sendall(bytes([byte]))
                            time.sleep(0.002)
                    elif plan == "large":
                        for start in range(0, len(reply), 1733):
                            peer.sendall(reply[start:start+1733])
                    else:
                        peer.sendall(reply)
                    assert peer.recv(1) == b"", "unexpected queued/replayed command"
        store.settimeout(0.25)
        try:
            peer, _ = store.accept()
        except socket.timeout:
            pass
        else:
            peer.close()
            raise AssertionError("unexpected reconnect after terminal stop")
    except BaseException as error:
        errors.append(error)


def run(binary, plan, expected_error=None, family=socket.AF_INET,
        store_address=None, master_worker=False, connect_full=False, groups=1):
    errors, blockers = [], []
    thread = proc = None
    output = b""
    prefix = "client-test:" + uuid.uuid4().hex
    with contextlib.ExitStack() as stack:
        frontend, admin, backend = [stack.enter_context(listener()) for _ in range(3)]
        if store_address is None:
            store = stack.enter_context(listener(family, plan != "backoff", 1 if connect_full else 10))
            store_address = (store.getsockname()[0], store.getsockname()[1])
            if connect_full:
                # Fill this test listener's queue; no firewall/route changes.
                for _ in range(2):
                    blockers.append(stack.enter_context(socket.create_connection(store_address, 1)))
            elif plan != "backoff":
                thread = threading.Thread(target=fixture, args=(store, plan, errors), daemon=True)
                thread.start()
        host, port = store_address
        address = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
        command_timeout = "2s" if plan == "large" else "150ms"
        config = f"""global
 nbthread 4
 thread-groups {groups}
 stats socket fd@{admin.fileno()} level admin
 global-lb state-store {address}
 global-lb instance-id test/ha-0
 global-lb key-prefix {prefix}
 global-lb timeout connect 100ms
 global-lb timeout command {command_timeout}
 global-lb reconnect 40ms 160ms
 global-lb reconnect-jitter 0
defaults
 mode tcp
 timeout connect 1s
 timeout client 5s
 timeout server 5s
frontend fe
 bind fd@{frontend.fileno()}
 default_backend be
backend be
 balance roundrobin
 server s1 127.0.0.1:{backend.getsockname()[1]}
"""
        env = dict(os.environ, GLB_CLIENT_TEST_PLAN=plan)
        if expected_error is not None:
            env["GLB_CLIENT_TEST_ERROR"] = str(expected_error)
        args = [binary, "-db", "-f", "/dev/stdin"]
        if master_worker:
            args.insert(1, "-W")
        proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, env=env,
                                pass_fds=(frontend.fileno(), admin.fileno()))
        proc.stdin.write(config.encode())
        proc.stdin.close()
        try:
            # Existing traffic/CLI must work while store transport is active/failing.
            with socket.create_connection(frontend.getsockname(), 3) as traffic:
                traffic.settimeout(3)
                traffic.sendall(b"unaffected-traffic")
                peer, _ = backend.accept()
                with peer:
                    peer.settimeout(3)
                    assert peer.recv(100) == b"unaffected-traffic"
                    peer.sendall(b"unaffected-reply")
                    assert traffic.recv(100) == b"unaffected-reply"
                    with socket.create_connection(admin.getsockname(), 3) as cli:
                        cli.settimeout(3)
                        cli.sendall(b"show global-lb local\n")
                        data = b""
                        while True:
                            chunk = cli.recv(65536)
                            if not chunk:
                                break
                            data += chunk
                        assert b"be\ts1\t" in data and b"\tRUNNING\t1\t1" in data, data
            with selectors.DefaultSelector() as selector:
                selector.register(proc.stdout, selectors.EVENT_READ)
                deadline = time.monotonic() + 7
                while b"GLB_TEST DONE" not in output and time.monotonic() < deadline:
                    for key, _ in selector.select(0.1):
                        data = os.read(key.fileobj.fileno(), 65536)
                        if not data:
                            raise AssertionError("driver exited: " + output.decode())
                        output += data
                assert b"GLB_TEST DONE" in output, output.decode()
            if thread:
                thread.join(3)
                assert not thread.is_alive(), "server fixture did not finish"
            assert not errors, errors
            text = output.decode()
            done = re.search(r"DONE ready=(\d+) reply=(\d+) failed=(\d+) uuid=([^ ]+) seq=(\d+)", text)
            assert done, text
            ready, replies, failed, generation, sequence = done.groups()
            if plan == "backoff":
                assert (ready, replies, failed) == ("0", "0", "4"), text
                times = [int(x) for x in re.findall(r"FAIL error=\d+ time=(\d+)", text)]
                for actual, expected in zip([b-a for a, b in zip(times, times[1:])], [40, 80, 160]):
                    assert expected - 5 <= actual <= expected + 100, (times, expected)
            elif plan == "reconnect":
                assert (ready, replies, failed, sequence) == ("2", "1", "1", "2"), text
            elif plan == "store":
                assert (ready, replies, failed, sequence) == ("1", "3", "0", "3"), text
            elif expected_error is not None:
                assert replies == "0" and failed == "1", text
            elif plan in ("stop-ready", "stop-pending", "stop-connecting"):
                assert replies == "0" and failed == "0", text
            else:
                assert (ready, replies, failed) == ("1", "1", "0"), text
            print(f"PASS: {plan} family={family} master_worker={master_worker} groups={groups}; TCP/CLI unchanged", flush=True)
            return prefix, generation
        except BaseException:
            print(output.decode(), file=sys.stderr)
            raise
        finally:
            proc.send_signal(signal.SIGUSR1) if not master_worker else proc.terminate()
            try:
                proc.wait(5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()
                raise AssertionError("HAProxy did not stop")
            stderr = proc.stderr.read().decode()
            assert proc.returncode == 0, (proc.returncode, stderr)
            assert all(marker not in stderr for marker in [
                "Assertion", "BUG", "runtime error:", "ERROR: AddressSanitizer",
                "ERROR: LeakSanitizer", "AddressSanitizer:DEADLYSIGNAL"
            ]), stderr


def store_test(binary, image):
    token = uuid.uuid4().hex
    container = None
    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True).strip()
    try:
        server = "valkey-server" if image.split("/")[-1].startswith("valkey:") else "redis-server"
        container = docker("run", "--rm", "--pull=never", "-d", "--label",
                           "global-lb-client-test=" + token, "-p", "127.0.0.1::6379",
                           image, server, "--save", "", "--appendonly", "no")
        info = json.loads(docker("inspect", container))[0]
        port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
        for _ in range(100):
            try:
                with socket.create_connection(("127.0.0.1", port), 1) as peer:
                    peer.sendall(encode([b"PING"]))
                    with peer.makefile("rb") as stream:
                        assert read(stream) == b"PONG"
                break
            except (OSError, AssertionError):
                time.sleep(0.05)
        else:
            raise AssertionError("test store readiness timeout")
        prefix, gen = run(binary, "store", store_address=("127.0.0.1", port))
        key = f"glb:v1:{prefix.encode().hex()}:{b'test/ha-0'.hex()}".encode()
        with socket.create_connection(("127.0.0.1", port), 2) as peer:
            with peer.makefile("rb") as stream:
                for command, expected in [
                    ([b"EXISTS", key + b":snapshot"], 0),
                    ([b"HGET", key + b":owner", b"writer_generation"], gen.encode()),
                    ([b"HGET", key + b":owner", b"snapshot_sequence"], b"3"),
                    ([b"PTTL", key + b":owner"], -1),
                ]:
                    peer.sendall(encode(command))
                    assert read(stream) == expected
        print(f"PASS: {image} actual async START/UPDATE/DELETE, retained UUID/sequence", flush=True)
    finally:
        if container:
            info = json.loads(docker("inspect", container))[0]
            assert info["Config"]["Labels"]["global-lb-client-test"] == token
            docker("stop", "--time", "1", container)


if __name__ == "__main__":
    binary = sys.argv[1]
    if len(sys.argv) > 2:
        store_test(binary, sys.argv[2])
    else:
        generations = []
        for plan in ["fragment", "large", "error", "reconnect", "stop-ready", "stop-pending"]:
            generations.append(run(binary, plan)[1])
        assert len(set(generations)) == len(generations), "new process must have new UUID"
        for plan, error in [("malformed", 6), ("extra", 6), ("idle", 6),
                            ("rxlimit", 6), ("timeout", 3), ("eof", 5), ("reset", 4)]:
            run(binary, plan, error)
        run(binary, "backoff", 4)
        run(binary, "connect-timeout", 2, connect_full=True)
        run(binary, "stop-connecting", connect_full=True)
        run(binary, "fragment", family=socket.AF_INET6)
        run(binary, "fragment", master_worker=True)
        run(binary, "fragment", groups=2)

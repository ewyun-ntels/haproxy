#!/usr/bin/env python3
"""Automatic publisher integration, no test-only C driver.
Usage: global-lb-publish.py BINARY [locally cached Redis/Valkey image]
Owns isolated loopback listeners/container/keys; never touches user's store.
UD-007 r7 / UD-005 r6, 2026-09-04.
"""
import contextlib
from concurrent.futures import ThreadPoolExecutor
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("transport_test", Path(__file__).with_name("global-lb-client.py"))
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)
encode, read = helpers.encode, helpers.read


def wait(test, seconds=5):
    deadline = time.monotonic() + seconds
    result = None
    while time.monotonic() < deadline:
        result = test()
        if result:
            return result
        time.sleep(0.02)
    raise AssertionError(f"condition timed out; last result={result!r}")


def command(address, *args):
    with socket.create_connection(address, 2) as sock:
        sock.settimeout(2)
        with sock.makefile("rb") as stream:
            sock.sendall(encode([x if isinstance(x, bytes) else str(x).encode() for x in args]))
            return read(stream)


def listener(host="127.0.0.1", family=socket.AF_INET):
    sock = socket.socket(family)
    sock.bind((host, 0))
    sock.listen(128)
    sock.settimeout(0.2)
    return sock


class Echo:
    def __init__(self, host="127.0.0.1", family=socket.AF_INET):
        self.sock = listener(host, family)
        self.address = self.sock.getsockname()[:2]
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                peer, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            threading.Thread(target=self.echo, args=(peer,), daemon=True).start()

    def echo(self, peer):
        with peer:
            peer.settimeout(0.2)
            while not self.stop.is_set():
                try:
                    data = peer.recv(65536)
                    if not data:
                        return
                    peer.sendall(data)
                except socket.timeout:
                    continue
                except OSError:
                    return

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(1)


class HA:
    def __init__(self, binary, store, echo, *, dns="", algorithm="global-leastconn", master=False):
        self.front = listener()
        self.other = listener()
        self.native = listener()
        self.admin = listener()
        self.prefix = "publish-test/" + uuid.uuid4().hex
        self.instance = "test/ha-0"
        self.key = f"glb:v1:{self.prefix.encode().hex()}:{self.instance.encode().hex()}"
        config = f"""global
 nbthread 4
 stats socket fd@{self.admin.fileno()} level admin
 global-lb state-store {store}
 global-lb key-prefix {self.prefix}
 global-lb instance-id {self.instance}
defaults
 mode tcp
 timeout connect 200ms
 timeout client 30s
 timeout server 30s
frontend fe
 bind fd@{self.front.fileno()}
 default_backend be
frontend fe_other
 bind fd@{self.other.fileno()}
 default_backend be_other
frontend fe_native
 bind fd@{self.native.fileno()}
 default_backend be_native
backend be
 balance {algorithm}
 server-template s 1-2 127.0.0.1:{echo.address[1]}
backend be_other
 balance {algorithm}
 server s1 127.0.0.1:{echo.address[1]}
backend be_native
 balance roundrobin
 server s1 127.0.0.1:{echo.address[1]}
{dns}
"""
        args = [binary, "-db", "-f", "/dev/stdin"]
        if master:
            args.insert(1, "-W")
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE,
                                     pass_fds=tuple(s.fileno() for s in (self.front, self.other, self.native, self.admin)))
        self.proc.stdin.write(config.encode())
        self.proc.stdin.close()

    def cli(self, text):
        with socket.create_connection(self.admin.getsockname(), 2) as sock:
            sock.settimeout(2)
            sock.sendall(text.encode() + b"\n")
            result = b""
            while True:
                data = sock.recv(65536)
                if not data:
                    return result
                result += data

    def connect(self, frontend=None):
        sock = socket.create_connection((frontend or self.front).getsockname(), 2)
        sock.settimeout(3)
        self.probe(sock)
        return sock

    def probe(self, sock):
        sock.sendall(b"preserved-tcp")
        assert sock.recv(100) == b"preserved-tcp"

    def close(self, crash=False):
        if self.proc.poll() is None:
            self.proc.send_signal(signal.SIGKILL if crash else signal.SIGUSR1)
        self.proc.wait(timeout=5)
        out = self.proc.stdout.read() + self.proc.stderr.read()
        for sock in (self.front, self.other, self.native, self.admin):
            sock.close()
        assert not any(x in out for x in (b"Assertion", b"BUG", b"AddressSanitizer", b"runtime error:")), out
        if not crash:
            assert self.proc.returncode == 0, (self.proc.returncode, out)


def snapshot(address, ha):
    values = command(address, "HGETALL", ha.key + ":snapshot")
    return dict(zip(values[::2], values[1::2]))


def counts(address, ha):
    return {k.decode(): int(v) for k, v in snapshot(address, ha).items() if k.startswith(b"c:")}


def lifecycle(binary, address):
    with contextlib.ExitStack() as stack:
        a, b = Echo(), Echo("127.0.0.2")
        stack.callback(a.close)
        stack.callback(b.close)
        ha = HA(binary, "%s:%s" % address, a)
        stack.callback(ha.close)
        wait(lambda: snapshot(address, ha))
        first = snapshot(address, ha)
        writer = first[b"writer_generation"]
        time.sleep(0.7)
        assert int(snapshot(address, ha)[b"snapshot_sequence"]) >= int(first[b"snapshot_sequence"]) + 2
        peers = [ha.connect() for _ in range(8)]
        for peer in peers:
            stack.callback(peer.close)
        other = stack.enter_context(ha.connect(ha.other))
        native = stack.enter_context(ha.connect(ha.native))
        ka = f"c:be|127.0.0.1:{a.address[1]}"
        kb = f"c:be|127.0.0.2:{b.address[1]}"
        ko = f"c:be_other|127.0.0.1:{a.address[1]}"
        wait(lambda: counts(address, ha) == {ka: 8, ko: 1})
        assert b"be_native\ts1\t" in ha.cli("show global-lb local")
        for slot in ("s1", "s2"):
            answer = ha.cli(f"set server be/{slot} addr 127.0.0.2 port {b.address[1]}")
            assert b"changed" in answer, answer
        wait(lambda: ha.cli("show global-lb local").count(b"127.0.0.2:") == 2)
        fresh = [ha.connect() for _ in range(3)]
        for peer in fresh:
            stack.callback(peer.close)
        wait(lambda: counts(address, ha) == {ka: 8, kb: 3, ko: 1})
        for peer in peers + fresh:
            ha.probe(peer)  # remapping MUST NOT close old TCP connections
        peers[0].close()
        wait(lambda: counts(address, ha) == {ka: 7, kb: 3, ko: 1})
        before = int(snapshot(address, ha)[b"snapshot_sequence"])
        command(address, "CLIENT", "KILL", "TYPE", "normal", "SKIPME", "yes")
        peers[1].close()
        wait(lambda: counts(address, ha) == {ka: 6, kb: 3, ko: 1})
        after = snapshot(address, ha)
        assert after[b"writer_generation"] == writer
        assert int(after[b"snapshot_sequence"]) > before
        # Only this test's two exact keys are removed to simulate memory loss.
        command(address, "DEL", ha.key + ":owner", ha.key + ":snapshot")
        wait(lambda: counts(address, ha) == {ka: 6, kb: 3, ko: 1})
        assert snapshot(address, ha)[b"writer_generation"] == writer
        assert command(address, "PTTL", ha.key + ":owner") == -1
        ttl = command(address, "PTTL", ha.key + ":snapshot")
        assert 2000 < ttl <= 3000, ttl
        # Other UUID rejects UPDATE without refreshing snapshot TTL.
        command(address, "HSET", ha.key + ":owner", "writer_generation", str(uuid.uuid4()))
        frozen = snapshot(address, ha)
        time.sleep(0.7)
        assert snapshot(address, ha) == frozen
        assert command(address, "PTTL", ha.key + ":snapshot") < ttl - 500
        for peer in peers + fresh:
            peer.close()
        other.close()
        native.close()
        command(address, "HSET", ha.key + ":owner", "writer_generation", writer)
        wait(lambda: counts(address, ha) == {})
        wait(lambda: snapshot(address, ha)[b"snapshot_sequence"] != frozen[b"snapshot_sequence"])
        assert counts(address, ha) == {}
        assert ha.proc.poll() is None
    wait(lambda: command(address, "EXISTS", ha.key + ":snapshot") == 0, 4)
    assert command(address, "EXISTS", ha.key + ":owner") == 1
    print("PASS: 300ms, opt-in, duplicate slots, IP remap with live TCP, close, fresh reconnect, UUID, memory loss, fencing, empty replace, TTL", flush=True)


class DNS:
    def __init__(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self.answer = None  # NXDOMAIN until test makes the store resolvable
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        while not self.stop.is_set():
            try:
                packet, addr = self.sock.recvfrom(4096)
            except socket.timeout:
                continue
            except OSError:
                return
            end = 12
            while packet[end]:
                end += packet[end] + 1
            end += 5
            question = packet[12:end]
            qtype = struct.unpack("!H", question[-4:-2])[0]
            answer = b""
            if self.answer and qtype == 1:
                answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 1, 4) + socket.inet_aton(self.answer)
            header = packet[:2] + struct.pack("!HHHHH", 0x8180 if self.answer else 0x8183, 1, bool(answer), 0, 0)
            self.sock.sendto(header + question + answer, addr)

    def close(self):
        self.stop.set()
        self.sock.close()
        self.thread.join(1)


def dns_test(binary, address):
    with contextlib.ExitStack() as stack:
        echo, dns = Echo(), DNS()
        stack.callback(echo.close)
        stack.callback(dns.close)
        config = f"""resolvers default
 nameserver owned 127.0.0.1:{dns.port}
 hold valid 100ms
 hold nx 100ms
 hold timeout 100ms
 timeout resolve 100ms
 timeout retry 100ms
"""
        ha = HA(binary, f"store.test:{address[1]}", echo, dns=config, master=True)
        stack.callback(ha.close)
        peer = stack.enter_context(ha.connect())
        time.sleep(0.35)
        assert not snapshot(address, ha)
        dns.answer = address[0]
        wait(lambda: bool(snapshot(address, ha)), 8)
        ha.probe(peer)
        assert list(counts(address, ha).values()) == [1]
    print("PASS: master/worker, asynchronous DNS unavailable at startup then recovery, traffic preserved", flush=True)


def no_optin(binary):
    with contextlib.ExitStack() as stack:
        echo = Echo()
        stack.callback(echo.close)
        store = stack.enter_context(listener())
        ha = HA(binary, "%s:%s" % store.getsockname(), echo, algorithm="leastconn")
        stack.callback(ha.close)
        peer = stack.enter_context(ha.connect())
        time.sleep(0.5)
        try:
            connection, _ = store.accept()
        except socket.timeout:
            pass
        else:
            connection.close()
            raise AssertionError("native backend unexpectedly activated publisher")
        ha.probe(peer)
    print("PASS: native backend no automatic store connection", flush=True)


def ambiguous_reply(binary):
    # A test RESP endpoint intentionally loses START's reply. The next TCP
    # connection must receive UPDATE/new sequence/current count, not replay.
    with contextlib.ExitStack() as stack:
        echo = Echo()
        stack.callback(echo.close)
        store = stack.enter_context(listener())
        store.settimeout(4)
        ha = HA(binary, "%s:%s" % store.getsockname(), echo)
        stack.callback(ha.close)
        first, _ = store.accept()
        first.settimeout(3)
        with first, first.makefile("rb") as stream:
            old = read(stream)
            assert old[0] == b"EVAL" and old[5] == b"start"
            peer = stack.enter_context(ha.connect())
            # Close without any response. Do not send a fake successful ACK.
        second, _ = store.accept()
        second.settimeout(3)
        with second, second.makefile("rb") as stream:
            fresh = read(stream)
            assert fresh[5] == b"update" and fresh[6] == old[6]
            assert int(fresh[7]) > int(old[7])
            values = dict(zip(fresh[9::2], fresh[10::2]))
            assert values[f"c:be|127.0.0.1:{echo.address[1]}".encode()] == b"1"
            second.sendall(b":1\r\n")
            # A stored publication is followed on the same single-flight
            # connection by a complete SCAN/HGETALL collection.
            scan = read(stream)
            assert scan == [b"SCAN", b"0", b"MATCH",
                            f"glb:v1:{ha.prefix.encode().hex()}:*:snapshot".encode(),
                            b"COUNT", b"32"]
            second.sendall(b"*2\r\n$1\r\n0\r\n*1\r\n" +
                           encode([(ha.key + ":snapshot").encode()])[4:])
            hgetall = read(stream)
            assert hgetall == [b"HGETALL", (ha.key + ":snapshot").encode()]
            fields = [b"writer_generation", fresh[6],
                      b"snapshot_sequence", fresh[7], *fresh[9:]]
            second.sendall(encode(fields))
            # No next publication until the scheduled next cycle.
            second.settimeout(0.15)
            try:
                extra = second.recv(1)
            except socket.timeout:
                pass
            else:
                raise AssertionError(f"unexpected early command {extra!r}")
            ha.probe(peer)
    print("PASS: lost START reply -> same UUID, fresh UPDATE/sequence/current count, single-flight", flush=True)


def collector_limit(binary):
    """The 4097th global endpoint invalidates cache and reconnects only store I/O."""
    with contextlib.ExitStack() as stack:
        echo = Echo()
        stack.callback(echo.close)
        store = stack.enter_context(listener())
        store.settimeout(4)
        ha = HA(binary, "%s:%s" % store.getsockname(), echo)
        stack.callback(ha.close)
        traffic = stack.enter_context(ha.connect())
        peer, _ = store.accept()
        peer.settimeout(3)
        with peer, peer.makefile("rb") as stream:
            first = read(stream)
            assert first[0] == b"EVAL" and first[5] == b"start"
            peer.sendall(b":1\r\n")
            assert read(stream)[0] == b"SCAN"
            snapshot_key = (ha.key + ":snapshot").encode()
            peer.sendall(b"*2\r\n$1\r\n0\r\n*1\r\n" + encode([snapshot_key])[4:])
            assert read(stream) == [b"HGETALL", snapshot_key]
            peer.sendall(encode([b"writer_generation", first[6],
                                 b"snapshot_sequence", first[7], *first[9:]]))

            second = read(stream)
            assert second[0] == b"EVAL" and second[5] == b"update"
            assert second[6] == first[6] and int(second[7]) > int(first[7])
            peer.sendall(b":1\r\n")
            assert read(stream)[0] == b"SCAN"
            peer.sendall(b"*2\r\n$1\r\n0\r\n*1\r\n" + encode([snapshot_key])[4:])
            assert read(stream) == [b"HGETALL", snapshot_key]
            fields = [b"writer_generation", second[6],
                      b"snapshot_sequence", second[7]]
            for i in range(4097):
                fields.extend([f"c:be|10.9.{i // 250}.{i % 250}:5000".encode(), b"1"])
            peer.sendall(encode(fields))
            assert peer.recv(1) == b""

        replacement, _ = store.accept()
        replacement.settimeout(3)
        with replacement, replacement.makefile("rb") as stream:
            fresh = read(stream)
            assert fresh[0] == b"EVAL" and fresh[5] == b"update"
            assert fresh[6] == first[6] and int(fresh[7]) > int(second[7])
            ha.probe(traffic)
    print("PASS: 4097th global endpoint -> store reconnect/local-LC service preserved", flush=True)


def concurrent_lifecycle(binary, address):
    with contextlib.ExitStack() as stack:
        echo = Echo()
        stack.callback(echo.close)
        ha = HA(binary, "%s:%s" % address, echo)
        stack.callback(ha.close)
        wait(lambda: snapshot(address, ha))
        def connect_close(index):
            with ha.connect() as peer:
                if index % 3 == 0:
                    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
        with ThreadPoolExecutor(max_workers=16) as workers:
            list(workers.map(connect_close, range(512)))
        wait(lambda: counts(address, ha) == {})
        peers = [stack.enter_context(ha.connect()) for _ in range(8)]
        wait(lambda: sum(counts(address, ha).values()) == 8)
        ha.cli("shutdown sessions server be/s1")
        ha.cli("shutdown sessions server be/s2")
        wait(lambda: counts(address, ha) == {})
        # Map both slots to an owned bound-but-not-listening port. Connection
        # failures/retries must release exactly the previously acquired record.
        dead = stack.enter_context(socket.socket())
        dead.bind(("127.0.0.1", 0))
        for slot in ("s1", "s2"):
            ha.cli(f"set server be/{slot} addr 127.0.0.1 port {dead.getsockname()[1]}")
        wait(lambda: ha.cli("show global-lb local").count(f"127.0.0.1:{dead.getsockname()[1]}".encode()) == 2)
        for _ in range(8):
            with socket.create_connection(ha.front.getsockname(), 2) as peer:
                peer.settimeout(3)
                peer.sendall(b"fail")
                try:
                    assert not peer.recv(1)
                except ConnectionResetError:
                    pass
        wait(lambda: counts(address, ha) == {})
    print("PASS: 512 concurrent lifecycle operations/4 threads, RST, CLI session shutdown, failed connect/retry", flush=True)


def main():
    binary = os.path.abspath(sys.argv[1])
    image = sys.argv[2] if len(sys.argv) > 2 else "valkey/valkey:9.1.1-alpine"
    token, container = uuid.uuid4().hex, None
    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True).strip()
    try:
        container = docker("run", "-d", "--rm", "--pull=never", "--label", "glb-publish-test=" + token,
                           "-p", "127.0.0.1::6379", image, "--save", "", "--appendonly", "no")
        port = int(docker("port", container, "6379/tcp").split(":")[-1])
        address = ("127.0.0.1", port)
        for _ in range(50):
            try:
                if command(address, "PING") == b"PONG":
                    break
            except (OSError, AssertionError):
                time.sleep(0.1)
        no_optin(binary)
        ambiguous_reply(binary)
        collector_limit(binary)
        lifecycle(binary, address)
        concurrent_lifecycle(binary, address)
        dns_test(binary, address)
        print(f"PASS: automatic publisher on {image}", flush=True)
    finally:
        if container:
            info = json.loads(docker("inspect", container))[0]
            assert info["Config"]["Labels"]["glb-publish-test"] == token
            docker("stop", "--time", "1", container)


if __name__ == "__main__":
    main()

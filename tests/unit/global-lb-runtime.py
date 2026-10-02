#!/usr/bin/env python3
"""UD-012/013 r1, 2026-10-02: terminal cleanup and read-only diagnostics.
Uses owned listeners and a labeled disposable store; never uses port 6379.
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time
import uuid

spec = importlib.util.spec_from_file_location("publish", Path(__file__).with_name("global-lb-publish.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


def status(ha):
    return dict(line.split(": ", 1) for line in
                ha.cli("show global-lb status").decode().splitlines() if ": " in line)


def closed(sock):
    sock.settimeout(1)
    try:
        assert sock.recv(1) == b""
    except ConnectionResetError:
        pass


def normal_stop(binary, address, sig, master=False):
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        ha = p.HA(binary, "%s:%s" % address, echo, master=master)
        stack.callback(ha.close)
        peer = stack.enter_context(ha.connect())
        p.wait(lambda: status(ha).get("state") == "ACTIVE")
        before = p.snapshot(address, ha)
        ha.proc.send_signal(sig)
        ha.proc.wait(2)
        closed(peer)
        assert p.command(address, "EXISTS", ha.key + ":snapshot") == 0
        assert p.command(address, "HGET", ha.key + ":owner", "writer_generation") == before[b"writer_generation"]
        assert int(p.command(address, "HGET", ha.key + ":owner", "snapshot_sequence")) > int(before[b"snapshot_sequence"])
        assert ha.proc.returncode == 0
    print(f"PASS: signal {sig}, master={master}: DELETE before TCP stop, persistent owner", flush=True)


def diagnostics(binary, address):
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        ha = p.HA(binary, "%s:%s" % address, echo)
        stack.callback(ha.close)
        peer = stack.enter_context(ha.connect())
        p.wait(lambda: status(ha).get("state") == "ACTIVE")
        p.wait(lambda: p.counts(address, ha) != {})
        active = status(ha)
        assert active["usable"] == "1" and active["recovery"] == "3/3", active
        assert active["shutdown"] == "running" and active["cleanup"] == "not-requested"
        assert active["writer_generation"] == p.snapshot(address, ha)[b"writer_generation"].decode()
        cache = ha.cli("show global-lb cache").decode()
        assert "state=ACTIVE usable=1" in cache, cache
        assert f"be|127.0.0.1:{echo.address[1]}\t1\t1\t1\t1" in cache, cache
        assert b"expects no arguments" in ha.cli("show global-lb status extra")
        assert b"expects no arguments" in ha.cli("show global-lb cache extra")
        # Changing owner stops our writer. A copied status on arbitrary CLI
        # threads must expose grace -> stale fallback -> three-cycle recovery.
        owner = active["writer_generation"]
        replacement = str(uuid.uuid4())
        p.command(address, "HSET", ha.key + ":owner", "writer_generation", replacement)
        p.wait(lambda: status(ha).get("state") == "GRACE")
        grace = status(ha)
        assert grace["recovery"] == "0/3" and int(grace["failures"]) > 0
        p.wait(lambda: status(ha).get("state") == "FALLBACK", 5)
        assert status(ha)["reason"] == "stale-cache"
        ha.probe(peer)
        p.command(address, "HSET", ha.key + ":owner", "writer_generation", owner)
        p.wait(lambda: status(ha).get("state") == "ACTIVE")
        ha.probe(peer)
        ha.proc.send_signal(signal.SIGUSR1)
        ha.proc.wait(2)
        logs = ha.proc.stderr.read()
        for transition in (b"RECOVERING -> ACTIVE", b"ACTIVE -> GRACE",
                           b"GRACE -> FALLBACK", b"FALLBACK -> RECOVERING",
                           b"shutdown snapshot cleanup=deleted"):
            assert transition in logs, (transition, logs)
        assert b"BUG" not in logs and b"AddressSanitizer" not in logs
    print("PASS: status/cache CLI, live counts, arguments, grace/stale/recovery and long TCP", flush=True)


def different_owner(binary, address):
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        ha = p.HA(binary, "%s:%s" % address, echo)
        stack.callback(ha.close)
        peer = stack.enter_context(ha.connect())
        p.wait(lambda: status(ha).get("state") == "ACTIVE")
        other = str(uuid.uuid4())
        p.command(address, "HSET", ha.key + ":owner", "writer_generation", other)
        p.command(address, "HSET", ha.key + ":snapshot", "writer_generation", other)
        frozen = p.snapshot(address, ha)
        ha.proc.send_signal(signal.SIGTERM)
        ha.proc.wait(2)
        closed(peer)
        assert p.snapshot(address, ha) == frozen
        assert p.command(address, "HGET", ha.key + ":owner", "writer_generation") == other.encode()
    print("PASS: terminal DELETE cannot remove a different writer snapshot", flush=True)


def shutdown_wire(binary, respond):
    # No store container required: withhold one in-flight reply and observe the
    # actual EVAL wire plus the traffic connection before acknowledging DELETE.
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        store = stack.enter_context(p.listener())
        store.settimeout(3)
        ha = p.HA(binary, "%s:%s" % store.getsockname(), echo)
        stack.callback(ha.close)
        traffic = stack.enter_context(ha.connect())
        connection, _ = store.accept()
        connection.settimeout(2)
        with connection, connection.makefile("rb") as stream:
            start = p.read(stream)
            assert start[5] == b"start"
            if respond:
                connection.sendall(b":1\r\n")
                assert p.read(stream)[0] == b"SCAN"
            began = time.monotonic()
            ha.proc.send_signal(signal.SIGTERM)
            if respond:
                # No DELETE may be pipelined before the pending SCAN reply.
                connection.settimeout(0.02)
                try:
                    extra = connection.recv(1, socket.MSG_PEEK)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(f"pipelined cleanup: {extra!r}")
                connection.settimeout(1)
                connection.sendall(b"*2\r\n$1\r\n0\r\n*0\r\n")
                delete = p.read(stream)
                assert delete[0] == b"EVAL" and delete[5] == b"delete", delete
                assert delete[6] == start[6] and int(delete[7]) > int(start[7])
                traffic.settimeout(0.02)
                try:
                    result = traffic.recv(1)
                except socket.timeout:
                    pass
                else:
                    raise AssertionError(f"traffic closed before cleanup: {result!r}")
                connection.sendall(b":2\r\n")
            ha.proc.wait(2)
            assert time.monotonic() - began < 0.7
            closed(traffic)
            assert connection.recv(1) == b""
        store.settimeout(0.15)
        try:
            connection, _ = store.accept()
        except socket.timeout:
            pass
        else:
            connection.close()
            raise AssertionError("shutdown reconnected")
    print(f"PASS: terminal single-flight, respond={respond}, bounded wait/no reconnect", flush=True)


def crash(binary, address):
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        ha = p.HA(binary, "%s:%s" % address, echo)
        stack.callback(lambda: ha.close(crash=True))
        p.wait(lambda: status(ha).get("state") == "ACTIVE")
        ha.proc.kill()
        ha.proc.wait(2)
        assert p.command(address, "EXISTS", ha.key + ":snapshot") == 1
        p.wait(lambda: p.command(address, "EXISTS", ha.key + ":snapshot") == 0, 4)
        assert p.command(address, "EXISTS", ha.key + ":owner") == 1
    print("PASS: SIGKILL leaves snapshot for TTL and retains owner", flush=True)


def unavailable(binary):
    with contextlib.ExitStack() as stack:
        echo = p.Echo()
        stack.callback(echo.close)
        port = stack.enter_context(socket.socket())
        port.bind(("127.0.0.1", 0))  # owned, intentionally not listening
        ha = p.HA(binary, "%s:%s" % port.getsockname(), echo)
        stack.callback(ha.close)
        traffic = stack.enter_context(ha.connect())
        p.wait(lambda: status(ha).get("transport") == "BACKOFF")
        started = time.monotonic()
        ha.proc.send_signal(signal.SIGTERM)
        ha.proc.wait(2)
        assert time.monotonic() - started < 0.7
        closed(traffic)


def main():
    binary = os.path.abspath(sys.argv[1])
    image = sys.argv[2] if len(sys.argv) > 2 else "valkey/valkey:9.1.1-alpine"
    token, container = uuid.uuid4().hex, None
    def docker(*args):
        return subprocess.check_output(["docker", *args], text=True).strip()
    try:
        container = docker("run", "-d", "--rm", "--pull=never", "--label", "glb-runtime-test=" + token,
                           "-p", "127.0.0.1::6379", image, "--save", "", "--appendonly", "no")
        address = ("127.0.0.1", int(docker("port", container, "6379/tcp").split(":")[-1]))
        def ready():
            try:
                return p.command(address, "PING") == b"PONG"
            except OSError:
                return False
        p.wait(ready)
        diagnostics(binary, address)
        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGUSR1):
            normal_stop(binary, address, sig)
        normal_stop(binary, address, signal.SIGTERM, master=True)
        different_owner(binary, address)
        shutdown_wire(binary, True)
        shutdown_wire(binary, False)
        # Exercise the idle multi-thread stop acknowledgement race repeatedly.
        for _ in range(32):
            unavailable(binary)
        print("PASS: 32 unavailable-store stops, no reconnect or idle-thread hang", flush=True)
        crash(binary, address)
        print(f"PASS: shutdown/observability on {image}", flush=True)
    finally:
        if container:
            info = json.loads(docker("inspect", container))[0]
            assert info["Config"]["Labels"]["glb-runtime-test"] == token
            docker("stop", "--time", "1", container)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""UD-005/007/009/010/011/016 v2-r3. Actual production native path.
Usage: global-lb-v2-native.py HAPROXY_BINARY STORE_IMAGE
Owns isolated container/listeners/keys. Never touches user Valkey/FLUSHDB.
START/HB are supplied by the production lifecycle; no EXTRA_OBJS driver.
"""
import concurrent.futures
import csv
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("helpers", Path(__file__).with_name("global-lb-test-helpers.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)


class HA:
    def __init__(self, binary, store, prefix, instance, servers, extra="", reserve="100ms", redispatch=True, command="100ms"):
        self.front, self.admin = p.listener(), p.listener()
        config = f"""global
 nbthread 4
 stats socket fd@{self.admin.fileno()} level admin
 global-lb state-store {store}
 global-lb key-prefix {prefix}
 global-lb instance-id {instance}
 global-lb timeout reserve {reserve}
 global-lb timeout command {command}
 global-lb heartbeat-interval 300ms
 global-lb instance-timeout 3s
defaults
 mode tcp
 timeout connect 100ms
 timeout queue 3s
 timeout client 30s
 timeout server 30s
 retries 2
frontend fe
 bind fd@{self.front.fileno()}
 default_backend be
backend be
 balance global-leastconn
{" option redispatch 1" if redispatch else ""}
{servers}
{extra}
"""
        self.proc = subprocess.Popen([binary, "-db", "-f", "/dev/stdin"], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                     pass_fds=(self.front.fileno(), self.admin.fileno()))
        self.proc.stdin.write(config.encode()); self.proc.stdin.close()
        def available():
            if self.proc.poll() is not None:
                raise AssertionError(self.proc.stderr.read())
            try:
                return self.cli("show info")
            except OSError:
                return False
        p.wait(available)

    def cli(self, text):
        with socket.create_connection(self.admin.getsockname(), 2) as peer:
            peer.sendall(text.encode()+b"\n")
            out = b""
            while True:
                data = peer.recv(65536)
                if not data:
                    return out
                out += data

    def connect(self):
        peer = socket.create_connection(self.front.getsockname(), 3)
        peer.settimeout(3)
        return peer

    def close(self):
        if self.proc.poll() is None:
            self.proc.terminate()
        self.proc.wait(5)
        logs = self.proc.stderr.read()+self.proc.stdout.read()
        if os.environ.get("GLB_TEST_DEBUG"):
            print(logs.decode(errors="replace"))
        self.front.close(); self.admin.close()
        assert b"BUG" not in logs and b"AddressSanitizer" not in logs, logs


binary, image = os.path.abspath(__import__("sys").argv[1]), __import__("sys").argv[2]
token = uuid.uuid4().hex
container = None
try:
    server = "valkey-server" if "valkey:" in image else "redis-server"
    container = subprocess.check_output(["docker", "run", "--pull=never", "--rm", "-d",
                     "--label", "global-lb-v2-native="+token, "-p", "127.0.0.1::6379",
                     image, server, "--save", "", "--appendonly", "no"], text=True).strip()
    info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
    port = info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"]
    address = ("127.0.0.1", int(port))
    def cmd(*args):
        return p.command(address, *args)
    def store_ready():
        try:
            return cmd("PING") == b"PONG"
        except (OSError, RuntimeError):
            return False
    p.wait(store_ready)
    def ns(prefix, field):
        return f"glb:v2:{prefix.encode().hex()}:{field}"
    def rows(prefix, field):
        raw = cmd("HGETALL", ns(prefix, field))
        return dict(zip(raw[::2], raw[1::2]))
    def counts(prefix):
        return {k: int(v) for k, v in rows(prefix, "counts").items()}
    def start_wait(prefix, n):
        p.wait(lambda: len(rows(prefix, "liveness")) == n)
        time.sleep(.05)

    with contextlib.ExitStack() as stack:
        echoes = [p.TaggedEcho(bytes([65+i])) for i in range(3)]
        for echo in echoes:
            stack.callback(echo.close)
        servers = "\n".join(f" server s{i} 127.0.0.1:{e.address[1]}" for i, e in enumerate(echoes))
        prefix = "native-test/"+token
        has = [HA(binary, f"127.0.0.1:{port}", prefix, f"ha-{i}", servers) for i in range(3)]
        for ha in has:
            stack.callback(ha.close)
        start_wait(prefix, 3)
        def connect(i):
            peer = has[i % 3].connect()
            tag = peer.recv(1)
            assert tag in (b"A", b"B", b"C"), tag
            peer.sendall(b"long-tcp"); assert peer.recv(8) == b"long-tcp"
            return peer, tag
        with concurrent.futures.ThreadPoolExecutor(max_workers=24) as pool:
            connections = list(pool.map(connect, range(100)))
        peers, tags = zip(*connections)
        for peer in peers:
            stack.callback(peer.close)
        p.wait(lambda: sum(counts(prefix).values()) == 100)
        assert len(rows(prefix, "requests")) == 100
        distribution = [tags.count(bytes([65+i])) for i in range(3)]
        assert max(distribution)-min(distribution) <= 1, distribution
        time.sleep(.4)  # real heartbeats must not add a second reservation
        assert sum(counts(prefix).values()) == 100
        for peer in peers:
            peer.close()
        p.wait(lambda: not counts(prefix) and not rows(prefix, "requests"))
        print(f"PASS: {image}: 3 workers x 4 threads, 100 TCPs {distribution}, no success +1, exact release")

        # Native maxconn and backend queues remain native; an unassigned queue
        # entry has no remote request. Dequeue adopts local metadata instead.
        prefix_q = prefix+"-queue"
        queued = HA(binary, f"127.0.0.1:{port}", prefix_q, "ha-q",
                    f" server s0 127.0.0.1:{echoes[0].address[1]} maxconn 1")
        stack.callback(queued.close); start_wait(prefix_q, 1)
        first = queued.connect(); stack.callback(first.close); assert first.recv(1) == b"A"
        second = queued.connect(); stack.callback(second.close); second.settimeout(.15)
        try:
            assert not second.recv(1)
            raise AssertionError("maxconn violated")
        except socket.timeout:
            pass
        assert sum(counts(prefix_q).values()) == 1
        assert len(rows(prefix_q, "requests")) == 1
        first.close(); second.settimeout(2); assert second.recv(1) == b"A"
        second.sendall(b"queue"); assert second.recv(5) == b"queue"
        second.close()
        p.wait(lambda: not counts(prefix_q) and not rows(prefix_q, "requests"))
        print("PASS: native maxconn/queue preserved, unassigned queue has no Global reservation")

        # Maintenance excludes an endpoint, backup is only used without active.
        prefix_b = prefix+"-backup"
        backup = HA(binary, f"127.0.0.1:{port}", prefix_b, "ha-b",
                    f" server s0 127.0.0.1:{echoes[0].address[1]} disabled\n"
                    f" server s1 127.0.0.1:{echoes[1].address[1]} backup")
        stack.callback(backup.close); start_wait(prefix_b, 1)
        peer = backup.connect(); stack.callback(peer.close); assert peer.recv(1) == b"B"
        assert all(k.endswith(f"|be|127.0.0.1:{echoes[1].address[1]}".encode()) for k in counts(prefix_b))
        peer.close(); p.wait(lambda: not counts(prefix_b))
        print("PASS: maintenance/backup eligibility and cleanup")

        # Refused connect + redispatch drops the failed assignment before
        # reserving the other endpoint. No retained dead-server count.
        dead = socket.socket(); dead.bind(("127.0.0.1", 0)); stack.callback(dead.close)
        dead_port = dead.getsockname()[1]  # reserved but not listening
        prefix_r = prefix+"-redispatch"
        retry = HA(binary, f"127.0.0.1:{port}", prefix_r, "ha-r",
                   f" server bad 127.0.0.1:{dead_port}\n"
                   f" server good 127.0.0.1:{echoes[2].address[1]}")
        stack.callback(retry.close); start_wait(prefix_r, 1)
        retry_peers = []
        for _ in range(12):
            peer = retry.connect(); stack.callback(peer.close); retry_peers.append(peer)
            assert peer.recv(1) == b"C"
        p.wait(lambda: sum(counts(prefix_r).values()) == 12 and len(rows(prefix_r, "requests")) == 12)
        assert all(k.endswith(f"|be|127.0.0.1:{echoes[2].address[1]}".encode()) for k in counts(prefix_r))
        for peer in retry_peers:
            peer.close()
        p.wait(lambda: not counts(prefix_r) and not rows(prefix_r, "requests"))
        print("PASS: refused connect/redispatch to a new endpoint, exact failure release")

        # Without redispatch, a same-server retry keeps its native slot and
        # the ONE Global request, not a TAKE for each connect attempt.
        prefix_same = prefix+"-same"
        same = HA(binary, f"127.0.0.1:{port}", prefix_same, "ha-s",
                  f" server bad 127.0.0.1:{dead_port}", redispatch=False)
        stack.callback(same.close); start_wait(prefix_same, 1)
        peer = same.connect(); stack.callback(peer.close)
        assert peer.recv(1) == b""
        p.wait(lambda: not counts(prefix_same) and not rows(prefix_same, "requests"))
        live = next(iter(rows(prefix_same, "liveness").values())).decode().split("|")
        assert live[2] == "1", live  # only one monotonic request allocated
        print("PASS: same-server retries keep one reservation; final failure releases once")

        # UD-009/016 v2-only-20261004: redispatch may choose the same sole
        # endpoint. Preserve native lbtot=1 and count the two retries separately.
        prefix_stats = prefix+"-retry-stats"
        stats = HA(binary, f"127.0.0.1:{port}", prefix_stats, "ha-stats",
                   f" server bad 127.0.0.1:{dead_port}", reserve="1s", command="1s")
        stack.callback(stats.close)
        p.wait(lambda: b"state: ACTIVE\n" in stats.cli("show global-lb status"))
        peer = stats.connect(); stack.callback(peer.close)
        assert peer.recv(1) == b""
        p.wait(lambda: not counts(prefix_stats) and not rows(prefix_stats, "requests"))
        for row in csv.DictReader(stats.cli("show stat").decode().splitlines()):
            if row["svname"] in ("bad", "BACKEND"):
                assert int(row["lbtot"]) == 1 and int(row["wretr"]) == 2, row
        print("PASS: same-server redispatch preserves native lbtot and retry statistics")

        # Current slot IP:port changes without rewriting the old live TCP's
        # immutable endpoint contribution. New connects use the new address.
        prefix_m = prefix+"-remap"
        remap = HA(binary, f"127.0.0.1:{port}", prefix_m, "ha-m",
                   f" server s0 127.0.0.1:{echoes[0].address[1]}")
        stack.callback(remap.close); start_wait(prefix_m, 1)
        old = remap.connect(); stack.callback(old.close); assert old.recv(1) == b"A"
        answer = remap.cli(f"set server be/s0 addr 127.0.0.1 port {echoes[1].address[1]}")
        assert b"error" not in answer.lower(), answer
        new = remap.connect(); stack.callback(new.close); assert new.recv(1) == b"B"
        p.wait(lambda: sum(counts(prefix_m).values()) == 2)
        assert len(counts(prefix_m)) == 2
        old.sendall(b"old-still-A"); assert old.recv(11) == b"old-still-A"
        old.close(); p.wait(lambda: sum(counts(prefix_m).values()) == 1)
        assert all(k.endswith(f"|be|127.0.0.1:{echoes[1].address[1]}".encode()) for k in counts(prefix_m))
        new.close(); p.wait(lambda: not counts(prefix_m))
        print("PASS: runtime endpoint remap preserves old TCP identity, new endpoint and exact release")
finally:
    if container:
        subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL)

# Fragmented/lost reply, stream death and whole admission deadline, isolated
# fake RESP store: no external services, no store state claimed reconciled.
with contextlib.ExitStack() as stack:
    echo = p.TaggedEcho(b"F"); stack.callback(echo.close)
    listener = p.listener(); stack.callback(listener.close)
    commands, ready, stop = [], threading.Event(), threading.Event()
    stack.callback(stop.set)
    def fake_store():
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept()
                    break
                except socket.timeout:
                    continue
            else:
                return
            with conn, conn.makefile("rb") as stream:
                while not stop.is_set():
                    args = p.read(stream)
                    commands.append(args)
                    if args[7] == b"start":
                        for byte in b"*3\r\n:1\r\n$0\r\n\r\n:0\r\n":
                            conn.sendall(bytes([byte]))
                        ready.set()
                    elif args[7] == b"reserve":
                        time.sleep(.25)  # crosses queue+send+reply deadline
                        endpoint = args[20]
                        conn.sendall(b"*3\r\n:1\r\n$%d\r\n" % len(endpoint)+endpoint+b"\r\n:1\r\n")
                    else:
                        conn.sendall(b"*3\r\n:1\r\n$0\r\n\r\n:0\r\n")
        except (OSError, RuntimeError, AssertionError, TypeError):
            pass
    thread = threading.Thread(target=fake_store, daemon=True); thread.start()
    ha = HA(binary, f"127.0.0.1:{listener.getsockname()[1]}", "fake/"+token, "ha-f",
            f" server s0 127.0.0.1:{echo.address[1]}", reserve="100ms")
    stack.callback(ha.close); assert ready.wait(2); time.sleep(.05)
    began = time.monotonic()
    peer = ha.connect(); stack.callback(peer.close)
    assert peer.recv(1) == b"F"
    elapsed = time.monotonic()-began
    assert .05 <= elapsed < .23, elapsed
    peer.sendall(b"fallback-still-live"); assert peer.recv(19) == b"fallback-still-live"
    peer.close(); time.sleep(.35)
    assert sum(cmd[7] == b"reserve" for cmd in commands) == 1  # no blind TAKE replay
    print(f"PASS: fragmented START, 100ms whole reserve deadline ({elapsed:.3f}s), local fallback, late reply/no replay")

# Owner dies while reserve is in flight. The late reply is cancelled, never
# used to connect, and no callback points at the destroyed stream/task.
with contextlib.ExitStack() as stack:
    echo = p.TaggedEcho(b"X"); stack.callback(echo.close)
    listener = p.listener(); stack.callback(listener.close)
    ready, reserved, cancelled, stop = (threading.Event() for _ in range(4))
    stack.callback(stop.set)
    allocated, abort_commands = {}, []
    def abort_store():
        try:
            while not stop.is_set():
                try:
                    conn, _ = listener.accept(); break
                except socket.timeout:
                    continue
            else:
                return
            with conn, conn.makefile("rb") as stream:
                while not stop.is_set():
                    args = p.read(stream)
                    op, rid = args[7], args[11]
                    abort_commands.append(op)
                    if op == b"reserve":
                        allocated[rid] = args[20]; reserved.set(); time.sleep(.12)
                        endpoint = allocated[rid]
                        conn.sendall(b"*3\r\n:1\r\n$%d\r\n" % len(endpoint)+endpoint+b"\r\n:1\r\n")
                    elif op in (b"cancel", b"release"):
                        allocated.pop(rid, None)
                        conn.sendall(b"*3\r\n:%d\r\n$0\r\n\r\n:0\r\n" % (4 if op == b"cancel" else 3))
                        cancelled.set()
                    elif op == b"restore":
                        # Production may invalidate during stream teardown;
                        # confirmed atomic replacement is also reconciliation.
                        n = int(args[20])
                        allocated.clear()
                        allocated.update((args[21+2*i], args[22+2*i]) for i in range(n))
                        conn.sendall(b"*3\r\n:1\r\n$0\r\n\r\n:0\r\n")
                        if not allocated:
                            cancelled.set()
                    else:
                        conn.sendall(b"*3\r\n:1\r\n$0\r\n\r\n:0\r\n")
                        if op == b"start":
                            ready.set()
        except (OSError, RuntimeError, AssertionError, TypeError):
            pass
    threading.Thread(target=abort_store, daemon=True).start()
    ha = HA(binary, f"127.0.0.1:{listener.getsockname()[1]}", "abort/"+token, "ha-a",
            f" server s0 127.0.0.1:{echo.address[1]}", reserve="1s", command="1s")
    stack.callback(ha.close); assert ready.wait(2); time.sleep(.05)
    peer = ha.connect(); assert reserved.wait(2)
    peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0)); peer.close()
    assert cancelled.wait(2) and not allocated, (abort_commands, allocated)
    print("PASS: client RST during reserve, detached owner, late success reconciled by cancel/atomic restore")

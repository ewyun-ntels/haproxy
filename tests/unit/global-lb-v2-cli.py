#!/usr/bin/env python3
"""UD-012/016 v2-r4-20261004: copied read-only v2 CLI and observed 100-TCP burst.
Own disposable loopback store only, no user store, FLUSHDB, pulled images,
test C driver or arbitrary performance PASS threshold. Times include Python
scheduling, local TCP handshake and first backend byte, not Lua-only latency.
Usage: global-lb-v2-cli.py HAPROXY_BINARY STORE_IMAGE
"""
import concurrent.futures
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("lifecycle", Path(__file__).with_name("global-lb-v2-lifecycle.py"))
lc = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lc)
p = lc.p

def fields(raw):
    assert raw and b"Unknown command" not in raw, raw
    lines = [line for line in raw.splitlines() if b": " in line and not line.startswith(b"#")]
    result = dict(line.split(b": ", 1) for line in lines)
    assert len(result) == len(lines), raw  # no duplicate chunks on output yield
    return result

def status(ha):
    return fields(ha.cli("show global-lb status"))

def ledger(ha):
    d = fields(ha.cli("show global-lb reservations"))
    assert int(d[b"entries"]) == sum(int(d[x]) for x in
        (b"waiting", b"ready", b"native_slots", b"failed", b"cleanup")), d
    return d

def run(binary, image):
    token = uuid.uuid4().hex
    container = None
    try:
        server = "valkey-server" if "valkey:" in image else "redis-server"
        container = subprocess.check_output(["docker", "run", "--pull=never", "--rm", "-d",
            "--label", "global-lb-v2-cli="+token, "-p", "127.0.0.1::6379", image,
            server, "--save", "", "--appendonly", "no"], text=True).strip()
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
        port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
        address = ("127.0.0.1", port)
        def cmd(*args): return p.command(address, *args)
        def ready():
            try: return cmd("PING") == b"PONG"
            except (OSError, RuntimeError): return False
        p.wait(ready)
        def rows(prefix, field):
            raw = cmd("HGETALL", f"glb:v2:{prefix.encode().hex()}:{field}")
            return dict(zip(raw[::2], raw[1::2]))
        with contextlib.ExitStack() as stack:
            echoes = [p.TaggedEcho(bytes([65+i])) for i in range(3)]
            for echo in echoes: stack.callback(echo.close)
            servers = "\n".join(f" server s{i} 127.0.0.1:{e.address[1]}" for i, e in enumerate(echoes))
            # Direct product->store path for latency measurement, without the
            # Python RESP fault relay or deliberately tiny CLI buffers.
            direct_prefix = "burst/"+token
            direct = [lc.HA(binary, f"127.0.0.1:{port}", direct_prefix, f"burst-{i}", echoes[0],
                            servers=servers) for i in range(3)]
            for ha in direct: stack.callback(ha.close)
            p.wait(lambda: all(status(ha)[b"state"] == b"ACTIVE" for ha in direct))
            gate = threading.Barrier(100)
            def burst(i):
                gate.wait(5); start = time.monotonic()
                peer = socket.create_connection(direct[i % 3].front.getsockname(), 3)
                peer.settimeout(3); tag = peer.recv(1)
                assert tag in (b"A", b"B", b"C"), tag
                return peer, tag, (time.monotonic()-start)*1000
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                measured = list(pool.map(burst, range(100)))
            for peer, _, _ in measured: stack.callback(peer.close)
            p.wait(lambda: all(status(ha)[b"state"] == b"ACTIVE" for ha in direct))
            p.wait(lambda: sum(int(n) for n in rows(direct_prefix, "counts").values()) == 100)
            counters = [ledger(ha) for ha in direct]
            samples = sorted(elapsed for _, _, elapsed in measured)
            dist = [sum(tag == bytes([65+i]) for _, tag, _ in measured) for i in range(3)]
            abandoned = sum(int(s[b"abandoned_unsent"])+int(s[b"abandoned_sent"]) for s in counters)
            if not abandoned: assert max(dist)-min(dist) <= 1, dist
            print("MEASURE: "+json.dumps({"path": "direct-store", "image": image, "workers": 3,
                "threads_per_worker": 4, "simultaneous_tcp": 100, "distribution": dist,
                "abandoned_admissions": abandoned, "reserve_confirmed": sum(int(s[b"reserve_confirmed"]) for s in counters),
                "observed_connect_first_byte_ms": {"min": round(samples[0], 3), "p50": round(samples[49], 3),
                    "p95": round(samples[94], 3), "p99": round(samples[98], 3), "max": round(samples[-1], 3)}}, sort_keys=True), flush=True)
            for peer, _, _ in measured: peer.close()
            p.wait(lambda: not rows(direct_prefix, "counts") and not rows(direct_prefix, "requests"))
            for ha in direct: ha.close()
            proxy = lc.Proxy(address); stack.callback(proxy.close)
            prefix = "cli/"+token
            has = [lc.HA(binary, f"127.0.0.1:{proxy.address[1]}", prefix, f"ha-{i}", echoes[0],
                         extra=" tune.bufsize 1024", servers=servers) for i in range(3)]
            for ha in has: stack.callback(ha.close)
            try:
                p.wait(lambda: all(status(ha).get(b"state") == b"ACTIVE" for ha in has))
            except AssertionError:
                print("STARTUP DIAGNOSTICS:", [status(ha) for ha in has], flush=True)
                raise
            for ha in has:
                s = status(ha)
                assert s[b"mode"] == b"v2-reservation" and s[b"owner"] == b"confirmed", s
                assert s[b"usable"] == b"1" and s[b"starts"] == b"1", s
                assert b"cache_version" not in s and b"sync_interval_ms" not in s, s
                assert s[b"heartbeat_interval_ms"] == b"300" and s[b"instance_timeout_ms"] == b"3000"
                assert b"not a periodic Global Cache" in ha.cli("show global-lb cache")
                for command in ("show global-lb status", "show global-lb reservations", "show global-lb cache"):
                    assert b"expects no arguments" in ha.cli(command+" unexpected")
            p.wait(lambda: all(int(status(ha)[b"heartbeat_reply_age_ms"]) >= 0 for ha in has))
            print("PASS: v2 ACTIVE/owner/HB/restore/timers, explicit v1 cache guidance, small-buffer complete output")

            begin = threading.Barrier(100)
            def connect(i):
                begin.wait(5)
                start = time.monotonic()
                peer = socket.create_connection(has[i % 3].front.getsockname(), 3)
                peer.settimeout(3); tag = peer.recv(1)
                elapsed = (time.monotonic()-start)*1000
                assert tag in (b"A", b"B", b"C"), tag
                lc.HA.probe(peer)
                return peer, tag, elapsed
            with concurrent.futures.ThreadPoolExecutor(max_workers=100) as pool:
                connections = list(pool.map(connect, range(100)))
            for peer, _, _ in connections: stack.callback(peer.close)
            distribution = [sum(tag == bytes([65+i]) for _, tag, _ in connections) for i in range(3)]
            p.wait(lambda: sum(int(n) for n in rows(prefix, "counts").values()) == 100)
            p.wait(lambda: sum(int(ledger(ha)[b"native_slots"]) for ha in has) == 100)
            p.wait(lambda: all(status(ha)[b"state"] == b"ACTIVE" for ha in has))
            samples = sorted(elapsed for _, _, elapsed in connections)
            metrics = {"path": "python-fault-proxy-small-buffer", "image": image, "workers": 3, "threads_per_worker": 4, "simultaneous_tcp": 100,
                "distribution": distribution, "observed_connect_first_byte_ms":
                {"min": round(samples[0], 3), "p50": round(samples[49], 3), "p95": round(samples[94], 3),
                 "p99": round(samples[98], 3), "max": round(samples[-1], 3)}}
            print("MEASURE: "+json.dumps(metrics, sort_keys=True))

            fixed = {name: rows(prefix, name) for name in ("owners", "counts", "requests")}
            before = len(proxy.commands)
            def read(i):
                ha = has[i % 3]
                assert status(ha)[b"usable"] == b"1"
                assert int(ledger(ha)[b"native_slots"]) in (33, 34)  # per-worker frontend allocation, NOT backend distribution
                assert b"# backend\tserver\tendpoint\toper_state\tcur_sess\tserved" in ha.cli("show global-lb local")
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool: list(pool.map(read, range(120)))
            assert fixed == {name: rows(prefix, name) for name in fixed}
            assert all(a[7] == b"heartbeat" for _, a in proxy.commands[before:])
            print("PASS: 360 concurrent CLI reads are read-only; no count/request/owner writes, restore or extra I/O")

            # Transport failure: cached ACTIVE must not hide actual ledger fallback.
            old = [status(ha)[b"writer_generation"] for ha in has]
            proxy.down = True; proxy.cut()
            p.wait(lambda: all(status(ha)[b"state"] == b"FALLBACK" for ha in has))
            for ha in has:
                s = status(ha)
                assert s[b"usable"] == b"0" and int(s[b"transport_failures"]) > 0, s
                assert s[b"last_transport_error"] != b"none", s
            for peer, _, _ in connections: lc.HA.probe(peer)
            proxy.down = False
            p.wait(lambda: all(status(ha)[b"state"] == b"ACTIVE" for ha in has))
            assert old == [status(ha)[b"writer_generation"] for ha in has]
            assert sum(int(n) for n in rows(prefix, "counts").values()) == 100
            print("PASS: actual transport failure/fallback/fresh RESTORE diagnostics; all 100 TCPs survive")

            # Hold a genuine applied reply to observe a copied pending TAKE
            # and FIFO queue. Extended timers are fixture-only, not defaults.
            pending = lc.HA(binary, f"127.0.0.1:{proxy.address[1]}", prefix+"-pending", "pending", echoes[0],
                            extra=" global-lb timeout command 1s", reserve="1s")
            stack.callback(pending.close)
            p.wait(lambda: status(pending)[b"state"] == b"ACTIVE")
            entered, unblock = threading.Event(), threading.Event()
            def hold(args, result):
                if args[7] == b"reserve" and args[8] == pending.iid:
                    entered.set(); unblock.wait(2)
                return False
            proxy.hook = hold
            waiting = []
            try:
                for _ in range(5):
                    peer = socket.create_connection(pending.front.getsockname(), 2)
                    peer.settimeout(3); peer.sendall(b"long-tcp"); waiting.append(peer); stack.callback(peer.close)
                assert entered.wait(1)
                p.wait(lambda: int(ledger(pending)[b"queued_reserve"]) == 4, .5)
                d = ledger(pending)
                assert d[b"inflight"] == b"TAKE" and int(d[b"waiting"]) == 5, d
                assert status(pending)[b"transport"] == b"COMMAND"
            finally:
                unblock.set(); proxy.hook = None
            for peer in waiting:
                assert peer.recv(1) == b"A"
                assert peer.recv(8) == b"long-tcp"
            p.wait(lambda: int(ledger(pending)[b"native_slots"]) == 5)
            for peer in waiting: peer.close()
            p.wait(lambda: ledger(pending)[b"entries"] == b"0")
            print("PASS: pending TAKE/FIFO and cleanup counters observed without changing dispatcher state")

            # Diagnostic authority is a local confirmed owner, never a live claim.
            ha = has[0]
            foreign = b"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
            cmd("HSET", f"glb:v2:{prefix.encode().hex()}:owners", ha.iid, foreign)
            p.wait(lambda: status(ha)[b"state"] == b"FENCED")
            s = status(ha)
            assert s[b"owner"] == b"fenced" and s[b"usable"] == b"0", s
            for _ in range(10): status(ha); ledger(ha)
            assert rows(prefix, "owners")[ha.iid] == foreign
            print("PASS: owner mismatch FENCED, CLI cannot steal/restore owner")

            low = lc.HA(binary, f"127.0.0.1:{port}", prefix+"-acl", "low", echoes[0], level="operator")
            stack.callback(low.close)
            for command in ("show global-lb status", "show global-lb reservations", "show global-lb local", "show global-lb cache"):
                assert b"Permission denied" in low.cli(command), command
            print("PASS: all Global LB diagnostic commands remain admin-only")
            long = lc.HA(binary, f"127.0.0.1:{port}", prefix+"-long", "x"*1500, echoes[0])
            stack.callback(long.close)
            p.wait(lambda: status(long)[b"state"] == b"ACTIVE")
            s = status(long)
            assert s[b"instance-id-truncated"] == b"yes" and len(s[b"instance-id"]) == 1024, s
            assert s[b"cleanup"] == b"not-requested" and b"max_requests" in s
            print("PASS: oversized diagnostic identity is explicitly truncated without losing terminal fields")
            for peer, _, _ in connections: peer.close()
            p.wait(lambda: all(int(ledger(h)[b"native_slots"]) == 0 for h in has))
        print(f"PASS: v2 read-only CLI ({image})")
    finally:
        if container: subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL)

if __name__ == "__main__": run(os.path.abspath(sys.argv[1]), sys.argv[2])

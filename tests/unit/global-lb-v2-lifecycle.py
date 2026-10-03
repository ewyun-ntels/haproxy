#!/usr/bin/env python3
"""UD-006/007/008/010/011/016 v2-r3. Production lifecycle integration.
Owns isolated --pull=never Docker store, loopback peers and keys. No test C
driver, fixed user ports, FLUSHDB/FLUSHALL, AUTH/TLS or user-store mutations.
Usage: global-lb-v2-lifecycle.py HAPROXY_BINARY STORE_IMAGE
"""
import concurrent.futures
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid

spec = importlib.util.spec_from_file_location("publish", Path(__file__).with_name("global-lb-publish.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)

class HA:
    def __init__(self, binary, store, prefix, instance, echo, extra="", master=False, servers=None, dns="", level="admin", reserve="100ms"):
        self.front, self.admin = p.listener(), p.listener()
        self.logs = b""
        self.closed = False
        self.iid = instance.encode().hex().encode()
        config = f"""global
 nbthread 4
 stats socket fd@{self.admin.fileno()} level {level}
 global-lb state-store {store}
 global-lb key-prefix {prefix}
 global-lb instance-id {instance}
 global-lb timeout reserve {reserve}
 global-lb heartbeat-interval 300ms
 global-lb instance-timeout 3s
{extra}
defaults
 mode tcp
 timeout connect 100ms
 timeout client 30s
 timeout server 30s
frontend fe
 bind fd@{self.front.fileno()}
 default_backend be
backend be
 balance global-leastconn
{servers or f' server s0 127.0.0.1:{echo.address[1]}'}
{dns}
"""
        args = [binary, "-db", "-f", "/dev/stdin"]
        if master: args.insert(1, "-W")
        self.proc = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                     stderr=subprocess.PIPE, pass_fds=(self.front.fileno(), self.admin.fileno()))
        self.proc.stdin.write(config.encode()); self.proc.stdin.close()
        p.wait(lambda: self.cli("show info"))

    def cli(self, command):
        if self.proc.poll() is not None: raise AssertionError(self.proc.stderr.read())
        try:
            with socket.create_connection(self.admin.getsockname(), 1) as peer:
                peer.settimeout(1); peer.sendall(command.encode()+b"\n")
                chunks = []
                while True:
                    data = peer.recv(65536)
                    if not data: return b"".join(chunks)
                    chunks.append(data)
        except OSError: return False

    def connect(self):
        peer = socket.create_connection(self.front.getsockname(), 2)
        peer.settimeout(3); self.probe(peer); return peer

    @staticmethod
    def probe(peer):
        peer.sendall(b"long-tcp"); assert peer.recv(8) == b"long-tcp"

    def close(self, sig=signal.SIGTERM):
        if self.closed: return 0
        self.closed = True
        start = time.monotonic()
        if self.proc.poll() is None: self.proc.send_signal(sig)
        try: self.proc.wait(3)
        except subprocess.TimeoutExpired:
            self.proc.kill(); self.proc.wait(2); raise
        elapsed = time.monotonic() - start
        if not self.logs: self.logs = self.proc.stderr.read()+self.proc.stdout.read()
        self.front.close(); self.admin.close()
        assert not any(x in self.logs for x in (b"BUG", b"AddressSanitizer", b"runtime error:", b"Assertion")), self.logs
        if sig != signal.SIGKILL: assert self.proc.returncode == 0, (self.proc.returncode, self.logs)
        return elapsed

class Proxy:
    """Transparent RESP fault proxy. One persistent upstream per HA connection.
    Hooks run AFTER Lua has executed, to inject genuinely uncertain replies.
    """
    def __init__(self, upstream):
        self.upstream = upstream
        self.sock = p.listener(); self.address = self.sock.getsockname()[:2]
        self.commands, self.sockets = [], []
        self.hook = None; self.down = False; self.stop = threading.Event()
        self.thread = threading.Thread(target=self.accept, daemon=True); self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try: peer, _ = self.sock.accept()
            except socket.timeout: continue
            except OSError: return
            if self.down: peer.close(); continue
            self.sockets.append(peer)
            threading.Thread(target=self.run, args=(peer,), daemon=True).start()

    @staticmethod
    def response(r):
        if isinstance(r, int): return b":"+str(r).encode()+b"\r\n"
        if isinstance(r, list): return b"*"+str(len(r)).encode()+b"\r\n"+b"".join(Proxy.response(x) for x in r)
        if r is None: return b"$-1\r\n"
        return b"$"+str(len(r)).encode()+b"\r\n"+r+b"\r\n"

    def run(self, peer):
        try:
            with peer, socket.create_connection(self.upstream, 2) as upstream:
                peer.settimeout(5); upstream.settimeout(5)
                with peer.makefile("rb") as stream, upstream.makefile("rb") as inp:
                    while not self.stop.is_set():
                        args = p.read(stream)
                        self.commands.append((time.monotonic(), args))
                        upstream.sendall(p.encode(args)); result = p.read(inp)
                        hook = self.hook
                        if hook and hook(args, result): return
                        peer.sendall(self.response(result))
        except (OSError, RuntimeError, TypeError, AssertionError): pass

    def cut(self):
        for peer in list(self.sockets):
            try: peer.shutdown(socket.SHUT_RDWR)
            except OSError: pass

    def ops(self, instance=None):
        return [args for _, args in self.commands if instance is None or args[8] == instance]

    def close(self):
        self.stop.set(); self.cut(); self.sock.close(); self.thread.join(1)

def run(binary, image):
    token = uuid.uuid4().hex
    container = None
    try:
        server = "valkey-server" if "valkey:" in image else "redis-server"
        container = subprocess.check_output(["docker", "run", "--pull=never", "--rm", "-d",
                    "--label", "global-lb-v2-lifecycle="+token, "-p", "127.0.0.1::6379",
                    image, server, "--save", "", "--appendonly", "no"], text=True).strip()
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
        port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
        address = ("127.0.0.1", port)
        def cmd(*args): return p.command(address, *args)
        def ready():
            try: return cmd("PING") == b"PONG"
            except (OSError, RuntimeError): return False
        p.wait(ready)
        def key(prefix, field): return f"glb:v2:{prefix.encode().hex()}:{field}"
        def rows(prefix, field):
            raw = cmd("HGETALL", key(prefix, field)); return dict(zip(raw[::2], raw[1::2]))
        def total(prefix): return sum(int(n) for n in rows(prefix, "counts").values())
        def meta(prefix, ha):
            return rows(prefix, "liveness").get(ha.iid, b"0|0|0|R").split(b"|")
        with contextlib.ExitStack() as stack:
            echo = p.Echo(); stack.callback(echo.close)
            proxy = Proxy(address); stack.callback(proxy.close)
            store = f"127.0.0.1:{proxy.address[1]}"
            prefix = "lifecycle/"+token
            ha = HA(binary, store, prefix, "ha-0", echo); stack.callback(ha.close)
            p.wait(lambda: meta(prefix, ha)[3] == b"A")
            old_uuid = rows(prefix, "owners")[ha.iid]
            peers = [ha.connect() for _ in range(100)]
            for peer in peers: stack.callback(peer.close)
            p.wait(lambda: total(prefix) == 100)
            before = len(proxy.commands); time.sleep(.7)
            newops = [a[7] for _, a in proxy.commands[before:]]
            assert b"heartbeat" in newops and b"restore" not in newops, newops
            assert len(rows(prefix, "requests")) == total(prefix) == 100
            print("PASS: production startup/HB only, 100 long TCP reservations, no periodic count sync")

            # Real transport failure; old TCP survives, fallback is captured.
            proxy.down = True; proxy.cut(); time.sleep(.12)
            extra = [ha.connect() for _ in range(10)]
            for peer in extra: stack.callback(peer.close)
            for peer in peers[:20]: peer.close()
            HA.probe(peers[20]); HA.probe(extra[0])
            revision = int(meta(prefix, ha)[0])
            proxy.down = False
            p.wait(lambda: total(prefix) == 90 and int(meta(prefix, ha)[0]) > revision)
            assert rows(prefix, "owners")[ha.iid] == old_uuid
            assert len(rows(prefix, "requests")) == 90
            HA.probe(peers[20]); HA.probe(extra[0])
            fresh = ha.connect(); stack.callback(fresh.close)
            p.wait(lambda: total(prefix) == 91)
            fresh.close(); p.wait(lambda: total(prefix) == 90)
            assert sum(a[7] == b"start" for a in proxy.ops(ha.iid)) == 1
            print("PASS: reconnect same UUID, coherent >32-entry capture/commit, fallback and concurrent releases restored")

            # Drop a successfully applied RELEASE reply; then reconcile rather
            # than indefinitely retaining a lost delta behind healthy HB.
            dropped = threading.Event()
            def lose_release(args, result):
                if args[7] == b"release" and not dropped.is_set(): dropped.set(); return True
                return False
            proxy.hook = lose_release
            revision = int(meta(prefix, ha)[0]); peers[20].close()
            assert dropped.wait(2)
            p.wait(lambda: total(prefix) == 89 and int(meta(prefix, ha)[0]) > revision)
            proxy.hook = None
            assert rows(prefix, "owners")[ha.iid] == old_uuid
            print("PASS: uncertain release causes fresh same-UUID reconciliation, no HB-only leaked count")

            # New connections/closures while RESTORE is awaiting confirmation
            # must cause a new revision, never activate a stale capture.
            held, release = threading.Event(), threading.Event()
            def hold_restore(args, result):
                if args[7] == b"restore" and not held.is_set():
                    held.set(); release.wait(.6)
                return False
            proxy.hook = hold_restore; proxy.cut()
            assert held.wait(3)
            held_revision = int(meta(prefix, ha)[0])
            during = ha.connect(); stack.callback(during.close)
            peers[21].close(); release.set()
            p.wait(lambda: total(prefix) == 89 and len(rows(prefix, "requests")) == 89
                   and int(meta(prefix, ha)[0]) > held_revision)
            proxy.hook = None
            HA.probe(during)
            p.wait(lambda: any(a[7] == b"heartbeat" for a in proxy.ops(ha.iid)[-3:]))
            assert rows(prefix, "owners")[ha.iid] == old_uuid
            print("PASS: local mutation during RESTORE confirmation cannot commit stale snapshot")

            # Restart the OWNED memory-mode container, not the user's store.
            subprocess.run(["docker", "restart", container], check=True, stdout=subprocess.DEVNULL)
            info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
            address = ("127.0.0.1", int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"]))
            proxy.upstream = address  # Docker may reassign an ephemeral host port.
            p.wait(ready)
            p.wait(lambda: total(prefix) == 89 and len(rows(prefix, "requests")) == 89, 8)
            assert rows(prefix, "owners")[ha.iid] == old_uuid
            HA.probe(during)
            assert sum(a[7] == b"start" for a in proxy.ops(ha.iid)) == 1
            print("PASS: Redis/Valkey memory-store restart re-registers same UUID/current native ledger")

            for peer in peers[22:]: peer.close()
            for peer in extra: peer.close()
            during.close(); p.wait(lambda: total(prefix) == 0 and not rows(prefix, "requests"))
            for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGUSR1):
                pref = prefix+"-stop-"+str(sig)
                stopping = HA(binary, store, pref, "stop-0", echo); stack.callback(stopping.close)
                p.wait(lambda: meta(pref, stopping)[3] == b"A")
                peer = stopping.connect(); stack.callback(peer.close)
                p.wait(lambda: total(pref) == 1)
                elapsed = stopping.close(sig)
                assert elapsed < .6, elapsed
                assert meta(pref, stopping)[3] == b"D" and total(pref) == 0
                assert stopping.iid in rows(pref, "owners") and not rows(pref, "requests")
                assert b"cleanup=excluded" in stopping.logs, stopping.logs
                assert peer.recv(1) == b""
            print("PASS: SIGTERM/SIGINT/SIGUSR1 stop admission, UUID exclusion, TCP teardown and retained owner fence")

            # UUID mismatch never steals on reconnect nor deletes new writer.
            other = str(uuid.uuid4()).encode()
            cmd("HSET", key(prefix, "owners"), ha.iid, other)
            proxy.cut(); time.sleep(.6)
            peer = ha.connect(); stack.callback(peer.close); HA.probe(peer)
            assert rows(prefix, "owners")[ha.iid] == other
            ha.close()
            assert rows(prefix, "owners")[ha.iid] == other
            assert b"owner/terminal fenced" in ha.logs
            print("PASS: other writer remains owner; old worker stays local and conditional STOP cannot delete it")

            # Startup while unavailable must include already accepted fallback
            # native reservations in its FIRST atomic START, not reset to zero.
            proxy.down = True
            pref = prefix+"-startup"
            startup = HA(binary, store, pref, "startup-0", echo); stack.callback(startup.close)
            slots = [startup.connect() for _ in range(10)]
            for peer in slots: stack.callback(peer.close)
            proxy.down = False
            p.wait(lambda: total(pref) == 10)
            initial = next(a for a in proxy.ops(startup.iid) if a[7] in (b"start", b"restore"))
            assert int(initial[20]) == 10, initial
            assert sum(a[7] == b"start" for a in proxy.ops(startup.iid)) <= 1
            print("PASS: delayed startup/uncertain START registration includes fallback reservations already alive")

            # Explicit group request limit != native maxconn: excess connections
            # still forward locally; no partial restore/forced TCP shutdown.
            pref = prefix+"-limit"
            limited = HA(binary, store, pref, "limited-0", echo,
                         extra=" global-lb max-requests 2\n global-lb max-instances 16")
            stack.callback(limited.close); p.wait(lambda: meta(pref, limited)[3] == b"A")
            limpeers = [limited.connect() for _ in range(3)]
            for peer in limpeers: stack.callback(peer.close); HA.probe(peer)
            time.sleep(.2); assert total(pref) <= 2
            revision = int(meta(pref, limited)[0])
            limpeers[-1].close()
            p.wait(lambda: total(pref) == 2 and int(meta(pref, limited)[0]) > revision)
            limited.close(); assert b"limit; local leastconn" in limited.logs
            print("PASS: configured group limit logs/falls back, leaves native TCP intact and recovers after scale shrinks")

            pref = prefix+"-owners"
            one = HA(binary, store, pref, "one-0", echo, extra=" global-lb max-instances 1")
            stack.callback(one.close); p.wait(lambda: meta(pref, one)[3] == b"A")
            two = HA(binary, store, pref, "two-0", echo, extra=" global-lb max-instances 1")
            stack.callback(two.close)
            peer = two.connect(); stack.callback(peer.close); HA.probe(peer)
            time.sleep(.2); assert len(rows(pref, "owners")) == 1
            two.close(); assert one.iid in rows(pref, "owners") and b"resource limit" in two.logs
            print("PASS: configured owner-record limit preserves existing instance, new worker serves local fallback")

            proxy.down = True
            for i in range(8):
                unavailable = HA(binary, store, prefix+"-unavailable", f"unavailable-{i}", echo)
                stack.callback(unavailable.close)
                peer = unavailable.connect(); stack.callback(peer.close)
                assert unavailable.close() < .6
            proxy.down = False
            print("PASS: 8 unavailable-store terminal stops, fallback TCP, no idle-thread hang")

            pref = prefix+"-inflight"
            inflight = HA(binary, store, pref, "inflight-0", echo); stack.callback(inflight.close)
            p.wait(lambda: meta(pref, inflight)[3] == b"A"); time.sleep(.05)
            reserved = threading.Event()
            def terminal_reserve(args, result):
                if args[8] == inflight.iid and args[7] == b"reserve":
                    reserved.set(); time.sleep(.05)
                return False
            proxy.hook = terminal_reserve
            peer = socket.create_connection(inflight.front.getsockname(), 2)
            stack.callback(peer.close); peer.settimeout(2)
            assert reserved.wait(2)
            assert inflight.close() < .6
            proxy.hook = None
            assert meta(pref, inflight)[3] == b"D" and total(pref) == 0 and not rows(pref, "requests")
            ops = [a[7] for a in proxy.ops(inflight.iid)]
            assert ops[-1] == b"stop" and ops.count(b"reserve") == 1, ops
            print("PASS: terminal drains in-flight TAKE then STOP, no late re-registration/HB/reservation")

            # STOP while a RESTORE response is unavailable shares the existing
            # 100ms total deadline; shutdown never waits for full backoff/drain.
            held, release = threading.Event(), threading.Event()
            def terminal_hold(args, result):
                if args[8] == startup.iid and args[7] == b"restore":
                    held.set(); release.wait(1)
                return False
            proxy.hook = terminal_hold; proxy.cut(); assert held.wait(4)
            elapsed = startup.close(); release.set(); proxy.hook = None
            assert elapsed < .6 and b"cleanup=timeout" in startup.logs, (elapsed, startup.logs)
            print(f"PASS: terminal during in-flight restore bounded ({elapsed:.3f}s), no reconnect/re-registration")

            pref = prefix+"-master"
            master = HA(binary, store, pref, "master-0", echo, master=True); stack.callback(master.close)
            p.wait(lambda: meta(pref, master)[3] == b"A")
            peer = master.connect(); stack.callback(peer.close); master.close()
            assert meta(pref, master)[3] == b"D" and total(pref) == 0
            print("PASS: master-worker forwards terminal cleanup into worker lifecycle")

            pref = prefix+"-crash"
            a, b = p.TaggedEcho(b"A"), p.TaggedEcho(b"B")
            stack.callback(a.close); stack.callback(b.close)
            dead = HA(binary, store, pref, "dead-0", a); stack.callback(dead.close)
            survivor = HA(binary, store, pref, "survivor-0", a,
                          servers=f" server a 127.0.0.1:{a.address[1]}\n server b 127.0.0.1:{b.address[1]}")
            stack.callback(survivor.close)
            p.wait(lambda: len(rows(pref, "liveness")) == 2)
            def tagged(ha, tag):
                peer = socket.create_connection(ha.front.getsockname(), 2); peer.settimeout(3)
                assert peer.recv(1) == tag; stack.callback(peer.close); return peer
            deadpeers = [tagged(dead, b"A") for _ in range(5)]
            p.wait(lambda: total(pref) == 5)
            before = tagged(survivor, b"B"); p.wait(lambda: total(pref) == 6)
            old = rows(pref, "owners")[dead.iid]
            dead.close(signal.SIGKILL)
            assert meta(pref, dead)[3] == b"A"  # no graceful STOP sent
            time.sleep(3.15)
            after = tagged(survivor, b"A")
            p.wait(lambda: total(pref) == 7)
            assert len(rows(pref, "requests")) == 7  # stale physical data still retained
            restarted = HA(binary, store, pref, "dead-0", a); stack.callback(restarted.close)
            p.wait(lambda: rows(pref, "owners").get(dead.iid) != old and total(pref) == 2)
            assert rows(pref, "owners")[survivor.iid] != old
            restarted.close(); before.close(); after.close()
            print("PASS: crash has no STOP; >3s stale counts excluded from selection, restart replaces only own UUID/counts")

            dns = p.DNS(); stack.callback(dns.close)
            pref = prefix+"-dns"
            resolver = f"""resolvers default
 nameserver owned 127.0.0.1:{dns.port}
 hold valid 100ms
 hold nx 100ms
 hold timeout 100ms
 timeout resolve 100ms
 timeout retry 100ms
"""
            name = HA(binary, f"store.test:{proxy.address[1]}", pref, "dns-0", echo, dns=resolver)
            stack.callback(name.close)
            peer = name.connect(); stack.callback(peer.close)
            time.sleep(.2); assert not rows(pref, "owners")
            dns.answer = "127.0.0.1"
            p.wait(lambda: total(pref) == 1, 8); HA.probe(peer)
            name.close(); assert meta(pref, name)[3] == b"D"
            print("PASS: asynchronous state-store DNS unavailable at startup, local TCP then same-worker registration")
        print(f"PASS: production v2 lifecycle ({image})")
    finally:
        if container: subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL)

if __name__ == "__main__": run(os.path.abspath(sys.argv[1]), sys.argv[2])

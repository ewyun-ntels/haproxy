#!/usr/bin/env python3
"""UD-012/016 v2-r4: common/OFF copied CLI and no-store-I/O smoke.
Usage: global-lb-v2-cli-fences.py HAPROXY_BINARY common|off|v1
Only owned loopback sockets, no Docker/store dependency.
"""
import importlib.util
import os
from pathlib import Path
import socket
import signal
import subprocess
import sys

spec = importlib.util.spec_from_file_location("publish", Path(__file__).with_name("global-lb-publish.py"))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)

def run(binary, mode):
    assert mode in ("common", "off", "v1")
    front, admin, store = p.listener(), p.listener(), p.listener()
    echo = p.Echo(); proc = None
    try:
        settings = f""" global-lb state-store 127.0.0.1:{store.getsockname()[1]}
 global-lb instance-id common-0
""" if mode != "off" else ""
        if mode == "common": settings += " global-lb heartbeat-interval 300ms\n"
        config = f"""global
 nbthread 4
 stats socket fd@{admin.fileno()} level admin
{settings}defaults
 mode tcp
 timeout connect 1s
 timeout client 3s
 timeout server 3s
frontend fe
 bind fd@{front.fileno()}
 default_backend be
backend be
 balance leastconn
 server s0 127.0.0.1:{echo.address[1]}
"""
        proc = subprocess.Popen([binary, "-db", "-f", "/dev/stdin"], stdin=subprocess.PIPE,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(front.fileno(), admin.fileno()))
        proc.stdin.write(config.encode()); proc.stdin.close()
        def cli(command):
            if proc.poll() is not None: raise AssertionError(proc.stderr.read())
            try:
                with socket.create_connection(admin.getsockname(), 1) as peer:
                    peer.settimeout(1); peer.sendall(command.encode()+b"\n"); result = b""
                    while True:
                        data = peer.recv(65536)
                        if not data: return result
                        result += data
            except OSError: return False
        p.wait(lambda: cli("show info"))
        commands = ("show global-lb status", "show global-lb reservations", "show global-lb local")
        for _ in range(20):
            for command in commands:
                result = cli(command)
                if mode == "off": assert b"Unknown command" in result, result
                elif mode == "v1":
                    if command.endswith("reservations"): assert b"requires v2 reservation mode" in result, result
                    elif command.endswith("status"): assert b"cache_version:" in result and b"mode: v2-reservation" not in result, result
                elif command.endswith("status"):
                    assert b"mode: v2-reservation\n" in result and b"state: DISABLED\n" in result, result
                    assert b"enabled: 0\n" in result and (b"transport: DISABLED\n" in result or b"transport: IDLE\n" in result), result
                elif command.endswith("reservations"): assert b"entries: 0\n" in result, result
        with socket.create_connection(front.getsockname(), 1) as peer:
            peer.settimeout(1); peer.sendall(b"native-tcp"); assert peer.recv(10) == b"native-tcp"
            assert bool(cli("show info"))
        store.settimeout(.4)
        try:
            unexpected, _ = store.accept(); unexpected.close(); raise AssertionError("common/OFF contacted state-store")
        except socket.timeout: pass
        proc.terminate(); proc.wait(3)
        logs = proc.stderr.read()+proc.stdout.read()
        # Non-opted-in workers retain native SIGTERM semantics, not the v2
        # intercepted cleanup exit status. Negative SIGTERM is legitimate.
        assert proc.returncode in (0, -signal.SIGTERM) and b"BUG" not in logs and b"runtime error:" not in logs, (proc.returncode, logs)
        print(f"PASS: {mode} native TCP/CLI and no state-store I/O; diagnostics remain inactive or absent")
    finally:
        if proc and proc.poll() is None: proc.kill(); proc.wait(2)
        for peer in (front, admin, store): peer.close()
        echo.close()

if __name__ == "__main__": run(os.path.abspath(sys.argv[1]), sys.argv[2])

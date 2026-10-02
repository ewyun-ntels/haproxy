#!/usr/bin/env python3
"""UD-007/009/011 v2-r1: staged cfg must not activate v1 snapshot I/O.
Uses owned loopback listeners only; no Redis/Valkey or fixed user ports.
"""
import contextlib
import importlib.util
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import time

spec = importlib.util.spec_from_file_location("publish", Path(__file__).with_name("global-lb-publish.py"))
p = importlib.util.module_from_spec(spec)
spec.loader.exec_module(p)
binary = os.path.abspath(sys.argv[1])
mode = sys.argv[2] if len(sys.argv) > 2 else "on"

with contextlib.ExitStack() as stack:
    echo = p.Echo()
    stack.callback(echo.close)
    front, admin, store = (stack.enter_context(p.listener()) for _ in range(3))
    settings = "" if mode == "off" else f""" global-lb state-store 127.0.0.1:{store.getsockname()[1]}
 global-lb instance-id v2-runtime/ha-0
 global-lb timeout reserve 100ms
 global-lb heartbeat-interval 300ms
 global-lb instance-timeout 3s
"""
    algorithm = "global-leastconn" if mode == "on" else "leastconn"
    config = f"""global
 nbthread 4
 stats socket fd@{admin.fileno()} level admin
{settings}defaults
 mode tcp
 timeout connect 1s
 timeout client 10s
 timeout server 10s
frontend fe
 bind fd@{front.fileno()}
 default_backend be
backend be
 balance {algorithm}
 server s1 127.0.0.1:{echo.address[1]}
"""
    proc = subprocess.Popen([binary, "-db", "-f", "/dev/stdin"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            pass_fds=(front.fileno(), admin.fileno()))
    def cleanup():
        if proc.poll() is None:
            proc.terminate()
        proc.wait(3)
    stack.callback(cleanup)
    proc.stdin.write(config.encode())
    proc.stdin.close()
    def cli(command):
        with socket.create_connection(admin.getsockname(), timeout=2) as peer:
            peer.sendall(command.encode()+b"\n")
            out = b""
            while True:
                data = peer.recv(4096)
                if not data:
                    return out
                out += data
    p.wait(lambda: cli("show info"))
    with socket.create_connection(front.getsockname(), timeout=2) as peer:
        peer.sendall(b"native-tcp-preserved")
        assert peer.recv(100) == b"native-tcp-preserved"
        if mode == "off":
            assert b"Unknown command" in cli("show global-lb local")
        else:
            local = cli("show global-lb local")
            assert b"cur_sess\tserved" in local and b"\t1\t1\n" in local, local
        time.sleep(0.35)
        peer.sendall(b"long-tcp-still-alive")
        assert peer.recv(100) == b"long-tcp-still-alive"
        try:
            incoming, _ = store.accept()
        except socket.timeout:
            incoming = None
        if incoming:
            incoming.close()
            raise AssertionError("v2 config incorrectly activated v1 state-store I/O")
    proc.send_signal(signal.SIGTERM)
    proc.wait(3)
    logs = proc.stdout.read() + proc.stderr.read()
    assert proc.returncode in (0, -signal.SIGTERM, 128+signal.SIGTERM), (proc.returncode, logs)
    if mode == "on":
        assert b"runtime integration pending" in logs, logs
    assert b"BUG" not in logs and b"AddressSanitizer" not in logs, logs
print(f"PASS: {mode}: native TCP/CLI/termination preserved; no v1 I/O for staged v2")

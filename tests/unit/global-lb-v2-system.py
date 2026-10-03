#!/usr/bin/env python3
"""UD-001/003/004/012/016 v2-r4: owned SRV fixture + PPv2 + TCP splice.
Not a Kubernetes/MetalLB deployment certification. No user store/keys/ports.
Usage: global-lb-v2-system.py HAPROXY_BINARY STORE_IMAGE
"""
import contextlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import struct
import subprocess
import sys
import threading
import uuid

spec = importlib.util.spec_from_file_location("lc", Path(__file__).with_name("global-lb-v2-lifecycle.py"))
lc = importlib.util.module_from_spec(spec); spec.loader.exec_module(lc)
p = lc.p

def recv(peer, n):
    out = b""
    while len(out) < n:
        data = peer.recv(n-len(out))
        if not data: raise EOFError
        out += data
    return out

class PP2Echo(p.Echo):
    def __init__(self):
        self.headers = self.checks = self.traffic = 0
        self.errors = []
        super().__init__()

    def echo(self, peer):
        with peer:
            peer.settimeout(2)
            header_ok, payload_seen = False, False
            try:
                header = recv(peer, 16)
                assert header[:12] == b"\r\n\r\n\x00\r\nQUIT\n", header
                assert header[12] in (0x20, 0x21), header
                recv(peer, int.from_bytes(header[14:16], "big"))
                self.headers += 1
                header_ok = True
                data = peer.recv(65536)
                if not data: self.checks += 1; return  # PPv2 followed by EOF
                self.traffic += 1
                payload_seen = True
                while data and not self.stop.is_set():
                    peer.sendall(data)
                    while not self.stop.is_set():
                        try: data = peer.recv(65536); break
                        except socket.timeout: continue  # preserve idle long TCP
            except (EOFError, ConnectionResetError, BrokenPipeError):
                if header_ok and not payload_seen: self.checks += 1
            except Exception as error:
                if not self.stop.is_set(): self.errors.append(repr(error))

class SRV(p.DNS):
    def __init__(self, endpoints):
        self.endpoints = endpoints
        super().__init__()

    @staticmethod
    def name(text):
        return b"".join(bytes([len(s)])+s.encode() for s in text.split("."))+b"\0"

    def run(self):
        while not self.stop.is_set():
            try: packet, addr = self.sock.recvfrom(4096)
            except socket.timeout: continue
            except OSError: return
            end = 12
            while packet[end]: end += packet[end]+1
            end += 5
            question = packet[12:end]
            qtype = int.from_bytes(question[-4:-2], "big")
            answers, additional = [], []
            for i, peer in self.endpoints:
                name = self.name(f"endpoint{i}.test")
                if qtype == 33:
                    data = struct.pack("!HHH", 0, 1, peer.address[1])+name
                    answers.append(b"\xc0\x0c"+struct.pack("!HHIH", 33, 1, 1, len(data))+data)
                    additional.append(name+struct.pack("!HHIH", 1, 1, 1, 4)+socket.inet_aton("127.0.0.1"))
                elif qtype == 1:
                    answers = [b"\xc0\x0c"+struct.pack("!HHIH", 1, 1, 1, 4)+socket.inet_aton("127.0.0.1")]
            header = packet[:2]+struct.pack("!HHHHH", 0x8180, 1, len(answers), 0, len(additional))
            try: self.sock.sendto(header+question+b"".join(answers+additional), addr)
            except OSError: return

def run(binary, image):
    token = uuid.uuid4().hex; container = None
    try:
        server = "valkey-server" if "valkey:" in image else "redis-server"
        container = subprocess.check_output(["docker", "run", "--pull=never", "--rm", "-d",
            "--label", "global-lb-v2-system="+token, "-p", "127.0.0.1::6379", image,
            server, "--save", "", "--appendonly", "no"], text=True).strip()
        info = json.loads(subprocess.check_output(["docker", "inspect", container]))[0]
        port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
        address = ("127.0.0.1", port)
        def ready():
            try: return p.command(address, "PING") == b"PONG"
            except (OSError, RuntimeError): return False
        p.wait(ready)
        prefix = "system/"+token
        def rows(field):
            raw = p.command(address, "HGETALL", f"glb:v2:{prefix.encode().hex()}:{field}")
            return dict(zip(raw[::2], raw[1::2]))
        def total(): return sum(int(n) for n in rows("counts").values())
        with contextlib.ExitStack() as stack:
            echoes = [PP2Echo() for _ in range(3)]
            for e in echoes: stack.callback(e.close)
            dns = SRV(list(enumerate(echoes[:2]))); stack.callback(dns.close)
            resolver = f"""resolvers service
 nameserver owned 127.0.0.1:{dns.port}
 hold valid 100ms
 hold obsolete 100ms
 hold nx 100ms
 timeout resolve 100ms
 timeout retry 100ms
"""
            servers = " option splice-auto\n server-template s 1-3 _tcp._tcp.backend.test resolvers service init-addr none check check-send-proxy send-proxy-v2 inter 100ms rise 1 fall 1"
            ha = lc.HA(binary, f"127.0.0.1:{port}", prefix, "system-0", echoes[0], servers=servers, dns=resolver)
            stack.callback(ha.close)
            def running_ports():
                return {int(row.split(b"\t")[2].rsplit(b":", 1)[1]) for row in ha.cli("show global-lb local").splitlines()
                        if b"\tRUNNING\t" in row and b":0\t" not in row}
            p.wait(lambda: set(e.address[1] for e in echoes[:2]) <= running_ports(), 8)
            def connect():
                peer = socket.create_connection(ha.front.getsockname(), 2); peer.settimeout(3)
                lc.HA.probe(peer); stack.callback(peer.close); return peer
            peers = [connect() for _ in range(10)]
            p.wait(lambda: total() == 10)
            try: p.wait(lambda: all(e.checks and e.traffic for e in echoes[:2]))
            except AssertionError:
                print("PPv2 DIAGNOSTICS:", [(e.headers, e.checks, e.traffic, e.errors) for e in echoes], flush=True)
                raise
            assert len(rows("requests")) == 10
            print("PASS: actual SRV server-template resolution/health checks, PPv2+EOF checks excluded from 10 reservations")
            dns.endpoints = list(enumerate(echoes))
            p.wait(lambda: echoes[2].address[1] in running_ports(), 8)
            new = connect(); p.wait(lambda: echoes[2].traffic > 0)
            p.wait(lambda: total() == 11)
            # DNS removes endpoint 0; its established TCP and immutable key remain.
            original = dict(rows("counts"))
            dns.endpoints = list(enumerate(echoes))[1:]
            p.wait(lambda: echoes[0].address[1] not in running_ports(), 8)
            for peer in peers: lc.HA.probe(peer)
            assert rows("counts") == original
            added = [connect() for _ in range(4)]
            p.wait(lambda: total() == 15)
            print("PASS: SRV add/remove preserves existing TCP/old identity; new healthy endpoint used")
            # Bulk bidirectional forwarding must retain PPv2 framing and the
            # same single reservation even when eligible for kernel splice.
            bulk = b"x"*(2*1024*1024)
            thread = threading.Thread(target=new.sendall, args=(bulk,)); thread.start()
            assert recv(new, len(bulk)) == bulk; thread.join(3); assert not thread.is_alive()
            info = ha.cli("show info")
            spliced = int(next(line.split(b": ", 1)[1] for line in info.splitlines() if line.startswith(b"TotalSplicedBytesOut: ")))
            assert spliced > 0, info
            assert total() == 15 and len(rows("requests")) == 15
            print(f"PASS: 2MiB PPv2 TCP forwarding, actual kernel splice ({spliced} bytes), no duplicate reservation")
            for peer in peers+added+[new]: peer.close()
            p.wait(lambda: total() == 0 and not rows("requests"))
            # Real runtime-created server deletion; static template removal
            # above is DNS state/remap, not native dynamic object deletion.
            reply = ha.cli(f"add server be/dyn 127.0.0.1:{echoes[2].address[1]} send-proxy-v2")
            assert b"New server registered" in reply, reply
            ha.cli("enable server be/dyn")
            for slot in ("s1", "s2", "s3"): ha.cli(f"disable server be/{slot}")
            dyn = connect(); p.wait(lambda: total() == 1)
            dyn.close(); p.wait(lambda: total() == 0 and not rows("requests"))
            ha.cli("disable server be/dyn")
            reply = ha.cli("del server be/dyn")
            assert b"Server deleted" in reply, reply
            assert not any(e.errors for e in echoes), [e.errors for e in echoes]
            print("PASS: dynamic native server create/select/release/delete; no dangling ledger identity")
        print(f"PASS: local SRV/PPv2/splice system integration ({image})")
    finally:
        if container: subprocess.run(["docker", "rm", "-f", container], check=False, stdout=subprocess.DEVNULL)

if __name__ == "__main__": run(os.path.abspath(sys.argv[1]), sys.argv[2])

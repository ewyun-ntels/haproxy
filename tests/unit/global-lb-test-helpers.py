#!/usr/bin/env python3
"""UD-016 v2-only-20261004: isolated RESP, TCP echo and DNS fixtures."""
import socket
import struct
import threading
import time

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


class TaggedEcho(Echo):
    def __init__(self, tag):
        self.tag = tag
        super().__init__()

    def echo(self, peer):
        with peer:
            peer.settimeout(0.2)
            peer.sendall(self.tag)
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

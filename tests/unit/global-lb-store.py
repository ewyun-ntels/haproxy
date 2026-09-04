#!/usr/bin/env python3
"""UD-007 r5 / UD-011 r3: test C-generated EVAL against a disposable store.

Usage: python3 tests/unit/global-lb-store.py BUILDER IMAGE
Never connects to an existing store. IMAGE must already be available locally.
Creates only one labeled, loopback-bound container and removes it on exit.
"""
import io
import json
import socket
import subprocess
import sys
import time
import uuid


class RespError(str):
    pass


def read(stream):
    line = stream.readline()
    if not line.endswith(b"\r\n"):
        raise RuntimeError("incomplete RESP reply")
    kind, body = line[:1], line[1:-2]
    if kind == b"+":
        return body
    if kind == b"-":
        return RespError(body.decode())
    if kind == b":":
        return int(body)
    if kind == b"$":
        length = int(body)
        if length == -1:
            return None
        data = stream.read(length)
        assert len(data) == length and stream.read(2) == b"\r\n"
        return data
    if kind == b"*":
        return [read(stream) for _ in range(int(body))]
    raise RuntimeError(f"unsupported RESP {line!r}")


def encode(args):
    args = [x if isinstance(x, bytes) else str(x).encode() for x in args]
    return b"*%d\r\n" % len(args) + b"".join(
        b"$%d\r\n" % len(x) + x + b"\r\n" for x in args
    )


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


builder, image = sys.argv[1:]
token = uuid.uuid4().hex
container = None
sock = stream = None
checks = 0


def check(condition, message):
    global checks
    if not condition:
        raise AssertionError(message)
    checks += 1


try:
    server = "valkey-server" if image.split("/")[-1].startswith("valkey:") else "redis-server"
    container = docker("run", "--pull=never", "--rm", "-d",
                       "--label", "global-lb-unit-test=" + token,
                       "-p", "127.0.0.1::6379", image, server,
                       "--save", "", "--appendonly", "no",
                       "--maxmemory", "64mb", "--maxmemory-policy", "noeviction")
    info = json.loads(docker("inspect", container))[0]
    port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
    for attempt in range(100):
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=3)
            stream = sock.makefile("rb")
            sock.sendall(encode(["PING"]))
            if read(stream) != b"PONG":
                raise RuntimeError("unexpected readiness reply")
            break
        except OSError:
            if stream:
                stream.close()
                stream = None
            if sock:
                sock.close()
                sock = None
            time.sleep(0.05)
    if sock is None:
        raise RuntimeError("disposable store did not start")

    def send(wire):
        sock.sendall(wire)
        return read(stream)

    def cmd(*args):
        return send(encode(args))

    def request(op=1, seq=1, gen=None, ttl=3000, entries=(), instance="ha-0"):
        args = [builder, "--request", str(op), "test[*]:" + token, instance,
                gen or a, str(seq), str(ttl), "1048576"]
        for field, count in entries:
            args.extend([field, str(count)])
        return subprocess.check_output(args)

    a, b = str(uuid.uuid4()), str(uuid.uuid4())
    initial = request(0, 1, entries=[("be_a|10.0.0.1:5000", 100),
                                     ("be_b|[::1]:6000", 50)])
    args = read(io.BytesIO(initial))
    owner, snapshot = args[3:5]

    def state():
        return cmd("HGETALL", owner), cmd("HGETALL", snapshot)

    def value(field):
        return cmd("HGET", snapshot, field)

    def reject(wire, expected, label):
        before = state()
        ttl_before = cmd("PTTL", snapshot)
        check(send(wire) == expected, label + " status")
        check(state() == before, label + " data unchanged")
        ttl_after = cmd("PTTL", snapshot)
        check(ttl_after <= ttl_before, label + " TTL not refreshed")

    check(cmd("PING") == b"PONG", "isolated store ready")
    check(send(initial) == 1, "startup")
    check(value("c:be_a|10.0.0.1:5000") == b"100", "startup actual count, not forced zero")
    check(0 < cmd("PTTL", snapshot) <= 3000, "snapshot 3s TTL")
    check(cmd("PTTL", owner) == -1, "persistent metadata")
    reject(request(1, 99, b), -1, "different writer update")
    reject(request(2, 99, b), -1, "different writer delete")
    reject(request(1, 1), 0, "equal sequence")
    check(send(request(1, 3, entries=[("be_a|10.0.0.2:5000", 7)])) == 1,
          "fresh reconnect same UUID")
    check(value("c:be_a|10.0.0.1:5000") is None, "removed endpoint gone")
    check(value("c:be_b|[::1]:6000") is None, "removed service endpoint gone")
    check(value("writer_generation") == a.encode(), "UUID retained")
    reject(request(1, 2, entries=[("be_a|10.0.0.1:5000", 100)]), 0, "late update")
    reject(request(0, 1), 0, "same UUID delayed startup")
    check(send(request(0, 1, b, entries=[("be_a|10.0.0.1:5000", 0)])) == 1,
          "new process replaces UUID and current snapshot")
    reject(request(1, 4), -1, "old UUID update after restart")
    check(send(request(0, 5, a)) == 1,
          "R2 accepted limitation: delayed different-UUID START can replace owner")
    check(send(request(0, 1, b)) == 1, "restore intended new writer in isolated test")
    check(send(request(1, 9007199254740993, b)) == 1, "sequence above 2^53 exact")
    reject(request(1, 9007199254740992, b), 0, "above 2^53 older sequence")
    check(send(request(1, 18446744073709551614, b,
                       entries=[("be_a|10.0.0.1:5000", 18446744073709551615)])) == 1,
          "uint64 counts/sequence exact")
    check(value("c:be_a|10.0.0.1:5000") == b"18446744073709551615", "uint64 count preserved")
    check(send(request(2, 18446744073709551615, b)) == 2, "conditional delete")
    check(cmd("EXISTS", snapshot) == 0, "snapshot removed")
    check(cmd("HGET", owner, "snapshot_sequence") == b"18446744073709551615",
          "cleanup retains last sequence")
    check(cmd("PTTL", owner) == -1, "cleanup metadata no TTL")
    reject(request(1, 18446744073709551614, b), 0, "late write after cleanup")
    reject(request(2, 18446744073709551615, b), 0, "duplicate cleanup")
    check(send(request(0, 1, a, entries=[("be_a|10.0.0.1:5000", 3)])) == 1, "new startup after cleanup")
    time.sleep(3.15)
    check(cmd("EXISTS", snapshot) == 0, "real 3s TTL expiry")
    check(cmd("EXISTS", owner) == 1, "owner survives snapshot expiry")
    reject(request(1, 1), 0, "expired snapshot not resurrected by duplicate")
    check(send(request(1, 2)) == 1, "new sequence after expiry")
    check(cmd("HLEN", snapshot) == 2, "empty snapshot has metadata only")
    # Simulate memory store data loss using ONLY these two disposable test keys.
    check(cmd("DEL", owner, snapshot) == 2, "simulate store loss")
    check(send(request(2, 3)) == 3, "cleanup does not register missing owner")
    check(cmd("EXISTS", owner) == 0, "missing-owner cleanup remains absent")
    check(send(request(1, 4)) == 1, "same process recovers after store data loss")
    check(value("writer_generation") == a.encode(), "recovery retains UUID")
    base = read(io.BytesIO(request(1, 5)))
    for idx, bad in [(5, b"other"), (6, b"bad-uuid"), (7, b"0"), (7, b"01"),
                     (7, b"18446744073709551616"), (7, b"-1"), (7, b"1.5"),
                     (8, b"0"), (8, b"2147483648")]:
        altered = base.copy()
        altered[idx] = bad
        reject(encode(altered), -2, "malformed argument " + str((idx, bad)))
    for fields in [[b"writer_generation", b"10"], [b"c:", b"10"],
                   [b"c:x", b"01"], [b"c:x", b"-1"],
                   [b"c:x", b"18446744073709551616"],
                   [b"c:x", b"1", b"c:x", b"2"], [b"c:x"]]:
        reject(encode(base + fields), -2, "bad fields " + str(fields))
    altered = base.copy()
    altered[4] = owner
    reject(encode(altered), -2, "same key arguments")
    # Independent instance must not replace this instance's owner/snapshot.
    before = state()
    check(send(request(0, 1, b, instance="ha-1")) == 1, "second instance")
    check(state() == before, "instance isolation")
    # Wrong types and malformed/expiring owner records are rejected pre-write.
    check(cmd("DEL", snapshot) == 1, "remove test snapshot")
    check(cmd("SET", snapshot, "wrong") == b"OK", "inject wrong snapshot type")
    check(send(request(1, 6)) == -3, "reject wrong snapshot type")
    check(cmd("GET", snapshot) == b"wrong", "wrong type not overwritten")
    cmd("DEL", snapshot)
    cmd("DEL", owner)
    cmd("SET", owner, "wrong-owner")
    check(send(request(0, 6)) == -3, "reject wrong owner type even on startup")
    check(cmd("GET", owner) == b"wrong-owner", "wrong owner not overwritten")
    cmd("DEL", owner)
    cmd("HSET", owner, "snapshot_sequence", "4")
    reject(request(1, 6), -3, "missing stored UUID")
    cmd("HSET", owner, "writer_generation", a)
    cmd("HSET", owner, "snapshot_sequence", "garbage")
    reject(request(1, 6), -3, "malformed stored sequence")
    cmd("HSET", owner, "snapshot_sequence", "4")
    cmd("PEXPIRE", owner, 30000)
    reject(request(1, 6), -3, "owner must not expire")
    cmd("PERSIST", owner)
    check(send(request(1, 6)) == 1, "restore valid test state")
    # Deliberate post-write command error: ACL denies PEXPIRE inside EVAL.
    # This test-only user does NOT add auth support to HAProxy.
    check(cmd("ACL", "SETUSER", "glb_fault", "on", ">test-pass", "~*",
              "+eval", "+type", "+hget", "+exists", "+hlen", "+pttl",
              "+hset", "+del") == b"OK", "create fault injection user")
    check(cmd("AUTH", "glb_fault", "test-pass") == b"OK", "test-only restricted client")
    failed = send(request(1, 7, entries=[("be_a|10.0.0.1:5000", 77)]))
    check(isinstance(failed, RespError), "write error is not success")
    check(cmd("AUTH", "default", "") == b"OK", "restore disposable test client")
    check(cmd("EXISTS", snapshot) == 0, "failed replacement invalidated, no partial hash")
    check(cmd("HGET", owner, "snapshot_sequence") == b"7", "failed write may consume sequence")
    check(send(request(1, 8)) == 1, "fresh operation recovers after failed write")
    # Enough pairs to exercise iterative HSET (no Lua unpack/stack dependency).
    many = [(f"be_many|10.1.{i // 250}.{i % 250 + 1}:5000", i) for i in range(5000)]
    check(send(request(1, 9, entries=many)) == 1, "5000 endpoint batch")
    check(cmd("HLEN", snapshot) == 5002, "entire batch stored")
    check(send(request(1, 10, entries=[many[0]])) == 1, "shrink batch")
    check(cmd("HLEN", snapshot) == 3, "old large batch fields removed")
    time.sleep(0.2)
    ttl_before = cmd("PTTL", snapshot)
    check(send(request(1, 11)) == 1, "renew snapshot")
    check(cmd("PTTL", snapshot) > ttl_before, "successful write refreshes TTL")
    print(f"PASS: {image}: {checks} storage checks (isolated container, port {port})")
finally:
    if stream:
        stream.close()
    if sock:
        sock.close()
    if container:
        info = json.loads(docker("inspect", container))[0]
        if info["Config"]["Labels"].get("global-lb-unit-test") != token:
            raise RuntimeError("refusing to stop a container not owned by this test")
        docker("stop", "--time", "1", container)

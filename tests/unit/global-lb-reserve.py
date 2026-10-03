#!/usr/bin/env python3
"""UD-007/009/011 v2-r1-20261003. C-generated Lua against a disposable store.
Never reads/writes the user's store. Does not pull images or use FLUSHDB.
"""
import concurrent.futures
import io
import json
from pathlib import Path
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
        n = int(body)
        if n == -1:
            return None
        data = stream.read(n)
        assert len(data) == n and stream.read(2) == b"\r\n"
        return data
    if kind == b"*":
        return [read(stream) for _ in range(int(body))]
    raise RuntimeError(f"unsupported RESP {line!r}")


def encode(args):
    parts = [x if isinstance(x, bytes) else str(x).encode() for x in args]
    return b"*%d\r\n" % len(parts) + b"".join(b"$%d\r\n" % len(x) + x + b"\r\n" for x in parts)


def docker(*args):
    return subprocess.check_output(["docker", *args], text=True).strip()


builder, image = sys.argv[1:]
token = uuid.uuid4().hex
prefix = "test[*]:v2:" + token
checks = 0
container = sock = stream = None
generations = {f"ha-{i}": str(uuid.uuid4()) for i in range(5)}
endpoints = ["be|10.0.0.1:5000", "be|10.0.0.2:5000", "be|[::1]:5000"]


def check(value, label):
    global checks
    if not value:
        raise AssertionError(label)
    checks += 1


def request(op=0, instance="ha-0", gen=None, rev=1, rid=0, water=0,
            timeout=3000, seed=1, limits=(64, 4096, 100000),
            service="", candidates=(), entries=(), pool=None):
    args = [builder, "--request", str(op), pool or prefix, instance,
            gen or generations[instance], str(rev), str(rid), str(water),
            str(timeout), str(seed), *map(str, limits), service, str(len(candidates)),
            *candidates, str(len(entries))]
    for request_id, endpoint in entries:
        args.extend([str(request_id), endpoint])
    return subprocess.check_output(args)


try:
    server = "valkey-server" if image.split("/")[-1].startswith("valkey:") else "redis-server"
    container = docker("run", "--pull=never", "--rm", "-d", "--label", "global-lb-v2-test=" + token,
                       "-p", "127.0.0.1::6379", image, server, "--save", "", "--appendonly", "no",
                       "--maxmemory", "64mb", "--maxmemory-policy", "noeviction")
    info = json.loads(docker("inspect", container))[0]
    port = int(info["NetworkSettings"]["Ports"]["6379/tcp"][0]["HostPort"])
    for _ in range(100):
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=3)
            stream = sock.makefile("rb")
            sock.sendall(encode(["PING"]))
            if read(stream) == b"PONG":
                break
        except OSError:
            if stream:
                stream.close()
            if sock:
                sock.close()
            sock = stream = None
            time.sleep(0.05)
    if not sock:
        raise RuntimeError("test store did not start")

    def send(wire):
        sock.sendall(wire)
        return read(stream)

    def cmd(*args):
        return send(encode(args))

    initial = request()
    arguments = read(io.BytesIO(initial))
    owners, live, counts, requests = arguments[3:7]
    script = arguments[1]
    check(script == Path("dev/global-lb/reserve.lua").read_bytes(), "embedded Lua matches source")
    check(all(x.startswith(b"glb:v2:") for x in arguments[3:7]), "v2 namespace")
    check(send(initial) == [1, b"", 0], "startup")
    check(cmd("HGET", owners, b"ha-0".hex()) == generations["ha-0"].encode(), "owner UUID")

    def state():
        return tuple(cmd("HGETALL", key) for key in (owners, live, counts, requests))

    def reject(wire, status, label):
        before = state()
        check(send(wire)[0] == status, label + " status")
        check(state() == before, label + " no mutation")

    def total(endpoint):
        rows = cmd("HGETALL", counts)
        return sum(int(rows[i+1]) for i in range(0, len(rows), 2)
                   if rows[i].endswith(b"|" + endpoint.encode()))

    first = request(2, rid=1, service="be", candidates=endpoints)
    result = send(first)
    chosen = result[1]
    check(result[0] == 1 and result[2] == 1 and chosen in [e.encode() for e in endpoints], "reserve chooses and increments")
    before = state()
    check(send(first)[0:2] == [2, chosen], "duplicate reserve same endpoint")
    check(state() == before, "duplicate reserve no increment")
    release = request(3, rid=1)
    check(send(release)[0:2] == [3, chosen], "release original reservation")
    check(send(release)[0] == 5, "duplicate release absent")
    check(total(chosen.decode()) == 0, "release never negative")
    reject(first, 0, "released request cannot reserve again")
    check(send(request(4, rid=2))[0] == 4, "cancel before reserve")
    reject(request(2, rid=2, service="be", candidates=endpoints), 0, "cancel blocks late reserve")
    check(send(request(2, rid=3, service="be", candidates=endpoints))[0] == 1, "reserve after cancel")
    check(send(request(4, rid=3))[0] == 4, "cancel known endpoint")
    check(send(request(4, rid=3))[0] == 4, "duplicate cancel")
    check(cmd("HLEN", requests) == 0, "no completed request tombstones accumulate")

    for op in (2, 3, 4, 5, 6):
        kwargs = {"rid": 4} if op in (2, 3, 4) else {}
        if op == 2:
            kwargs.update(service="be", candidates=endpoints)
        reject(request(op, gen=str(uuid.uuid4()), **kwargs), -1, "other writer op " + str(op))
    reject(request(5, rev=2), -4, "wrong restore revision")

    # Restore derives the native reservation count from active assignments.
    restored = request(1, rev=2, water=10, entries=[(7, endpoints[0]), (8, endpoints[0]), (10, endpoints[1])])
    check(send(restored)[0] == 1, "restore absolute state")
    check(total(endpoints[0]) == 2 and total(endpoints[1]) == 1, "restore count and ledger agree")
    reject(request(3, rid=7), -4, "old release fenced after restore")
    reject(request(2, rid=11, service="be", candidates=endpoints), -4, "old reserve fenced after restore")
    check(send(request(2, rev=2, rid=11, service="be", candidates=endpoints))[0] == 1, "new revision reserve")
    before = state()
    check(send(restored)[0] == 2 and state() == before, "duplicate restore never overwrites new deltas")
    reject(request(1, rev=3, water=1), -4, "restore high water cannot go backwards")
    check(send(request(3, rev=2, rid=7))[0] == 3 and total(endpoints[0]) == 1, "release restored reservation")

    pool = prefix + ":minimum"
    check(send(request(pool=pool, water=14, entries=[
        *[(i, endpoints[0]) for i in range(1, 6)],
        *[(i, endpoints[1]) for i in range(6, 8)],
        *[(i, endpoints[2]) for i in range(8, 15)]]))[0] == 1, "known load setup")
    check(send(request(2, pool=pool, rid=15, service="be", candidates=endpoints)) ==
          [1, endpoints[1].encode(), 3], "global minimum chosen")
    check(send(request(2, pool=pool, rid=16, service="be", candidates=[endpoints[0]])) ==
          [1, endpoints[0].encode(), 6], "only eligible endpoint chosen")
    check(send(request(2, pool=pool, rid=16, service="be", candidates=[endpoints[2]])) ==
          [2, endpoints[0].encode(), 6], "duplicate never reassigns original reservation")
    other = "other|10.0.0.9:6000"
    check(send(request(2, pool=pool, rid=17, service="other", candidates=[other])) ==
          [1, other.encode(), 1], "same instance different service isolated")

    pool = prefix + ":memory-loss"
    check(send(request(pool=pool, water=1, entries=[(1, endpoints[0])]))[0] == 1, "memory loss setup")
    args = read(io.BytesIO(request(pool=pool)))
    cmd("DEL", *args[3:7])  # Only owned keys in this disposable test container.
    check(send(request(2, pool=pool, rid=2, service="be", candidates=endpoints))[0] == 5,
          "missing owner does not silently admit")
    check(send(request(1, pool=pool, rev=2, water=1, entries=[(1, endpoints[0])]))[0] == 1,
          "same UUID current local state restored after store loss")
    check(cmd("HGET", args[3], b"ha-0".hex()) == generations["ha-0"].encode(), "restore retains UUID")

    # Replacement removes only this instance; old UUID cannot delete the new one.
    check(send(request(0, instance="ha-1", water=1, entries=[(1, endpoints[0])]))[0] == 1, "second instance")
    generations["ha-0"], old = str(uuid.uuid4()), generations["ha-0"]
    check(send(request())[0] == 1, "restart replaces own state")
    check(total(endpoints[0]) == 1, "restart leaves other instance count")
    reject(request(6, gen=old, rev=2), -1, "old writer stop cannot delete replacement")
    check(send(request(6, rev=999))[0] == 1, "terminal stop with uncertain local revision")
    reject(request(5), -7, "terminal writer cannot heartbeat")
    reject(request(1, rev=2), -7, "terminal writer cannot restore/restart")
    check(send(request(6))[0] == 1, "duplicate stop")

    pool = prefix + ":r2"
    older, newer = str(uuid.uuid4()), str(uuid.uuid4())
    check(send(request(pool=pool, gen=older))[0] == 1, "R2 old startup")
    check(send(request(pool=pool, gen=newer))[0] == 1, "R2 new startup")
    check(send(request(pool=pool, gen=older))[0] == 1, "R2 delayed first START can replace owner: accepted limitation")

    pool = prefix + ":corrupt-count"
    check(send(request(pool=pool, water=1, entries=[(1, endpoints[0])]))[0] == 1, "corrupt count setup")
    args = read(io.BytesIO(request(pool=pool)))
    field = b"ha-0".hex() + "|" + endpoints[0]
    cmd("HSET", args[5], field, "-1")
    check(send(request(2, pool=pool, rid=2, service="be", candidates=[endpoints[0]]))[0] == -3, "negative stored count rejected")
    cmd("HSET", args[5], field, "2147483647")
    check(send(request(2, pool=pool, rid=2, service="be", candidates=[endpoints[0]]))[0] == -5, "per-instance count overflow rejected")

    # Stale HB excludes counts; HB alone is not sufficient to reactivate them.
    pool = prefix + ":stale"
    init = read(io.BytesIO(request(pool=pool)))
    stale_live = init[4]
    check(send(request(pool=pool, water=100, entries=[(i, endpoints[0]) for i in range(1, 101)]))[0] == 1, "stale test setup")
    check(send(request(instance="ha-1", pool=pool))[0] == 1, "live peer setup")
    now = cmd("TIME")
    expired = int(now[0])*1000 + int(now[1])//1000 - 3001
    cmd("HSET", stale_live, b"ha-0".hex(), f"1|{expired}|100|A")
    check(send(request(2, instance="ha-1", pool=pool, rid=1, service="be", candidates=[endpoints[0]]))[2] == 1, "stale count excluded")
    check(send(request(5, pool=pool))[0] == -6, "stale HB requires restore")
    check(send(request(1, pool=pool, rev=2, water=100, entries=[(1, endpoints[0])]))[0] == 1, "stale instance recovery")

    # Exact uint64 request/revision handling above Lua's 2^53 range.
    pool = prefix + ":uint64"
    check(send(request(pool=pool, rev=2**64-1))[0] == 1, "uint64 revision")
    high = request(2, pool=pool, rev=2**64-1, rid=2**64-1, service="be", candidates=endpoints)
    check(send(high)[0] == 1, "uint64 request ID")
    check(send(request(4, pool=pool, rev=2**64-1, rid=2**64-1))[0] == 4, "uint64 cancel")
    check(send(high)[0] == 0, "uint64 high-water replay fence")

    # Server-side validators are tested by mutating a valid C EVAL envelope.
    for label, index, value in [("unknown operation", 7, b"bad"), ("bad UUID", 9, b"bad"),
                                 ("leading zero revision", 10, b"01"), ("zero timeout", 13, b"0")]:
        args = read(io.BytesIO(request()))
        args[index] = value
        reject(encode(args), -2, label)
    args = read(io.BytesIO(request(2, rid=4, service="be", candidates=endpoints)))
    args[20] = b"other|10.0.0.1:5000"
    reject(encode(args), -2, "cross service candidate")
    args = read(io.BytesIO(request(2, rid=4, service="be", candidates=endpoints)))
    args[21] = args[20]
    reject(encode(args), -2, "duplicate endpoint")
    args = read(io.BytesIO(request(1, rev=3, water=20, entries=[(10, endpoints[0]), (20, endpoints[1])])))
    args[-2] = args[-4]
    reject(encode(args), -2, "duplicate snapshot request")

    pool = prefix + ":limit"
    check(send(request(pool=pool, limits=(1, 1, 1)))[0] == 1, "limited startup")
    check(send(request(instance="ha-1", pool=pool, limits=(1, 1, 1)))[0] == -5, "instance limit")
    check(send(request(2, pool=pool, limits=(1, 1, 1), rid=1, service="be", candidates=[endpoints[0]]))[0] == 1, "limited reserve")
    check(send(request(2, pool=pool, limits=(1, 1, 1), rid=2, service="be", candidates=[endpoints[0]]))[0] == -5, "active request limit")
    check(send(request(3, pool=pool, limits=(1, 1, 1), rid=1))[0] == 3, "limited release")

    pool = prefix + ":types"
    args = read(io.BytesIO(request(pool=pool)))
    cmd("SET", args[5], "not-a-hash")
    check(send(encode(args))[0] == -3, "wrong key type rejected")

    # Lua write error: no rollback claim, require a fresh revision restore.
    pool = prefix + ":acl"
    check(send(request(pool=pool, water=1, entries=[(1, endpoints[0])]))[0] == 1, "write error setup")
    cmd("ACL", "SETUSER", "v2-test", "on", ">test-only", "~*", "+@all", "-hdel")
    cmd("AUTH", "v2-test", "test-only")
    result = send(request(6, pool=pool))
    check(isinstance(result, RespError), "runtime write error is error reply")
    cmd("AUTH", "default", "")
    check(send(request(2, pool=pool, rid=2, service="be", candidates=endpoints))[0] == -7, "write failure invalidates contribution")
    check(send(request(1, pool=pool, rev=2, water=1, entries=[(1, endpoints[0])]))[0] == 1, "fresh restore after write failure")

    # 100 admissions over five independent connections, same eligible set.
    pool = prefix + ":burst"
    for i in range(5):
        check(send(request(instance=f"ha-{i}", pool=pool))[0] == 1, "burst instance startup")
    def burst(i):
        instance = f"ha-{i}"
        with socket.create_connection(("127.0.0.1", port), timeout=5) as peer:
            with peer.makefile("rb") as inp:
                for rid in range(1, 21):
                    peer.sendall(request(2, instance=instance, pool=pool, rid=rid,
                                         seed=1+i*20+rid, service="be", candidates=endpoints))
                    result = read(inp)
                    assert result[0] == 1 and result[1] in [e.encode() for e in endpoints]
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        list(executor.map(burst, range(5)))
    args = read(io.BytesIO(request(pool=pool)))
    rows = cmd("HGETALL", args[5])
    dist = [sum(int(rows[i+1]) for i in range(0, len(rows), 2)
                if rows[i].endswith(b"|"+e.encode())) for e in endpoints]
    check(sum(dist) == 100 and max(dist)-min(dist) <= 1, "100 atomic admissions balanced")
    check(cmd("HLEN", args[6]) == 100, "100 active mappings")
    # Pool isolation: v1-looking and other pool keys are left untouched.
    cmd("SET", "glb:v1:sentinel:" + token, "keep")
    check(send(request(pool=prefix+":other"))[0] == 1, "other group startup")
    check(cmd("GET", "glb:v1:sentinel:" + token) == b"keep", "v1 key preserved")
    print(f"PASS: {checks} Redis/Valkey v2 protocol checks ({image}); atomic burst {dist}")
finally:
    if stream:
        stream.close()
    if sock:
        sock.close()
    if container:
        subprocess.run(["docker", "rm", "-f", container], check=True, stdout=subprocess.DEVNULL)

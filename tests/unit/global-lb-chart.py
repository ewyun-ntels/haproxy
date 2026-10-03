#!/usr/bin/env python3
"""UD-001/002/003/004/015/016 v2-packaging-20261004: offline chart regressions.

Requires helm, PyYAML; optional --binary/--image parse the generated cfg.
Never uses kubectl, the active cluster, or a running state store. Container
config checks use ephemeral read-only nonroot containers; no port publication.
--smoke additionally creates only task-owned stores/network and publishes health
on an ephemeral loopback port; it does not modify a shared store.
"""
import argparse
import copy
import json
import os
from pathlib import Path
import subprocess
import socket
import tempfile
import time
import urllib.request
import uuid

import yaml


ROOT = Path(__file__).resolve().parents[2]
CHART = ROOT / "charts/haproxy-global-lb"
CHECKS = 0


def check(condition, message):
    global CHECKS
    assert condition, message
    CHECKS += 1


def render(values=None, success=True, release="haproxy", namespace="ipmdn"):
    result = subprocess.run(
        ["helm", "template", release, str(CHART), "--namespace", namespace,
         "-f", "-"], input=yaml.safe_dump(values or {}), text=True,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check((result.returncode == 0) == success, result.stderr)
    if not success:
        return result.stderr
    return list(yaml.safe_load_all(result.stdout))


def config(objects):
    return next(o["data"]["haproxy.cfg"] for o in objects if o["kind"] == "ConfigMap")


def parse_cfg(cfg, args, success=True):
    env = dict(os.environ, GLOBAL_LB_INSTANCE_ID="ipmdn-prod/haproxy-0")
    if args.binary:
        command = [str(Path(args.binary).resolve()), "-c", "-f", "/dev/stdin"]
    elif args.image:
        command = ["docker", "run", "--rm", "--pull=never", "-i", "--read-only",
                   "--user", "1000:1000", "--tmpfs", "/run/haproxy:uid=1000,gid=1000,mode=0770",
                   "--tmpfs", "/tmp", "-e", "GLOBAL_LB_INSTANCE_ID=ipmdn-prod/haproxy-0",
                   "--entrypoint", "/usr/local/sbin/haproxy", args.image,
                   "-c", "-f", "/dev/stdin"]
    else:
        return
    result = subprocess.run(command, input=cfg, text=True, env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    check((result.returncode == 0) == success, result.stdout + result.stderr)


def smoke_image(image):
    """Use ONLY task-owned stores/network; no existing store or cluster access."""
    def docker(*argv):
        return subprocess.check_output(["docker", *argv], text=True).strip()

    def wait(predicate, seconds=20):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            try:
                result = predicate()
                if result:
                    return result
            except (OSError, ValueError, subprocess.CalledProcessError):
                pass
            time.sleep(.1)
        raise AssertionError("container smoke timeout")

    for provider in ("valkey", "redis"):
        objects = render({"stateStore": {"provider": provider}})
        store = next(o for o in objects if o["kind"] == "Deployment")
        server = store["spec"]["template"]["spec"]["containers"][0]
        token = "glb-chart-" + uuid.uuid4().hex
        network = None
        containers = []
        try:
            network = docker("network", "create", "--label", "global-lb-chart=" + token, token)
            # Images must already exist locally; never fetch an unapproved image.
            alias = store["metadata"]["name"] + ".ipmdn.svc.cluster.local"
            store_id = docker("run", "--pull=never", "-d", "--label", "global-lb-chart=" + token,
                              "--network", token, "--network-alias", alias,
                              "--read-only", "--user", "1000:1000", "--cap-drop", "ALL",
                              "--tmpfs", "/data:uid=1000,gid=1000", "--tmpfs", "/tmp",
                              "--entrypoint", server["command"][0], server["image"], *server["args"])
            containers.append(store_id)
            wait(lambda: docker("exec", store_id, *server["readinessProbe"]["exec"]["command"]) == "PONG")
            with tempfile.TemporaryDirectory(prefix=token) as temp:
                runtime = Path(temp) / "runtime"
                runtime.mkdir(mode=0o770)
                cfg_path = Path(temp) / "haproxy.cfg"
                cfg_path.write_text(config(objects))
                # WSL user's UID is normally1000. Make writable for the exact
                # chart UID even when this regression is run by another user.
                os.chmod(temp, 0o755)
                os.chmod(runtime, 0o777)
                os.chmod(cfg_path, 0o644)
                ha = docker("run", "--pull=never", "-d", "--label", "global-lb-chart=" + token,
                            "--network", token, "--read-only", "--user", "1000:1000",
                            "--cap-drop", "ALL", "--tmpfs", "/tmp", "-e",
                            "GLOBAL_LB_INSTANCE_ID=ipmdn-prod/haproxy-haproxy-global-lb-0",
                            "-v", str(cfg_path) + ":/usr/local/etc/haproxy/haproxy.cfg:ro",
                            "-v", str(runtime) + ":/run/haproxy", "-p", "127.0.0.1::8404",
                            "--entrypoint", "/usr/local/sbin/haproxy", image,
                            "-db", "-f", "/usr/local/etc/haproxy/haproxy.cfg")
                containers.append(ha)

                def status():
                    with socket.socket(socket.AF_UNIX) as cli:
                        cli.settimeout(2)
                        cli.connect(str(runtime / "admin.sock"))
                        cli.sendall(b"show global-lb status\n")
                        output = b""
                        while True:
                            part = cli.recv(8192)
                            if not part:
                                break
                            output += part
                    return dict(line.split(b": ", 1) for line in output.splitlines() if b": " in line)

                def is_state(name):
                    current = status()
                    return current if current.get(b"state") == name else None

                first = wait(lambda: is_state(b"ACTIVE"))
                # UD-001/007/010/016 v2-timeouts-20261004: configured reserve
                # override is in the running worker, not a C default change.
                check(first[b"reserve_timeout_ms"] == b"1000", "configured 1s admission deadline")
                check(first[b"usable"] == b"1" and first[b"owner"] == b"confirmed", "container startup owner")
                check(first[b"instance-id"] == b"ipmdn-prod/haproxy-haproxy-global-lb-0", "actual env expansion")
                port = json.loads(docker("inspect", ha))[0]["NetworkSettings"]["Ports"]["8404/tcp"][0]["HostPort"]
                def health():
                    with urllib.request.urlopen("http://127.0.0.1:" + port + "/health", timeout=2) as response:
                        return response.status == 200 and response.read() == b"OK"
                check(health(), "HA health ACTIVE")
                docker("kill", store_id)
                wait(lambda: is_state(b"FALLBACK"))
                check(health(), "HA health stays UP when store dies")
                docker("start", store_id)
                final = wait(lambda: is_state(b"ACTIVE"))
                check(final[b"writer_generation"] == first[b"writer_generation"], "same UUID after memory-store restart")
                check(int(final[b"restores"]) >= 1, "confirmed restore")
                docker("stop", "--time", "10", ha)
                info = json.loads(docker("inspect", ha))[0]
                check(info["State"]["ExitCode"] == 0, "bounded SIGUSR1 terminal shutdown")
                print("PASS: %s container nonroot/read-only/DNS/startup/HB/fallback/health/restore/stop" % provider)
                # Remove HA while mounted directories still exist.
                docker("rm", ha)
                containers.remove(ha)
        finally:
            for container in reversed(containers):
                subprocess.run(["docker", "rm", "-f", container], stdout=subprocess.DEVNULL, check=True)
            if network:
                docker("network", "rm", network)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--binary")
    group.add_argument("--image")
    parser.add_argument("--smoke", action="store_true", help="with --image: use two task-owned Docker stores for runtime smoke")
    args = parser.parse_args()
    if args.smoke and not args.image:
        parser.error("--smoke requires --image")
    configs = []
    for provider in ("valkey", "redis"):
        objects = render({"stateStore": {"provider": provider}})
        check(len(objects) == 7, "expected 7 objects in bundled mode")
        ha = next(o for o in objects if o["kind"] == "StatefulSet")
        store = next(o for o in objects if o["kind"] == "Deployment")
        policies = [o for o in objects if o["kind"] == "NetworkPolicy"]
        services = [o for o in objects if o["kind"] == "Service"]
        check(store["spec"]["replicas"] == 1, "one standalone store")
        check(store["spec"]["strategy"]["type"] == "Recreate", "no multi-store rolling upgrade")
        sc = store["spec"]["template"]["spec"]["containers"][0]
        check(sc["command"] == [provider + "-server"], "provider command")
        check(sc["readinessProbe"]["exec"]["command"][0] == provider + "-cli", "provider probe")
        check(sc["args"][sc["args"].index("--save") + 1] == "", "no RDB")
        check(sc["args"][sc["args"].index("--appendonly") + 1] == "no", "no AOF")
        store_service = next(s for s in services if s["metadata"]["name"] == store["metadata"]["name"])
        check(store_service["spec"]["type"] == "ClusterIP", "store private")
        check(store_service["spec"]["selector"] == store["spec"]["selector"]["matchLabels"], "store routing")
        check(policies[0]["spec"]["podSelector"]["matchLabels"] == store_service["spec"]["selector"], "policy target")
        hc = ha["spec"]["template"]["spec"]["containers"][0]
        check(hc["command"] == ["/usr/local/sbin/haproxy"] and "-W" not in hc["args"], "worker PID1, no inherited reloader")
        check(hc["env"][0]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.name", "stable Pod name")
        check(hc["env"][1]["value"] == "ipmdn-prod/$(POD_NAME)", "per-Pod instance-id")
        check(ha["spec"]["updateStrategy"]["type"] == "OnDelete", "no automatic TCP disruption")
        traffic = next(s for s in services if s["spec"].get("type") == "LoadBalancer")
        check(traffic["spec"]["externalTrafficPolicy"] == "Local", "Local traffic policy")
        check(traffic["spec"]["selector"] == ha["spec"]["selector"]["matchLabels"], "HA routing")
        allowed = policies[0]["spec"]["ingress"][0]["from"][0]["podSelector"]["matchLabels"]
        check(allowed == traffic["spec"]["selector"], "same group only")
        check([p["port"] for p in traffic["spec"]["ports"]] == [5000], "probe/admin/store not externally exposed")
        cfg = config(objects)
        check(store_service["metadata"]["name"] + ".ipmdn.svc.cluster.local:6379" in cfg, "automatic store DNS")
        check('global-lb instance-id "$GLOBAL_LB_INSTANCE_ID"' in cfg, "cfg env identity")
        check("global-lb heartbeat-interval 300ms" in cfg and "global-lb instance-timeout 3s" in cfg, "approved timers")
        check("global-lb timeout reserve 1s" in cfg and "global-lb timeout command 1s" in cfg, "approved long-lived TCP timeout overrides")
        check("balance global-leastconn" in cfg and "global-lb fallback leastconn" in cfg, "v2 selection/fallback")
        check("check-send-proxy send-proxy-v2" in cfg and "resolvers default" in cfg, "PPv2 async DNS")
        check("sync-interval" not in cfg and "stale-after" not in cfg, "no v1 count sync")
        configs.append(cfg)
    for address in ("127.0.0.1:6379", "redis.private.example:6379", "[::1]:6379"):
        objects = render({"stateStore": {"enabled": False, "externalAddress": address}})
        check(len(objects) == 4 and not any(o["kind"] in ("Deployment", "NetworkPolicy") for o in objects), "external mode owns no store")
        check("global-lb state-store " + address in config(objects), "external address wiring")
        configs.append(config(objects))
    objects = render({"service": {"type": "ClusterIP"}, "stateStore": {"networkPolicy": {"enabled": False}},
                      "clusterDomain": "example.local", "haproxy": {"updateStrategy": "RollingUpdate"}})
    check(not any(o["kind"] == "NetworkPolicy" for o in objects), "policy opt-out")
    check(all("externalTrafficPolicy" not in o["spec"] for o in objects if o["kind"] == "Service"), "ClusterIP spec")
    check(".svc.example.local:6379" in config(objects), "custom domain")
    objects = render(release="h" * 53)
    check(all(len(o["metadata"]["name"]) <= 63 for o in objects), "long release names safe")
    defaults = yaml.safe_load((CHART / "values.yaml").read_text())
    backend = copy.deepcopy(defaults["backends"][0])
    backend.update(name="service_b", portName="second", port=5001, proxyProtocolV2=False)
    objects = render({"backends": defaults["backends"] + [backend]})
    cfg = config(objects)
    traffic = next(o for o in objects if o["kind"] == "Service" and o["spec"].get("type") == "LoadBalancer")
    check("backend service_b" in cfg and len(traffic["spec"]["ports"]) == 2, "multiple services")
    check("send-proxy-v2" not in cfg.split("backend service_b", 1)[1], "plain TCP option")
    configs.append(cfg)
    invalid = [
        {"stateStore": {"provider": "both"}}, {"stateStore": {"enabled": False}},
        {"stateStore": {"externalAddress": "127.0.0.1:6379"}},
        {"stateStore": {"enabled": "false"}},
        {"stateStore": {"enabled": False, "externalAddress": "redis://user:secret@host:6379"}},
        {"clusterId": 'x\n    daemon'}, {"globalLb": {"reserveTimeout": "bad"}},
        {"replicaCount": 17}, {"backends": []},
        {"backends": defaults["backends"] * 2}, {"stateStore": {"enabld": False}},
        {"backends": [dict(backend, port=8404)]}, {"backends": [dict(backend, portName="health")]},
        {"backends": [dict(backend, port=80)]},
        {"backends": [dict(defaults["backends"][0], slots=4096), backend]},
    ]
    for values in invalid:
        render(values, success=False)
    for cfg in configs:
        parse_cfg(cfg, args)
    parse_cfg(config(render({"globalLb": {"instanceTimeout": "100ms"}})), args, success=False)
    if args.smoke:
        smoke_image(args.image)
    print("PASS: %d chart/config checks; no Kubernetes deployment or shared-store mutation" % CHECKS)


if __name__ == "__main__":
    main()

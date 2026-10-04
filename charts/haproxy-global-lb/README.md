# HAProxy Global LeastConn v2 deployment

UD-001/002/003/004/015/016, revision `v2-packaging-20261004`.
Compile fences: `USE_GLOBAL_LB` / `USE_GLOBAL_LEASTCONN`. No core C change.

One Helm release owns one HAProxy StatefulSet group (default 3 Pods), its
ConfigMap/headless/traffic Services, and optionally one standalone **Valkey OR
Redis** Deployment and private ClusterIP Service. No external chart dependency.
MetalLB/BGP and the application/headless backend Services must already exist.

## Build and publish the custom image

Run in the repository with Docker. The Alpine base is digest-pinned; Dockerfile
preserves the existing SSL/Lua/QUIC/PCRE2/splice feature set and enables Global
LeastConn by default. A stock HAProxy image cannot parse this chart's cfg.

```sh
make container CONTAINER_IMAGE=registry.example.com/team/haproxy-global-lb CONTAINER_TAG=3.4.4-v2
# Explicit publication, only after login to your registry:
make container-push CONTAINER_IMAGE=registry.example.com/team/haproxy-global-lb CONTAINER_TAG=3.4.4-v2
docker run --rm --entrypoint haproxy registry.example.com/team/haproxy-global-lb:3.4.4-v2 -vv
```

Check `+GLOBAL_LB +GLOBAL_LEASTCONN +LINUX_SPLICE`. For a feature-OFF image:
`make container CONTAINER_USE_GLOBAL_LEASTCONN=0 CONTAINER_TAG=3.4.4-no-global-lb`.
That image is for compile-fence checks, **not this chart**. The container build
checks flags and, when enabled, parses `examples/global-lb-v2.cfg`.

## Select the state store

Bundled Valkey (default):

```yaml
stateStore:
  enabled: true
  provider: valkey
```

Bundled Redis instead (only one Deployment is rendered):

```yaml
stateStore:
  enabled: true
  provider: redis
```

External store, no store Deployment/Service/NetworkPolicy rendered:

```yaml
stateStore:
  enabled: false
  externalAddress: shared-store.ipmdn.svc.cluster.local:6379
```

An external address is required when disabled, forbidden when enabled. Use one
store per HAProxy group, not a shared multi-group server. `provider` selects the
bundled image/binary, **not a protocol mode**; both use the same RESP2/Lua client.
Inside a Pod, `127.0.0.1:6379` means that Pod, NOT your WSL development store.

The bundled server is one replica, memory-only (`save ""`, AOF off), no AUTH,
no TLS, no eviction, no PVC. Recreate strategy prevents two independent stores
behind one Service during upgrade. Its restart loses state; live HAProxy workers
fall back, then atomically restore their own current reservations with the same
UUID. Owner/fencing exceptions in `doc/global-lb-reservation.txt` still apply.
This is a single point of failure, deliberately not Cluster/Sentinel/replicated.
Memory/CPU resources default to unset: measure and set them for production.

The store is never exposed through NodePort/LoadBalancer. The default ingress
NetworkPolicy allows same-release HAProxy Pods in the same namespace only.
It requires a supporting CNI and is additive to other policies; broad policies
may allow other clients. For external stores, restrict access separately. An
operator pod must not assume store access through this policy. Images are
configurable; the packaged test versions are Valkey 9.1.1 and Redis 7.2.

## Configure and deploy (operator action)

Example `my-values.yaml`:

```yaml
clusterId: ipmdn-prod
replicaCount: 3
image:
  repository: registry.example.com/team/haproxy-global-lb
  tag: 3.4.4-v2
stateStore:
  enabled: true
  provider: valkey
service:
  annotations:
    metallb.io/address-pool: service-pool
backends:
  - name: be_ipmdn_tcp
    portName: ipmdn
    port: 5000
    srv: _ipmdn._tcp.ipmdn-backend.ipmdn.svc.cluster.local
    slots: 3
    serverPort: 5000
    proxyProtocolV2: true
    healthCheck:
      interval: 1s
      fastInterval: 500ms
      downInterval: 2s
      rise: 2
      fall: 3
```

Array overrides replace the whole backend list. Add entries to serve multiple
ports/services; names, portNames and listener ports must be unique. Listener
ports must be >=1024 for the nonroot/no-capabilities container; 8404/`health`
are reserved. Same backend names and resolved IP:port define shared endpoint
identity, not server-template slot names. All endpoints have equal weight.
PPv2 is enabled in the sample: the application must accept the header followed
by EOF for health checks. Turn off `proxyProtocolV2` for a plain TCP application.
Backend workloads themselves are NOT installed by this chart.

```sh
make chart-lint CHART_ARGS='-f my-values.yaml'
make chart-template CHART_ARGS='-f my-values.yaml'
# Inspect context and rendered output before this explicit deployment command:
kubectl config current-context
helm upgrade --install haproxy charts/haproxy-global-lb \
  --namespace ipmdn --create-namespace -f my-values.yaml
kubectl -n ipmdn get statefulset,pods,services
```

These commands are instructions, not automatically run by the build targets.
For image credentials use `imagePullSecrets`. Node scheduling is configurable
through `haproxy.nodeSelector`, `tolerations`, and `affinity`. No mandatory
one-Pod-per-node placement is imposed. With Local external traffic policy,
MetalLB advertises nodes that have eligible ready endpoints, not equal per-Pod
weights; multiple HAProxy Pods on one node may skew ingress. Validate placement
and BGP/ECMP in your environment. Cluster domain defaults to `cluster.local`;
adjust `clusterDomain` AND backend SRV names if your cluster differs.

## Identity, probes and shutdown

- `instance-id = clusterId/StatefulSet-Pod-name`: downward API POD_NAME, then
  dependent env expansion into GLOBAL_LB_INSTANCE_ID; HAProxy reads it from cfg.
  Each worker generates its own startup UUID. Never assign all Pods one ID.
- `resolvers default` reads `/etc/resolv.conf` for async store and backend DNS.
- v2 reserve 1s, heartbeat 300ms, instance-timeout 3s, connect 200ms,
  command 1s, reconnect 100ms..5s; limits 16 retained owners /1024 group
  request mappings. No periodic count sync, no v1 cache/recovery timer.
- UD-001/007/010/016 `v2-timeouts-20261004`: the chart and production cfg
  explicitly override BOTH timeouts to1s for long-lived TCP. Queue+send+reply
  share the reserve deadline: 300ms in queue leaves at most700ms for the
  command, not another full1s. Early replies proceed immediately. This is the
  reservation budget, not a guarantee that backend TCP connect completes in1s.
  C parser omission defaults remain100ms; no source/recompile change. Existing
  values-file overrides take precedence. Heartbeat, liveness, store connect,
  retry/reconnect and terminal cleanup deadlines are not changed. Apply through
  deliberate Pod replacement, not live reload. Repeat burst/delay/HB tests with
  these settings before production certification.
- Readiness/liveness use a separate HTTP frontend on8404. The traffic Service
  does not expose it. Store failure never intentionally makes HAProxy unready;
  local leastconn fallback and established TCP remain usable.
- Admin socket `/run/haproxy/admin.sock` is Pod-local, not a TCP Service.
  `show global-lb status`, `reservations`, `local` are read-only diagnostics.
  CLI client tools are not installed in this image by this chart.
- Direct HAProxy worker runs as PID1 (`-db`), bypassing inherited reload-capable
  entrypoint; no Data Plane API/reloader/sidecar. Runtimes commonly honor the
  inherited image stop signal SIGUSR1; others send TERM. Both supported shutdown
  paths use the implemented bounded terminal cleanup.
  Pod grace10s is NOT the store cleanup deadline (100ms). SIGKILL still relies
  on3s liveness exclusion, not guaranteed physical Hash garbage collection.
- Default StatefulSet `OnDelete` prevents automatic disruption on Helm upgrade.
  Replace Pods deliberately ONE AT A TIME; new cfg/image applies on startup.
  `haproxy.updateStrategy: RollingUpdate` opts into automatic Pod replacement,
  not live reload. Both terminate old TCP; clients need reconnect. Store config
  uses stable cluster Service DNS; switching bundled/external/provider while
  HAProxy Pods run requires a coordinated maintenance migration, not seamless
  continuity. In OnDelete mode `rollout restart` alone does not replace Pods.
- Changing release/fullname/clusterId changes identities and can consume retained
  owner capacity. Keep them stable; do not flush active group keys. See existing
  operator recovery/limits in `doc/global-lb-reservation.txt`.
- No GW watchdog, backend connection rebalance, AUTH/TLS or MetalLB installation.

## Local validation (no Kubernetes mutation)

```sh
python3 tests/unit/global-lb-chart.py --binary ./haproxy
python3 tests/unit/global-lb-chart.py --image haproxy-custom:3.4.4 --smoke
make chart-lint
make chart-lint CHART_ARGS='--set stateStore.provider=redis'
make chart-lint CHART_ARGS='--set stateStore.enabled=false --set stateStore.externalAddress=127.0.0.1:6379'
```

The regression renders all modes, validates object selection/address wiring,
schema failures, configuration parsing and compile-feature requirements. Image
smoke optionally creates ONLY two task-owned temporary stores and a Docker
network, checks DNS/startup/fallback/HTTP health/memory-store restore/shutdown
with nonroot read-only containers, and cleans up. It requires the configured
Valkey/Redis images already cached (`--pull=never`); PyYAML is a test dependency,
not part of HAProxy or the runtime image. These tests are separate from Kubernetes, NetworkPolicy,
MetalLB/BGP, real SRV, registry pull and production performance certification.

Kubernetes reference: [dependent env expansion](https://kubernetes.io/docs/tasks/inject-data-application/define-interdependent-environment-variables/),
[OnDelete updates](https://kubernetes.io/docs/concepts/workloads/controllers/statefulset/#update-strategies),
[image stop signals](https://kubernetes.io/docs/concepts/workloads/pods/pod-lifecycle/#stop-signals),
[NetworkPolicy enforcement and additive rules](https://kubernetes.io/docs/concepts/services-networking/network-policies/).

UD-007/009/012/016 `v2-only-20261004`: v1 publisher/cache/selector and their
configuration directives have been removed. Global LB always uses v2 atomic
reservations; `show global-lb cache` is no longer available. The existing
`USE_GLOBAL_LB` / `USE_GLOBAL_LEASTCONN` build fences remain in force.

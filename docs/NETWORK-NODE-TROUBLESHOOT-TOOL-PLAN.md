# Network & Node Troubleshooting Tool Plan

**Goal:** Make oscar’s Code Mode surface (`tools_search` → `tools_execute`) cover the **most common, high-leverage** connectivity / status / analyze workflows an agent needs for multi-cloud **and** node-level network debugging — including **BPF** and **Envoy** — without dumping schemas into the system prompt.

**Status:** Plan + **P0 partially delivered** (2026-07-28).

### Delivered (search + execute)

| ID | Notes |
|----|--------|
| `network.troubleshoot.playbook` | Symptom → ordered tool steps |
| `node.net.status\|route.table\|route.get\|neigh\|ss\|ping\|traceroute\|dns.lookup` | Local Linux L3/L4 |
| `node.bpf.progs.list`, `node.bpf.net.show` | bpftool inventory / XDP-tc |
| `mesh.envoy.ready\|server_info\|clusters\|stats\|config_dump\|listeners\|diagnose` | Read-only admin |
| Soft-search tags on CSP path tools | connectivity, status, analyze, troubleshoot |
| Tool id aliases | e.g. `aws.network.path.reachability` → `path.analyze` |

Still open: Phase B live BCC traces (tcpconnect/retrans), Phase D CSP effective routes/TGW.

### Pattern ladder (broad → narrow) — agent contract

```
BROAD:  network.pattern.find | network.ip.locate | dns.pattern.find | k8s.resources.pattern.search
        network.troubleshoot.playbook | network.troubleshoot.status
NARROW: *.network.{vpc,subnet,sg,nacl,nsg,firewall,route,route_table}.pattern
        *.compute.function.pattern | *.dns.*.pattern*
        k8s.{pods,services,nodes,namespaces,deployments,ingress,networkpolicy,endpoints}.pattern.search
        mesh.envoy.{clusters,stats}.pattern
PATH:   aws.network.path.analyze | gcp.network.connectivity.test | azure.network.path.troubleshoot
NODE:   node.net.* | node.bpf.* | mesh.envoy.diagnose
```

~50 pattern tools; ~174 total first-class tools (2026-07-28).

**Sources (web + practice):** AWS Reachability / Network Access Analyzer docs; GCP Connectivity Tests patterns; Azure Network Watcher; BCC/bpftrace networking tools (Gregg / iovisor); Envoy admin API; Istio proxy-config / admin endpoints; Kubernetes CNI troubleshooting (CoreDNS, NetworkPolicy, Cilium/Calico).

---

## 1. What exists today (usable)

### Cloud path / connectivity / analyze

| Tool ID | Role |
|---------|------|
| `aws.network.path.analyze` | VPC Reachability Analyzer (path) |
| `aws.network.access.analyze` | Network Access Analyzer |
| `gcp.network.connectivity.test` | Connectivity Tests |
| `azure.network.path.troubleshoot` | Network Watcher connection troubleshoot |
| `azure.network.next_hop` | Next hop for dest IP |
| `multicloud.path.narrative` | Ordered playbook (text) |
| `multicloud.path.orchestrate` | Inventory-first multi-hop steps |
| `multicloud.interconnect.awareness` | Hybrid interconnect narrative |

### Inventory / locate (pre-path)

| Tool ID | Role |
|---------|------|
| `*.network.pattern.search` / `*.ip.locate` / SG·NACL·RT·route·function patterns | Ownership discovery |
| `network.pattern.find` | Multi-cloud network locate |
| `dns.*` + resolver / forwarding map | Name → path |

### Kubernetes / CNI (partial)

| Tool ID | Role |
|---------|------|
| `k8s.cni.detect` | Which CNI |
| `k8s.coredns.discover` | CoreDNS presence |
| `k8s.networkpolicy.deny.narrative` | Policy deny story |
| `k8s.hubble.observe` / `k8s.hubble.diagnose` | Cilium flows (if present) |
| `k8s.calico.*` | BGP / node / policy (if present) |
| `k8s.cilium.policy.check` | Cilium policy check |
| `k8s.pods|services|resources.pattern.search` | Resource locate |
| `k8s.cni.pod_logs` | CNI DaemonSet logs |

### Skills (prompt guidance, not execute)

- `network-vlsm-path`, `k8s-cni-connectivity`, discovery-intent

### Gaps (critical)

| Area | Missing from search/execute |
|------|-----------------------------|
| **Linux node L3/L4 basics** | `ss`, `ip route`, `ip neigh`, `ping`/`mtr`, `traceroute`, `nft`/`iptables` summary, `resolvectl`/`dig` |
| **Status snapshots** | Node health: interface/link, MTU, carrier, default route, DNS resolvers, listening sockets |
| **BPF / eBPF** | `bpftool`, bcc network tools (`tcpconnect`, `tcpaccept`, `tcpretrans`, `tcplife`, `softirqs`, …), `bpftrace` one-liners, XDP/tc program list |
| **Envoy / mesh data plane** | Admin: `/ready`, `/server_info`, `/clusters`, `/stats`, `/config_dump`, `/listeners`; Istio `istioctl proxy-config` / `pilot-agent request` |
| **Cloud status (not only path)** | TGW route analyzer, VPC flow log hints, Azure effective routes / NSG effective rules, GCP firewall hierarchy / routes get |
| **K8s service path** | Endpoints/EndpointSlice health, kube-proxy mode, NetworkPolicy list by pod, CoreDNS query from debug pod |
| **Soft-search discoverability** | Queries like “connectivity test”, “bpf”, “envoy stats”, “node route”, “retransmit” may miss or rank poorly |

---

## 2. Troubleshooting model (agent mental stack)

Agents should walk layers **top-down** unless the user already points at a layer. Soft-search tags and playbooks must reinforce this order.

```
0. Access / identity        → system.access.*  (already native)
1. Name / ownership         → dns.*  network.pattern.*  k8s.*.pattern
2. Intent / path (cloud)    → *.path.*  *.connectivity.*  next_hop  access.analyze
3. Node L3/L4               → node.net.status  route  ss  neigh  mtu
4. Dataplane (mesh/CNI)     → envoy.*  cilium/hubble  calico  networkpolicy
5. Live packets / drops     → bpf.*  (short TTL, read-only)  flow logs
6. Auth after L4 OK         → IAM / RBAC  (access.troubleshoot)
```

**Decision rule (already in narrative tools):**  
`timeout/reset` → network path; `403/401` after connect → identity/RBAC; DNS fail before L4 → DNS first.

---

## 3. Soft-search (`tools_search`) requirements

Every tool below must be discoverable via **short natural queries**. Add tags liberally; prefer **OR soft ranking** (already improved for long queries).

### Required search phrases → tool families

| User / agent query fragment | Must rank tools |
|----------------------------|-----------------|
| connectivity test, reachability, path analyze | CSP path analyzers + multicloud.path.* |
| next hop, route table, UDR, blackhole | route patterns + azure.next_hop + node.route |
| status, health, ready, live | envoy.ready, node.net.status, server_info |
| security group, nsg, nacl, firewall | pattern tools (exist) |
| retransmit, tcp drop, connection refused | bpf.tcp.* + ss + path |
| bpf, ebpf, xdp, bcc, bpftrace | node.bpf.* family |
| envoy, sidecar, istio, service mesh, config_dump | mesh.envoy.* |
| coredns, dns fail, nxdomain | dns.* + k8s.coredns.* |
| pod cannot reach, service endpoints | k8s.service.path + endpoints |
| node not ready, CNI, calico, cilium | k8s.cni.* + node.* |

### Catalog / primer updates

- Extend `agent_tools_primer` with a **Network & node triage** section listing these families.
- Alias tool IDs where narrative still uses old names (`aws.network.path.reachability` → `aws.network.path.analyze`).
- Tag every path tool with: `connectivity`, `status`, `analyze`, `troubleshoot`, `path`, `network`.

---

## 4. Tool catalog to add (search + execute)

Naming convention (Code Mode, first-class):

```
<node|mesh|cloud>.<domain>.<action>
```

Capability: **Read** by default. BPF live traces: Read + **time-boxed** (default 5–15s). Never enable Envoy admin mutations (`quitquitquit`, `drain`, `runtime_modify`, healthcheck fail) unless Write mode **and** explicit confirm.

### 4.1 Phase A — Node network status & classic L3/L4 (highest ROI)

| Tool ID | Purpose | Backing commands | Tags |
|---------|---------|------------------|------|
| `node.net.status` | Snapshot: default route, primary IF, MTU, carrier, DNS resolvers, brief address list | `ip -j route`, `ip -j addr`, `ip -j link`, `resolvectl status` or `/etc/resolv.conf` | status, network, node, mtu, route |
| `node.net.route.table` | Full route table (main + tables) with optional dest match | `ip -j route show table all`, optional `ip route get <dst>` | route, next-hop, blackhole |
| `node.net.route.get` | Kernel fib lookup for one dest (best next hop) | `ip -j route get <dst> [from <src>] [iif/oif]` | route, fib, path |
| `node.net.neigh` | ARP/ND cache | `ip -j neigh` | arp, neigh, l2 |
| `node.net.ss` | Listening / established sockets (filter host:port) | `ss -Htanpi` / `ss -Htunpi` JSON-ish parse | socket, listen, connect, port |
| `node.net.ping` | ICMP reachability (count 3, deadline) | `ping -c 3 -W 2` | connectivity, icmp |
| `node.net.traceroute` | Path hops | `traceroute` or `tracepath` or `mtr -r -c 5` | path, mtr, hops |
| `node.net.dns.lookup` | Local resolver view of a name | `dig +short` / `getent hosts` | dns, resolve |
| `node.net.firewall.summary` | High-level nft/iptables policy presence (not full dump) | `nft list ruleset` truncated / `iptables-save` head | firewall, nft, iptables |
| `node.net.ns.list` | Network namespaces (for multi-tenant nodes) | `ip -j netns`, optional enter | netns, container |

**Safety:** run on **local host** or via explicit `target` (ssh/kubectl exec profile) later. Phase A = local + optional `kubectl exec` if `node_selector` provided.

**Execute input schema (shared):**

```json
{
  "target": { "type": "string", "description": "local | kubectl:ns/pod | ssh:host (phase B)" },
  "profile_id": { "type": "string" },
  "timeout_sec": { "type": "integer", "default": 10, "maximum": 60 }
}
```

### 4.2 Phase B — BPF / eBPF (network-focused)

| Tool ID | Purpose | Backing | Notes |
|---------|---------|---------|-------|
| `node.bpf.progs.list` | Loaded BPF programs + attach points | `bpftool prog show -p`, `bpftool net show -p` | Inventory first |
| `node.bpf.map.list` | Maps summary | `bpftool map show -p` | Optional detail |
| `node.bpf.xdp.status` | XDP on interfaces | `bpftool net show` / `ip -d link` | DDoS / drop paths |
| `node.bpf.tc.status` | clsact/tc BPF filters | `tc filter show dev …` + bpftool | |
| `node.bpf.tcpconnect` | Active TCP connects (time-boxed) | bcc `tcpconnect` or bpftrace | duration 5–15s |
| `node.bpf.tcpaccept` | Passive accepts | bcc `tcpaccept` | |
| `node.bpf.tcpretrans` | Retransmits | bcc `tcpretrans` | Latency/loss signal |
| `node.bpf.tcplife` | Connection lifespan/throughput | bcc `tcplife` | Prefer over tcpdump |
| `node.bpf.tcpdrop` | Kernel TCP drops (if tool present) | bcc `tcpdrop` / `skbdrop` | |
| `node.bpf.softirq` | NET_RX softirq pressure | bcc `softirqs` / `runqlat` optional | Node saturation |
| `node.bpf.oneshot` | Safe bpftrace one-liner from **allowlist** | `bpftrace -e '...'` | No free-form kernel write |

**Allowlist examples (bpftrace):**

- `tracepoint:syscalls:sys_enter_connect { … }` summary counts  
- `kprobe:tcp_retransmit_skb` count by daddr  
- `tracepoint:net:netif_receive_skb` rate (high overhead — cap duration)

**Not in v1:** arbitrary BCC Python, unrestricted kprobe attach, packet capture full payload (`tcpdump -w`). Offer `node.net.pcap.hint` narrative instead (suggest filters) under Read.

**Discovery tags:** `bpf`, `ebpf`, `bcc`, `bpftrace`, `xdp`, `tc`, `retransmit`, `tcpconnect`, `drop`, `trace`.

**Binary detection:** extend `system.binaries.list` / install plan for `bpftool`, `bpftrace`, `bcc-tools` paths (`/usr/share/bcc/tools`).

### 4.3 Phase C — Envoy / service mesh data plane

Prefer **read-only admin GET** endpoints (localhost or port-forward).

| Tool ID | Purpose | Backing | Envoy path |
|---------|---------|---------|------------|
| `mesh.envoy.ready` | Readiness | `curl -sS localhost:9901/ready` or `:15000/ready` | `/ready` |
| `mesh.envoy.server_info` | Version, LIVE state | `/server_info` | |
| `mesh.envoy.clusters` | Upstream hosts + health | `/clusters` or `?format=json` | SD / HC failures |
| `mesh.envoy.listeners` | Listeners + bound ports | `/listeners` | |
| `mesh.envoy.stats` | Filtered stats | `/stats?usedonly&filter=…` | cx/rq/5xx |
| `mesh.envoy.config_dump` | Config (redact secrets) | `/config_dump?include_eds` + redact | Routes/clusters |
| `mesh.envoy.certs` | Cert expiry | `/certs` | TLS issues |
| `mesh.istio.proxy_config` | Istio-friendly dump | `istioctl proxy-config cluster\|listener\|route\|endpoint` or `pilot-agent request GET …` | |
| `mesh.envoy.diagnose` | Opinionated pack | ready + clusters healthy summary + top error stats | Single agent call |

**Inputs:**

```json
{
  "admin_url": { "type": "string", "default": "http://127.0.0.1:15000" },
  "pod": { "type": "string", "description": "ns/name for kubectl exec -c istio-proxy|envoy" },
  "container": { "type": "string", "default": "istio-proxy" },
  "filter": { "type": "string", "description": "stats/cluster name fragment" },
  "include_eds": { "type": "boolean", "default": false }
}
```

**Hard rules:**

- Never call POST `/quitquitquit`, `/drain_listeners`, `/runtime_modify`, `/healthcheck/fail` in Read mode.
- Redact private keys from config_dump (Envoy attempts this; double-redact in oscar).
- Cap config_dump size (summarize listeners/routes/clusters counts + name filter).

**Tags:** `envoy`, `istio`, `mesh`, `sidecar`, `config_dump`, `clusters`, `stats`, `ready`, `xds`, `eds`.

### 4.4 Phase D — Cloud path/status completeness

| Tool ID | Cloud | Purpose |
|---------|-------|---------|
| `aws.network.path.status` | AWS | Poll existing analysis / list recent Network Insights analyses |
| `aws.network.tgw.route.analyze` | AWS | Transit Gateway Route Analyzer (multi-RT paths) |
| `aws.network.flowlog.hints` | AWS | Where flow logs live + query template (not full Athena) |
| `gcp.network.connectivity.status` | GCP | Get Connectivity Test result by name |
| `gcp.network.firewall.effective` | GCP | Effective firewall for instance/tag (gcloud compute) |
| `azure.network.effective.routes` | Azure | NIC effective routes |
| `azure.network.effective.nsg` | Azure | Effective NSG rules on NIC |
| `azure.network.connection.monitor` | Azure | Connection Monitor status (if configured) |

**Soft-search:** all must match `connectivity`, `status`, `analyze`.

**Align narrative aliases** in `multicloud.interconnect.awareness` / orchestrate with real IDs (`path.analyze` not stale names).

### 4.5 Phase E — Kubernetes service & node path

| Tool ID | Purpose |
|---------|---------|
| `k8s.service.path` | Service → EndpointSlice → pod IPs + ready flags |
| `k8s.endpoints.pattern` | Partial match endpoints/slices |
| `k8s.networkpolicy.list` | Policies affecting a pod (namespace + selectors) |
| `k8s.node.net.status` | Via `kubectl debug`/`nsenter` or DaemonSet exec: route/ss on node |
| `k8s.coredns.query` | Run dig/nslookup in ephemeral debug pod |
| `k8s.kube_proxy.mode` | Detect iptables/ipvs/nft vs Cilium kube-proxy replacement |
| `k8s.pod.exec.netcheck` | Bounded: resolve + connect to host:port from pod |

**Compose with existing:** `k8s.cni.detect` → branch to Hubble vs Calico vs AWS VPC CNI logs.

### 4.6 Phase F — Meta playbooks (search-friendly)

| Tool ID | Purpose |
|---------|---------|
| `network.troubleshoot.playbook` | Returns ordered tool IDs + args templates for a symptom (dns\|timeout\|refused\|mesh\|node\|cross-cloud) |
| `network.troubleshoot.status` | Runs **read-only pack**: inventory hit? path tool? node status? mesh ready? → one structured report |
| `node.troubleshoot.pack` | Local: status + route get + ss + optional short tcpretrans |

These are the “analyze everything important” entry points agents should hit first when the query is vague.

---

## 5. Symptom → tool map (for playbooks)

| Symptom | First tools | Then | Deep |
|---------|-------------|------|------|
| Name not resolving | `dns.where`, `*.dns.pattern.search` | `k8s.coredns.*`, private resolver inventory | node.dns.lookup |
| Timeout / no route | `*.ip.locate`, `*.network.route*`, path.analyze | next_hop / fib get | bpf.tcpretrans, flowlog hints |
| Connection refused | `node.net.ss` / k8s endpoints | SG/NSG/NACL pattern | envoy.clusters healthy |
| Works from node not pod | `k8s.cni.detect`, networkpolicy, service.path | Hubble/Calico | bpf on node netns |
| Intermittent latency | path + TC retrans | softirq, tcplife | envoy stats rq_time |
| Mesh 503 / no healthy upstream | `mesh.envoy.clusters`, stats filter `upstream` | config_dump routes | istio proxy-config |
| Cross-cloud / hybrid | multicloud.path.narrative | interconnect.awareness | per-CSP path + DNS forwarding map |
| Drop / blackhole suspect | route tables + NACL/SG | XDP/tc bpf status | tcpdrop / nft summary |

---

## 6. Implementation architecture

```
oscar-tools/
  node/          # Phase A+B: local CLI wrappers, duration caps
  mesh/          # Phase C: Envoy admin + istioctl helpers
oscar-aws|gcp|azure  # Phase D extensions
oscar-k8s/       # Phase E
multi.rs         # Phase F playbooks + soft-search tag audit
skills.rs        # Update network-vlsm-path + k8s-cni with new tool IDs
catalog.rs       # Primer lines for triage
```

### Shared execution helpers

- `run_json_command` / text capture with timeout (exists).
- `truncate_output(max_bytes)` for config_dump / nft.
- `which_ok` for optional binaries; return **install hints** via `system.binaries.install_plan`.
- **Target resolver:** `local` | `kubectl:{ns}/{pod}[-c container]` | future SSH profile.

### Mode gating

| Class | ReadOnly | Write | Admin |
|-------|----------|-------|-------|
| status / analyze / list / dump | ✓ | ✓ | ✓ |
| bpf time-boxed trace | ✓ | ✓ | ✓ |
| envoy POST mutations | ✗ | confirm | ✓ |
| tcpdump -w / raw pcap | ✗ | confirm | ✓ |

---

## 7. Soft-search quality bar (acceptance)

For each phrase, `tools_search` top-10 must include ≥1 correct tool:

1. `connectivity test`
2. `reachability analyzer`
3. `next hop`
4. `bpf retransmit`
5. `envoy config_dump`
6. `envoy clusters healthy`
7. `node route table`
8. `ss listening port`
9. `coredns pod`
10. `service endpoints not ready`
11. `xdp program`
12. `network status`

Add regression tests in `oscar-tools` registry search tests (mirror existing soft-match tests).

---

## 8. Phased delivery

| Phase | Deliverable | Effort | Priority |
|-------|-------------|--------|----------|
| **A0** | Soft-search tags + primer + alias fix for **existing** path/CNI tools | S | P0 |
| **A** | `node.net.status|route.*|ss|ping|traceroute|dns.lookup` | M | P0 |
| **F0** | `network.troubleshoot.playbook` wired to **current** tools only | S | P0 |
| **C** | `mesh.envoy.*` + diagnose pack | M | P0 |
| **B** | `node.bpf.progs/net` + tcpconnect/accept/retrans/life (optional binaries) | M | P1 |
| **E** | k8s service.path, endpoints, networkpolicy.list, coredns.query | M | P1 |
| **D** | CSP status/effective routes/TGW/flowlog hints | M | P1 |
| **F1** | `network.troubleshoot.status` multi-tool pack | M | P1 |
| **B2** | bpf.oneshot allowlist + xdp/tc status | S | P2 |
| **A2** | kubectl/ssh targets for node tools | L | P2 |

---

## 9. Concrete “must ship” minimum set (agent-useful)

If only one sprint: implement **A0 + A + C + F0**.

1. **Discoverable connectivity tools** (tags/aliases).  
2. **Node status + route get + ss** (explains 80% of “node network” tickets).  
3. **Envoy ready/clusters/stats/config_dump** (explains mesh 503/HC).  
4. **Playbook** that sequences: locate → DNS → path → node → mesh → bpf-if-present.

Then B (BPF) as the live-signal layer when config looks fine but packets still fail.

---

## 10. Example agent flows (after plan)

### “Pod cannot reach RDS”

1. `network.troubleshoot.playbook` symptom=`timeout`  
2. `k8s.pods.pattern.search` / service path  
3. `aws.network.ip.locate` + `aws.network.sg.pattern`  
4. `aws.network.path.analyze`  
5. If path OK: `node.bpf.tcpretrans` on node or `mesh.envoy.clusters` if sidecared  

### “Envoy 503”

1. `mesh.envoy.ready` + `server_info`  
2. `mesh.envoy.clusters` (unhealthy hosts)  
3. `mesh.envoy.stats` filter `upstream_rq_5xx|cx_connect_fail`  
4. `mesh.envoy.config_dump` resource filter  
5. Upstream: cloud path + DNS  

### “High latency / intermittent”

1. `node.net.status` (MTU, errors)  
2. `node.bpf.tcpretrans` (5–10s)  
3. `node.bpf.tcplife`  
4. Path analyzer + flow log hints  

---

## 11. Out of scope (explicit)

- Full packet capture UI / long-lived tcpdump in agent loop  
- Writing BPF programs from model text (allowlist only)  
- Envoy admin over public internet without tunnel  
- Replacing cloud provider UIs for flow log analytics  
- Active traffic generation load tests (optional later Write tool)

---

## 12. Success criteria

- [ ] Agent query “run a connectivity test” → finds CSP path tools in top results  
- [ ] Agent query “bpf retransmit” → finds `node.bpf.tcpretrans` (or install hint)  
- [ ] Agent query “envoy clusters” → finds mesh tools  
- [ ] `network.troubleshoot.playbook` returns ≥5 ordered executable tool IDs for timeout/DNS/mesh  
- [ ] Node status + Envoy diagnose return structured JSON + short summary for TUI  
- [ ] No new Write-capable admin mutations in ReadOnly mode  
- [ ] Unit tests: search ranking + mappers for envoy JSON + ip -j parse  

---

## 13. Next implementation step

1. Land **A0** (tags/aliases/primer) — no new CLI deps.  
2. Land **F0** playbook against existing path/DNS/CNI tools.  
3. Land **A** node status/route/ss.  
4. Land **C** Envoy admin pack.  
5. Iterate **B/E/D** per production pain.

This document is the backlog contract for making connectivity **status / analyze / test** — plus **BPF** and **Envoy** — first-class in oscar search and execute.

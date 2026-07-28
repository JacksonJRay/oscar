//! Agent-facing tool catalog text: how to use Code Mode search/execute.

/// Long description for `tools_search` (loaded into the model tool schema).
pub fn tools_search_description() -> String {
    r#"Search oscar's first-class multi-cloud/k8s tool inventory (Code Mode discovery).

WHEN TO USE
- Call before tools_execute if you are unsure of the exact tool_id for **cloud/infra** tools.
- Do **not** use this for account management — call system.access.* / system.profiles.list / system.identities.list as native tools.
- Prefer short 2–4 word queries with domain/cloud filters (long AND-style queries are soft-matched but shorter is better).

QUERY TIPS
- Free text matches id, name, description, and tags (e.g. "dns private", "subnet 10.0", "reachability", "inventory sync").
- domain: dns | network | access | account | cluster | infra | meta
- cloud: aws | gcp | azure | k8s | multi
- capability: read | write  (session is read-only by default; write tools fail unless mode is readwrite)

RETURNS
- Ranked tools with: id, name, description, domain, clouds, capability, tags, input_schema,
  required_binaries, execution_backend, feasibility (available|degraded|unavailable), missing_binaries, fallback.
- Only call tools_execute for feasibility=available (or degraded if you accept partial).
- If unavailable, tell the user which CLI to install OR pick a cache/first-class path that needs no binary.
- Use the `id` field as tools_execute.tool_id.
- Read input_schema.required and properties before calling execute.

AUTH / SAFETY
- Tools never return raw secrets. If auth is required, result includes auth_required + hint_commands.
- Do not ask the user to paste secrets into chat text; they use TUI secure bar or `oscar auth …` CLI.
- After auth, the host auto-retries the paused tool (or user types `retry`).
- Account/skills tools are **NATIVE** (call directly): system.access.review | prepare | select | system.profiles.list | system.identities.list | **system.skills.create | search | get | list** — never tools_search for these.

COMMON TOOL FAMILIES
- Inventory sync: aws|gcp|azure.dns.inventory.sync, *.network.inventory.sync, k8s.inventory.sync, *.dns.resolver.inventory.sync
- **Broad → narrow pattern ladder (prefer short fragments, mode=partial default):**
  1. BROAD: `network.pattern.find`, `network.ip.locate`, `dns.pattern.find` / `dns.where`, `k8s.resources.pattern.search`, `access.pattern.find`
  2. NARROW cloud: `*.network.vpc|subnet|sg|nacl|nsg|firewall|route|route_table.pattern`, `*.network.peering|tgw|vpn|endpoint|nat|igw|hybrid|share|prefix_list|service.pattern`, `*.compute.function.pattern`, `*.dns.pattern.search`, resolver/firewall/querylog/profile patterns
  3. NARROW k8s: `k8s.pods|services|nodes|namespaces|deployments|ingress|networkpolicy|endpoints.pattern.search`
  4. NARROW mesh: `mesh.envoy.clusters.pattern`, `mesh.envoy.stats.pattern` (after `mesh.envoy.diagnose`)
- Path / connectivity / analyze: aws.network.path.analyze, aws.network.access.analyze, gcp.network.connectivity.test, azure.network.path.troubleshoot, azure.network.next_hop
- **Write (create/delete) — only when session mode is readwrite:** `*.network.vpc|subnet|sg|firewall|nsg|route|peering|endpoint.create|delete`, SG ingress authorize/revoke, tags. DNS: `*.dns.record.create|delete`. IAM writes under `*.iam.*`. **Readonly mode hard-blocks all Capability::Write tools.**
- **Start vague network issues:** `network.troubleshoot.playbook` or `network.troubleshoot.status` (symptom + ladder)
- **Node L3/L4:** node.net.status, route.get|table, ss, ping, traceroute, dns.lookup, neigh
- **BPF:** node.bpf.progs.list, node.bpf.net.show
- **Envoy:** mesh.envoy.diagnose, ready, clusters(.pattern), stats(.pattern), config_dump, listeners
- K8s CNI: k8s.cni.detect, k8s.hubble.*, k8s.calico.*, k8s.cilium.*, k8s.networkpolicy.deny.narrative, k8s.coredns.discover
- IAM: aws.iam.*, gcp.iam.*, azure.iam.*, access.troubleshoot
- **Access / multi-profile:** system.access.review (what creds exist), system.access.prepare (create profile + secure paste/SSO), system.access.select (session pivot), system.profiles.list, system.identities.list
- **Kubernetes cluster connect:** `system.cluster.resolve` (fuzzy name: users say `2ptt` not full EKS name) → `system.cluster.prepare` by kind (eks→AWS STS; gke→gcloud+gke-gcloud-auth-plugin; aks→az+kubelogin; kind/k3s→kubeconfig). `system.cluster.infer_kubeconfig` classifies a pasted kubeconfig. Kind unknown → ask before secrets.
- **SSM remote exec (AWS nodes):** `aws.ssm.instances.list` then **`aws.ssm.exec`** with plain `command` + `instance_id` — oscar base64-wraps for SSM (no quoting hell). Write mode required.
- Skills/playbooks (progressive): `system.skills.search` → `system.skills.get` / `skill.<name>`; **`system.skills.create`** when user wants a new playbook. tools_search also returns matching `skill.*` ids (description only until execute).
- Binaries: system.binaries.list, system.binaries.install_plan (when feasibility=unavailable)
- MCP: tools with id mcp.<server>.<tool> (configured in TOML; never dumped into system prompt)

EACH RESULT INCLUDES enough to execute: id, input_schema, required_args, example_arguments, feasibility, can_execute_now.
"#.trim().into()
}

/// Long description for `tools_execute`.
pub fn tools_execute_description() -> String {
    r#"Execute a first-class oscar tool by stable tool_id with JSON arguments.

WHEN TO USE
- After tools_search selected a tool_id, or when you already know the exact id.
- Prefer inventory sync then pattern search over inventing multi-step cloud API plans.

ARGUMENTS
- tool_id (required): e.g. "aws.network.pattern.search" — use the `id` from tools_search (not display name).
- arguments (required object): must satisfy that tool's input_schema / required_args from tools_search.
  Prefer copying example_arguments from the search hit and editing values.
  Common pattern tools accept: pattern (or query), mode (partial|prefix|suffix|exact|glob|ip_or_cidr), profile_id, region, limit.
  Path tools accept: source, destination, protocol, destination_port, profile_id, region.
  If you get missing_required_args, re-call tools_execute with the fields listed in the error (example included).

BEHAVIOR
- Enforces session mode: write tools (network create/delete, DNS UPSERT/DELETE, IAM attach/…) **hard-blocked** in readonly via Capability::Write gate.
- Uses CSP credentials from oscar keychain (long-lived or short-lived STS) or detected binary sessions (aws/gcloud/az/kubectl). Never relies on ambient LLM env keys.
- On missing/expired credentials: returns auth_required with guidance + hint_commands; agent should surface those and stop inventing workarounds. Host pauses and auto-retries after auth.
- Large payloads are summarized; prefer the summary field for chat.

DO NOT
- Pass secrets, tokens, or private keys in arguments (they will be redacted and must not be requested in chat).
- Call write tools without user enabling readwrite mode.
- Claim cloud state without a successful tool result.

EXAMPLES
- tools_execute { "tool_id": "dns.where", "arguments": { "name": "api.internal.example" } }
- tools_execute { "tool_id": "aws.network.pattern.search", "arguments": { "pattern": "10.0.4", "mode": "partial" } }
- tools_execute { "tool_id": "aws.network.path.analyze", "arguments": { "source": "10.0.1.10", "destination": "10.0.2.20", "destination_port": 443 } }
"#.trim().into()
}

/// Extra agent guidance block injected into system prompt (not secrets).
pub fn agent_tools_primer() -> &'static str {
    r#"## Tool use — order of operations
0. **Narrate:** after each tool round, 1–2 sentences to the user (findings / miss / next step). Never silent-stop after tools.
1. **Account + skills tools are NATIVE** (call by name — no tools_search):
   `system.access.review` | `system.access.prepare` | `system.access.select` | `system.profiles.list` | `system.identities.list`
2. **Cloud/infra tools:** `tools_search` → `tools_execute` (DNS, network, path, IAM, k8s, MCP, inventory…).
   Prefer short search queries (2–4 words), e.g. `aws dns zones`, `dns pattern`. Known ids: `aws.dns.zones.list`, `aws.dns.pattern.search`, `aws.dns.inventory.sync`.
3. Session injects binary inventory, settings, skills catalog.
4. Prefer feasibility=available. Do not invent shell use of missing CLIs.
5. Missing binaries: `system.binaries.install_plan` (never sudo yourself).
6. auth_required: show hint_commands; wait for secure bar / SSO — never collect secrets in chat. Secure bar accepts a full `export AWS_*` block in one paste.
6b. Multi-account (HARD):
   - No cloud/account specified + multiple CSPs/profiles → **ask user first**.
   - Named account → native `system.access.review` → prepare if needed → select → domain tools with **`profile_id`**.
   - **Never** substitute aws-default for a named account (vdms ≠ default).
   - If usable profile already known, continue to DNS/network in the **same turn**.
7. Pattern + inventory for discovery; path analyzers for reachability; IAM tools for access.
7b. **Network / node triage:** `network.troubleshoot.playbook` or `network.troubleshoot.status` first. Ladder: **broad** pattern.find / ip.locate → **narrow** kind.pattern → path.analyze / envoy.diagnose → node/bpf. timeout/reset=network; 403 after connect=IAM.
7c. Pattern tools: always try **partial** name fragments first; use dedicated `*.sg.pattern` / `k8s.pods.pattern.search` etc. to narrow after a broad hit list.
7d. **Mode:** session is **readonly by default**. Find/troubleshoot tools are Read. Create/delete/authorize tools are Write and **fail in readonly** with ModeDenied — user must enable readwrite (`/mode` or config) before mutating networks/DNS/IAM.
8. Skills: search `system.skills.search` or tools_search → exec `system.skills.get` / `skill.<name>`. Create: `system.skills.create`.
9. IAM write needs readwrite; least privilege always.
10. K8s: detect CNI first; hard-validate SNAT for pod egress.
11. Never put long-lived keys / SA JSON in chat.
12. Context auto-compacts ~85% — keep tool use targeted."#
}

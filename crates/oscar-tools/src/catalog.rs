//! Agent-facing tool catalog text: how to use Code Mode search/execute.

/// Long description for `tools_search` (loaded into the model tool schema).
pub fn tools_search_description() -> String {
    r#"Search oscar's first-class multi-cloud/k8s tool inventory (Code Mode discovery).

WHEN TO USE
- Always call this before tools_execute if you are unsure of the exact tool_id.
- Prefer short queries with domain/cloud filters to keep results small and accurate.

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

COMMON TOOL FAMILIES
- Inventory sync: aws|gcp|azure.dns.inventory.sync, *.network.inventory.sync, k8s.inventory.sync, *.dns.resolver.inventory.sync
- Pattern discovery: dns.pattern.find, dns.where, dns.resolve.public, *.dns.pattern.search, network.pattern.find, *.network.pattern.search, *.ip.locate, k8s.*.pattern.search
- Private DNS / hybrid: aws.dns.resolver.*, gcp.dns.policy.*, azure.dns.vnet_link.*, azure.dns.private_resolver.*, dns.forwarding.map
- Path troubleshooting: aws.network.path.analyze, aws.network.access.analyze, gcp.network.connectivity.test, azure.network.path.troubleshoot, azure.network.next_hop
- K8s CNI: k8s.cni.detect, k8s.hubble.*, k8s.calico.*, k8s.cilium.*, k8s.networkpolicy.deny.narrative, k8s.coredns.discover
- IAM: aws.iam.*, gcp.iam.*, azure.iam.*, access.troubleshoot
- Skills: system.skills.list, system.skills.get (user steering playbooks)
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
- Enforces session mode: write tools blocked in readonly.
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
    r#"## Tool use (Code Mode) — order of operations
1. **First-class first:** `tools_search` → `tools_execute`. Only after that, secondary binaries / manual CLI recipes.
2. Session injects **binary inventory**, **user settings** (disabled tools/clouds, install policy), and **skills catalog**.
3. tools_search omits disabled tools/clouds; feasibility marks available|degraded|unavailable.
4. Prefer feasibility=available. Do not invent shell use of missing CLIs.
5. Missing binaries: follow install_binaries policy via `system.binaries.install_plan` (never sudo yourself).
6. auth_required: show hint_commands; wait for user auth/retry — never collect secrets in chat.
7. Pattern + inventory for discovery; path analyzers for reachability; IAM tools for access.
8. **Skills:** `system.skills.list` / `system.skills.get` load user/project playbooks that steer beyond the harness.
9. **IAM:** access.troubleshoot → simulate/test; manage create/delete/attach requires **readwrite**; least privilege always.
10. **K8s connectivity:** identify CNI first; assume SNAT for pod egress but hard-validate; first-class k8s tools then Hubble/calicoctl.
11. Never create long-lived access keys / SA keys into chat.
12. **Context:** host auto-compacts at ~85% of full context_window (Grok-style) — keep tool use targeted; re-fetch after compact notes."#
}

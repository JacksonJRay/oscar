# Changelog

All notable changes to **oscar** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release artifacts (Linux) are attached to GitHub Releases:

- Latest: <https://github.com/JacksonJRay/oscar/releases/latest>
- Tags: `vMAJOR.MINOR.PATCH` (see [docs/RELEASING.md](docs/RELEASING.md))

## [Unreleased]

## [0.2.0] — 2026-07-28

### Added

- **Kubernetes cluster connect by kind (`system.cluster.prepare`):** creates `k8s-…` profiles with auth surface by flavor — **EKS** → linked AWS short-lived STS + `aws eks update-kubeconfig` (exec get-token); **GKE** → gcloud + **gke-gcloud-auth-plugin**; **AKS** → az login + **kubelogin**; **kind/k3s/minikube/k0s/local** → kubeconfig only. If kind cannot be inferred, returns `needs_user_clarification`.
- **`system.cluster.resolve`:** fuzzy-match user fragments (`2ptt` → `jade-2ptt-e-upf`) against live EKS names + kube contexts. **`system.cluster.infer_kubeconfig`:** classify pasted kubeconfig (EKS/GKE/AKS/kind). Agent harness: never assume full cluster name; always resolve/infer first.
- **kubectl isolation:** k8s inventory/sync uses per-cluster `KUBECONFIG` + linked AWS STS env so EKS exec plugins work without clobbering ambient kind context.
- **AWS SSM exec:** `aws.ssm.exec` (Write) runs a **plain** shell command on EC2 via SSM Run Command — oscar base64-encodes/wraps so the agent never deals with SSM quoting; polls for stdout/stderr/exit. `aws.ssm.instances.list` discovers managed instances.
- **Skills progressive disclosure + create playbook:** `system.skills.search` (short hits only), `system.skills.create` (write SKILL.md from user guidance), `tools_search` surfaces `skill.<name>`, `tools_execute skill.<name>` loads body via `system.skills.get`. Catalog capped; builtin `create-playbook`. Aligns with Grok Build / OpenCode skill loading (no full bodies until exec).
- **Agent can author playbooks in readonly:** `system.skills.create` is **Read** + **NATIVE** (with search/get/list); accepts `guidance=` natural language; returns body and auto-pins the skill into the session after create.
- **Network / node triage (P0):** `network.troubleshoot.playbook` (symptom → ordered tools); local **node** tools (`node.net.status|route.*|ss|ping|traceroute|dns.lookup|neigh`); **BPF** inventory (`node.bpf.progs.list`, `node.bpf.net.show`); **Envoy** read-only admin pack (`mesh.envoy.ready|server_info|clusters|stats|config_dump|listeners|diagnose`). Soft-search tags for connectivity/status/analyze on CSP path tools; id aliases (`aws.network.path.reachability` → `path.analyze`). See [docs/NETWORK-NODE-TROUBLESHOOT-TOOL-PLAN.md](docs/NETWORK-NODE-TROUBLESHOOT-TOOL-PLAN.md).
- **Broad→narrow pattern ladder:** multi `network.ip.locate` + `network.troubleshoot.status`; k8s narrow patterns (`nodes|namespaces|deployments|ingress|networkpolicy|endpoints.pattern.search`); inventory sync adds deploy/ingress/NP/EndpointSlice; Envoy `clusters.pattern` / `stats.pattern`; catalog documents broad→narrow order.
- **Network fabric discovery (peering / sharing / hybrid):** `NetworkInventory.services` + ResourceKinds (peering, transit_gateway, vpn, hybrid_connection, private_endpoint, nat_gateway, internet_gateway, network_share, prefix_list). **AWS** sync+patterns: peering, tgw, vpn, endpoint, nat, igw, hybrid (DX), prefix_list, service. **GCP:** peering, vpn, hybrid (Interconnect), nat (Cloud NAT), share (Shared VPC), service. **Azure:** peering, vpn (VNet gateway), hybrid (ExpressRoute), endpoint (Private Endpoint), nat, service.
- **Network write suite (mode-gated):** AWS/GCP/Azure create+delete for VPC/VNet, subnet, SG/firewall/NSG, routes, peering (+ AWS accept/endpoint/tags; AWS SG ingress authorize/revoke). All `Capability::Write` — **blocked in readonly** via existing mode gate. See [docs/NETWORK-FABRIC-COVERAGE.md](docs/NETWORK-FABRIC-COVERAGE.md).
- **Network pattern discovery (all CSPs)**: partial-match search for security groups / firewalls / NSGs, NACLs (AWS), route tables + individual routes, VNets/VPCs, and serverless functions (Lambda / Cloud Functions+Run / Azure Functions). Inventory sync now fetches these via CLI; tools include:
  - AWS: `aws.network.sg|nacl|route_table|route.pattern`, `aws.compute.function.pattern`
  - GCP: `gcp.network.vpc|firewall|route|route_table.pattern`, `gcp.compute.function.pattern`
  - Azure: `azure.network.vnet|nsg|route_table|route.pattern`, `azure.compute.function.pattern`
  - Multi: `network.pattern.find` / `*.network.pattern.search` cover the expanded kinds

### Changed

- **Search tools default to partial match**: all `*.pattern.search` / `*.pattern.find` / `*.record.lookup` tools use substring (or dual partial+IP) matching by default; Azure Entra principal + role-definition search no longer use startswith/exact-only filters.
- **Account tools are native LLM tools** (no `tools_search`): `system.access.review|prepare|select`, `system.profiles.list`, `system.identities.list`. Cloud/infra stays Code Mode (`tools_search` → `tools_execute`).
- **Agent narration**: harness requires 1–2 sentence findings after each tool round; host injects a short nudge when the model would otherwise stay silent.
- **Secure bar**: accept a full `export AWS_ACCESS_KEY_ID=…` / secret / session-token block in one paste.
- **OpenCode Go** default base URL `https://opencode.ai/zen/go/v1`; static Go model fallbacks + NVIDIA catalog stubs.

### Fixed

- **TUI code blocks (bash / common languages)**: fenced and indented code no longer renders as flat dim gray. Clean box (`┌─ bash ──` / `│` rail / `└──`), language aliases (`sh`→`bash`), soft-cyan command body vs dim chrome, rails kept on wrap, inline `` `code` `` backticks kept. JSON/python/rust/etc. use the same pass.
- **Secure bar short-lived AWS paste loop**: `system.access.prepare` no longer re-emits `auth_required` after keys are already stored (was infinite retry after paste). Shape-validate AccessKeyId/Secret/SessionToken; reject full-chat transcript pastes that previously poisoned `AccessKeyId` with 10KB+ of chat.
- **Secure bar bulk paste is atomic**: full `export AWS_*` block stores all fields in one host batch before a single resume (no more AccessKey→retry→Secret→retry→Token→retry prepare loops). Install updated `oscar` binary (`~/.local/bin/oscar`) after rebuild.
- **TUI scroll**: stop auto-pinning to bottom on `Done` when the user scrolled up (agent answer no longer jumps away); slower wheel/PgUp steps.
- **TUI mouse highlight/copy**: hit-test uses the same multi-row wrap layout as the renderer so selection matches the cursor.
- **TUI copy (Grok-aligned)**: select whole entries/blocks (not single wrap-rows); `y`/`Ctrl+Y`/`Enter` copy plain block content (no `role:` prefixes); click no longer auto-copies the full chat; `/copy` copies latest assistant reply only.
- **Clipboard owner fix (Grok 1:1)**: stop creating short-lived `arboard::Clipboard` (caused “clipboard was dropped very quickly after writing” and empty pastes). Long-lived owner thread holds CLIPBOARD (+ PRIMARY on Linux); fallbacks `wl-copy` / `xclip` / `xsel` / `tmux load-buffer`; OSC 52 only if live routes fail; always writes `~/.config/oscar/last-copy.txt`; toast `Copied!` or names backup path.
- **Chat scroll is continuous visual rows (Grok)**: no more snapping whole messages/pages. Wheel / Ctrl+↑↓ / Ctrl+J/K move by visual rows; PageUp/Down = full viewport; Ctrl+U/D = half page.
- **Character text selection (Grok pager)**: mouse drag selects characters (cyan highlight), not whole model turns; release auto-copies the range. Click without drag still selects the entry for `y`. Esc clears text or entry selection.
- **TUI chat Grok parity (Wave 1)** ([docs/CHAT-UPDATE.plan.md](docs/CHAT-UPDATE.plan.md)): Esc never quits (cancel / clear-selection / Esc Esc clear prompt); Ctrl+C clear → cancel → double-quit; Space focuses prompt from scrollback; status `queue:N`; Done is a short toast not a permanent chat line; `scripts/chat-parity-smoke.sh`.
- **TUI assistant markdown**: tables/headers/lists render as clean columns (not raw `|---|` markdown).
- **Grok SuperGrok OAuth scopes**: removed `team:read` / `org:read` (xAI returns `invalid_scope` for User principals). Device login now issues a code at `accounts.x.ai/oauth2/device`. Use `oscar auth login` or `oscar auth login --device`.
- **Secret storage (root cause of “creds set but tools see nothing”)**: OS keyring alone was unreliable on Linux (Secret Service set-ok / get-empty). Oscar now uses a **native secrets dir** `~/.config/oscar/secrets/` (dir `0700`, files `0600`) as the authoritative store; OS keychain is an optional mirror. Also fixed empty `AWS_PROFILE=""` breaking AWS CLI validation.
- **Provider switch base_url**: `--provider` / activate no longer keep the previous provider’s URL (e.g. NVIDIA) when switching to Grok/xAI — was causing HTTP 404 on chat.
- **DNS inventory**: `aws.dns.zones.list` no longer overwrites record inventory with empty zones; incomplete (0-record) cache triggers live re-sync for pattern search.
- **`tools_search` soft ranking**: long multi-token queries no longer AND-fail to 0 hits (e.g. hosted zones + inventory).
- **`aws.dns.zones.list`**: live Route 53 list (not cache-only); empty results include account id + wrong-account guidance.
- **Named AWS profiles** (e.g. `aws-vdms`): refuse silent ambient default credentials; require profile-scoped secrets.

- **SSE streaming + chat→agent loop** (Grok Build / OpenCode patterns):
  - Provider SSE uses `eventsource-stream` with UTF-8 BOM strip, multi-line `data:` join, and clean transport-error termination
  - OpenAI-compat streams always flush `ToolCallDone` + `MessageStop` at finish **or** stream end (tools no longer drop when proxies omit `finish_reason`)
  - Force `finish_reason=tool_calls` when tool fragments were received (Grok Build override)
  - Agent loop simplified: run tools whenever finalized tool calls exist; cancel/error end the turn cleanly
  - Hardened shared HTTP client (connect timeout, keepalive, full error chains) — fixes opaque `error sending request` failures
  - Stream **idle timeout** (90s) aborts hung SSE
  - **Prompt queue** while a turn is busy (auto-dequeue on Done)
  - **`oscar serve`** local SSE event bus for testing (`GET /event`, `POST /prompt`)
  - **SSE hub starts with TUI** by default (`[sse]` config); **watchdog** restarts the listener on failure
  - **TUI no longer corrupted by SSE/logging**: quiet SSE mode + tracing to `~/.config/oscar/logs/oscar.log` (stderr was painting over alt-screen)
  - Slash Enter with args (`/model list`) submits the full line instead of menu-complete wiping args
  - **`/model list` no longer freezes the TUI**: catalog/model list runs in `spawn_blocking` (blocking models.dev HTTP was stalling the async runtime)
  - **Host events no longer wiped**: same-session `load_transcript` re-push no longer clears live chat/SSE notices; session apply runs before event apply
  - **TUI Enter → host delivery**: event loop no longer blocks the tokio worker with `crossterm::event::poll(50ms)`; drains input with non-blocking poll and `await`s a short sleep so the chat host can run (TUI sends were succeeding while host `recv` never fired)
  - Unbounded user channel + fair host `select!` (no `biased`) so slash/chat cannot be starved by transcript/config arms
  - **`/model` list readable again**: multi-line host notices are one ChatLine per row (embedded `\\n` jammed the whole catalog into one ratatui line and broke scroll)
  - **xAI/Grok model catalog**: merge models.dev + static flagships (`grok-4.5`, `grok-4.3`, `grok-4`, …); media models sorted last and tagged; status bar updates on `/model` switch
  - **Chat layout (Grok Build–style)**: manual width wrap (no body folding under role chrome); `❯` user turns; plain indented assistant; `◆ Thought` + `┃` rail; tools as `┃ ◆` / `❙ ✓` cards; bottom/right padding
  - **Multi-account targeting (hard rules)**: ask cloud/account when unspecified; named missing accounts → `system.access.prepare` + secure bar (never DNS on a substitute profile); multi-profile tools refuse silent default; access.review returns `TARGET_MISSING→prepare`
  - Unit tests for SSE reassembly and tool-call finalization without finish_reason

### Added

- **OpenCode-aligned provider system** ([docs/PROVIDER-PLAN.md](docs/PROVIDER-PLAN.md)):
  - **AuthStore** `~/.config/oscar/auth.json` (0600) with typed `api` \| `oauth` credentials
  - **models.dev catalog** (cached) for provider/model discovery + base URLs
  - **`oscar auth connect|list|remove`** and TUI **`/connect`**
  - Catalog-driven **Provider** pane (OpenRouter, Groq, DeepSeek, Together, Mistral, …)
  - Config: `[auth]` (`mirror_keychain`, `allow_catalog_env`), `[catalog]` filters
  - Secrets never in `config.toml`; optional OS keychain mirror
- **Settings → Raw config:** scrollable effective `config.toml` TOML viewer (path + disk/in-memory status; API keys never appear — keychain only)
- **Controllable chat pane + clipboard (Grok Build–style):** Tab focuses scrollback vs prompt; ↑↓ select lines; Shift+↑↓ extend highlight; `y` / Enter / Ctrl+Y copy; Ctrl+V paste; mouse click/drag select + wheel scroll; `/copy` [n|path]; OSC 52 + native clipboard + `~/.config/oscar/last-copy.txt` backup
- **Grok primary + OAuth:** `oscar auth login` / `--device`; tokens in `auth.json` + keychain; docs in `docs/AUTH-GROK.md`
- **Multi-provider models:** `[providers.*]` slots keep several providers loaded; **`/model`** lists and switches across all loaded providers (`/model 3`, `/model openai/gpt-4o`)

### Planned

- apt packages
- Windows MSI (zip already shipping)
- Optional IDE local SSE server (post-v0)
- Deeper multi-hop: auto-chain live path analyzers after locate (orchestrate currently inventory-only)
- LLM turn-summarization during compaction (fold/trim already ship)

## [0.1.3] — 2026-07-27

Downloadable multi-arch GitHub Release with **multi-profile access** (test this build for account pivot + secure paste).

### Added

- **Multi-profile access pivot:** `system.access.prepare` (per-account profile + short-lived secure paste/SSO), `system.access.review` (usable creds without values), `system.access.select` (session preferred profile), `system.profiles.list`
- Session `preferred_profile_id` — tools that omit `profile_id` target the active account
- **CSP-distinct profiles:** ids `aws-*` / `gcp-*` / `azure-*` / `k8s-*`, `[AWS]`/`[GCP]`/`[AZURE]` tags, account_kind labels, lists grouped by cloud
- Secure bar: multi-field short-term paste (access/secret/session); resume only when all fields stored; agent never sees secret values
- AWS ambient CLI only reused when STS account matches profile `account_ref` (no silent cross-account)
- `dns.resolve.public`; one-time legacy config dir import into `~/.config/oscar`

### Fixed

- Windows binary PATH probe (unix permissions gated); release publish proceeds when Linux builds succeed
- CI CLI smoke broken-pipe panic with `head`

## [0.1.2] — 2026-07-27

Packaging baseline (tag may not have published artifacts). Prefer **v0.1.3**.

### Added

- `dns.resolve.public` — host system resolver A/AAAA for a FQDN (public Internet)
- One-time config import from pre-rebrand config dir when oscar is empty

### Changed

- Docs: MCP transport row reflects OAuth PKCE + DCR as shipped
- `oscar-k8s` crate description matches live CNI tooling

## [0.1.1] — 2026-07-27

### Changed

- **Rebrand:** product and CLI renamed to **`oscar`**. Crates `oscar-*`, binary `oscar`, config `~/.config/oscar`, keychain service `oscar`, repository [JacksonJRay/oscar](https://github.com/JacksonJRay/oscar).

### Added

- Live DNS write tools (mode-gated): `aws|gcp|azure.dns.record.create` / `.delete` (alias + CAA)
- Live k8s write: `k8s.resource.create` (`kubectl apply`) / `k8s.resource.delete`
- **Native Anthropic Messages API** provider (SSE stream, tools, extended thinking)
- MCP HTTP/SSE transport; OAuth PKCE + refresh + dynamic client registration; `oscar mcp auth|set-token|logout|reload`
- In-session MCP remount (`/mcp reload`)
- Tool audit log (`logs/tool_audit.jsonl`)
- Multi-hop: `multicloud.path.narrative` + `multicloud.path.orchestrate`
- Plugin tools (`~/.config/oscar/plugins/*.toml`)
- Packaging: Linux + macOS + Windows GitHub Releases, Homebrew formula template, Nix flake
- Streaming cancel/reconnect policy docs (`docs/STREAMING.md`)

## [0.1.0] — 2026-07-27

First public Linux binary release of the multi-cloud dredger CLI.

### Added

- Agentic CLI with Ratatui TUI chat and headless `oscar ask` / `oscar ask --stream`
- Code Mode inventory: agent surface is `tools_search` + `tools_execute` only
- Multi-cloud tools for AWS, GCP, Azure, and Kubernetes (DNS, network, path, IAM, CNI)
- Unified inventory sync (`oscar inventory`) and pattern discovery tools
- MCP servers as first-class Code Mode tools (`mcp.<server>.<tool>`), not dumped into the system prompt
  - stdio transport, `oscar mcp` CLI (list/add/doctor/presets/install), project `.oscar/config.toml` merge
  - Write capability inference, `${VAR}` config expansion, result spill for large outputs
- Grok Build–style sessions (`oscar sessions`, `/history` `/new` `/resume`)
- Context manager with live meter, auto-compact at **85%** of full context window, soft-trim, `/compact [keep note]`, compaction checkpoints
- Auth: OS keychain LLM keys, cloud SSO / short-lived AWS keys, binary session detection; secrets never enter chat
- Settings, identities, skills, binaries install policy
- Linux GitHub Release packaging (x86_64 + aarch64 gnu tarballs + checksums)

### Security

- Read-only mode by default; write tools hard-gated
- Deep redaction of secrets in tool results and events

[Unreleased]: https://github.com/JacksonJRay/oscar/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/JacksonJRay/oscar/compare/v0.1.3...v0.2.0
[0.1.1]: https://github.com/JacksonJRay/oscar/releases/tag/v0.1.1
[0.1.0]: https://github.com/JacksonJRay/oscar/releases/tag/v0.1.0

# oscar

**Multi-cloud Native Dredger** — an agentic CLI for troubleshooting across AWS, GCP, Azure, and Kubernetes.

`oscar` is a Rust-first, Ratatui-powered engineering assistant that diagnoses infrastructure, network, DNS, access, account, and cluster issues. It prefers each cloud’s native tooling under the hood and exposes a small, stable agent surface (search + execute) so the tool inventory can grow without exploding the model context window.

## Highlights

- **Agentic first** — full-screen chat TUI or headless (`oscar ask`)
- **Multi-cloud** — AWS, GCP, Azure (+ K8s cluster pivoting)
- **Code Mode inventory** — agent uses `tools.search` + `tools.execute` against a typed registry
- **Read-only by default** — hard mode gate regardless of credential power
- **Secure credentials** — OS keychain storage; TUI input bar flips to masked secret entry
- **SSE streaming** — live content + thinking channels
- **Context management** — live usage meter, auto/manual compaction
- **Provider strategy** — Claude, xAI, OpenAI, OpenCode Zen/Go

Architecture and patterns are **inspired by** [Grok Build](https://github.com/xai-org/grok-build) (agent harness, TUI, headless), reimplemented for multi-cloud ops rather than forked.

## Status

`v0.1.3` usable dredger: agent harness, pattern discovery, multi-cloud DNS/network live inventory, path analyzers, IAM access tools, k8s/CNI helpers, settings/identities TUI, skills, **Grok-style auto-compact (85%)**, and **MCP servers mounted as first-class Code Mode tools** (search/execute — not dumped into context). Config is **TOML** at `~/.config/oscar/config.toml`.

## Install

### Linux binary (GitHub Releases)

```bash
# latest x86_64 / aarch64
curl -fsSL https://raw.githubusercontent.com/JacksonJRay/oscar/main/scripts/install-linux.sh | bash
oscar --version
```

Or download directly:

| Arch | Latest |
|---|---|
| x86_64 | [oscar-x86_64-unknown-linux-gnu.tar.gz](https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-x86_64-unknown-linux-gnu.tar.gz) |
| aarch64 | [oscar-aarch64-unknown-linux-gnu.tar.gz](https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-aarch64-unknown-linux-gnu.tar.gz) |

Releases & notes: [github.com/JacksonJRay/oscar/releases](https://github.com/JacksonJRay/oscar/releases) · [CHANGELOG](CHANGELOG.md) · [tagging strategy](docs/RELEASING.md)

### From source

```bash
cargo install --path crates/oscar-cli --locked
oscar --help
```

Full prerequisites, first-run auth, MCP presets, and packaging notes: [docs/INSTALL.md](docs/INSTALL.md).

## Auth, providers & agent-safe secrets

```bash
oscar --help
oscar tools catalog                    # Code Mode docs the agent receives
oscar provider list | status | set grok
oscar auth login                       # Grok OAuth (browser) — primary
oscar auth login --device              # Grok OAuth for SSH / headless
oscar auth policy
oscar auth provider-key --provider grok --key-file ~/.oscar-xai.key
oscar auth aws-sso-login [--aws-profile NAME]    # browser SSO; keys never enter chat
oscar auth gcloud-login [--adc]
oscar auth az-login [--tenant TID]
oscar auth aws-session / aws-assume-role / aws-keys …
oscar auth aws-test --profile aws-default
oscar binaries
```

In chat: **`/model`** lists models across all **loaded** providers; `/model 3` or `/model openai/gpt-4o` switches without unloading others. Details: [docs/AUTH-GROK.md](docs/AUTH-GROK.md).

**Isolation guarantee:** raw credentials never enter the model transcript. Secure TUI paste and `oscar auth` write to the OS keychain or CSP CLI SSO only; tool results are deep-redacted (`***REDACTED***`). Built-in LLM providers **do not** read `XAI_API_KEY` / `OPENAI_API_KEY` unless `provider.api_key_env` is set for a **custom** provider.

## TUI

`oscar` opens a chat **output panel** (user / agent / tools / system) and a bottom **input bar** with slash commands (`/model`, `/settings`, `/identities`, `/skills`, `/help`, …) — same shape as Grok Build.

## MCP (first-class, not in system prompt)

```bash
oscar mcp example
oscar mcp add mock -- python3 scripts/mock_mcp_server.py
oscar mcp doctor
oscar tools search mcp          # finds mcp.mock.echo etc.
```

See [docs/MCP-PLAN.md](docs/MCP-PLAN.md). Config is TOML under `[mcp]` / `[mcp.servers.*]`.

## Pattern discovery (first-class)

Native CSP APIs are weak at “find anything matching X”. oscar exposes **pattern search** tools so the agent does not burn tokens on multi-step list+filter plans:

| Intent | Tool ids |
|---|---|
| Where does this DNS name live? | `dns.where`, `dns.pattern.find` |
| DNS partial/glob in one cloud | `aws.dns.pattern.search`, `gcp.dns.pattern.search`, `azure.dns.pattern.search` |
| Subnet / VPC / IP fragment | `network.pattern.find`, `*.network.pattern.search`, `*.network.subnet.pattern`, `*.network.ip.locate` |
| K8s by name/label/IP | `k8s.resources.pattern.search`, `k8s.pods.pattern.search`, `k8s.services.pattern.search` |

**Match modes:** `partial` (default), `prefix`, `suffix`, `exact`, `glob` (`*`, `?`), `ip_or_cidr` (auto-inferred for `10.0.4`, `10.0.0.0/16`, etc.).

**Inventory cache** (live sync fills these):  
`~/.config/oscar/cache/<profile_id>/dns.json`  
`~/.config/oscar/cache/<profile_id>/network.json` (or `network-<region>.json`)  
`~/.config/oscar/cache/k8s/<context>.json`

```bash
oscar inventory status
oscar inventory seed-fixture --profile aws-fixture   # offline NetworkInventory
oscar inventory sync --cloud aws --kind network --region us-east-1
oscar inventory sync --cloud aws --kind dns
```

Create / delete / modify tools are registered with **write** capability (blocked in default readonly mode).

## Build

```bash
cargo build -p oscar-cli
cargo run -p oscar-cli -- --help
```

## CLI (planned / partial)

```
oscar                     # open TUI chat
oscar ask "..."           # headless one-shot
oscar ask --stream "..."  # NDJSON event stream
oscar mode show|set
oscar profiles list|add
oscar tools list|search
oscar provider list|set
oscar compact
```

## License

Apache-2.0

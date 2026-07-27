# Changelog

All notable changes to **oscar** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Release artifacts (Linux) are attached to GitHub Releases:

- Latest: <https://github.com/JacksonJRay/oscar/releases/latest>
- Tags: `vMAJOR.MINOR.PATCH` (see [docs/RELEASING.md](docs/RELEASING.md))

## [Unreleased]

### Planned

- apt packages
- Windows MSI (zip already shipping)
- Optional IDE local SSE server (post-v0)
- Deeper multi-hop: auto-chain live path analyzers after locate (orchestrate currently inventory-only)
- LLM turn-summarization during compaction (fold/trim already ship)

## [0.1.2] — 2026-07-27

First downloadable GitHub Release for the **oscar** product (Linux x86_64 + aarch64 gnu, plus macOS/Windows in the same pipeline).

### Added

- `dns.resolve.public` — host system resolver A/AAAA for a FQDN (public Internet)
- One-time config import: if `~/.config/oscar` has no config/profiles but the pre-rebrand config dir exists, copy metadata (sessions, TOML, caches). Keychain secrets are **not** moved — re-run `oscar auth` as needed.

### Changed

- Docs: MCP transport row reflects OAuth PKCE + DCR as shipped
- `oscar-k8s` crate description matches live CNI tooling (no longer “stub”)

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

[Unreleased]: https://github.com/JacksonJRay/oscar/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/JacksonJRay/oscar/releases/tag/v0.1.1
[0.1.0]: https://github.com/JacksonJRay/oscar/releases/tag/v0.1.0

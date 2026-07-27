# Installing oscar

## Download from GitHub Releases (Linux)

Prebuilt Linux binaries are published on every `v*` tag:

- **Latest release:** <https://github.com/JacksonJRay/oscar/releases/latest>
- **Changelog:** [CHANGELOG.md](../CHANGELOG.md)
- **Tagging / maintainer docs:** [RELEASING.md](./RELEASING.md)

### One-liner

```bash
curl -fsSL https://raw.githubusercontent.com/JacksonJRay/oscar/main/scripts/install-linux.sh | bash
```

### Direct links (copy/paste)

| Arch | Latest download |
|---|---|
| **x86_64** | <https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-x86_64-unknown-linux-gnu.tar.gz> |
| **aarch64** | <https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-aarch64-unknown-linux-gnu.tar.gz> |
| Checksums | <https://github.com/JacksonJRay/oscar/releases/latest/download/SHA256SUMS> |

```bash
# x86_64 example
curl -fL -o oscar.tgz \
  https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-x86_64-unknown-linux-gnu.tar.gz
tar -xzf oscar.tgz
sudo install -m 755 oscar /usr/local/bin/oscar
oscar --version
```

Pinned version (replace `v0.1.3`):

```text
https://github.com/JacksonJRay/oscar/releases/download/v0.1.3/oscar-v0.1.3-x86_64-unknown-linux-gnu.tar.gz
https://github.com/JacksonJRay/oscar/releases/download/v0.1.3/oscar-x86_64-unknown-linux-gnu.tar.gz
```

## Prerequisites

- Prebuilt binary: **glibc Linux** (gnu target) on x86_64 or aarch64
- From source: **Rust** 1.75+ — [rustup](https://rustup.rs/)
- Optional CSP CLIs (tools degrade gracefully when missing):
  - `aws` (AWS CLI v2)
  - `gcloud`
  - `az`
  - `kubectl`
- Optional for MCP stdio presets: **Node.js + npx**

## Install from source

```bash
# From the oscar repo root
cargo install --path crates/oscar-cli --locked

# Or build without installing
cargo build -p oscar-cli --release
# binary: target/release/oscar
```

Add `~/.cargo/bin` to your `PATH` if needed.

Local packaging smoke (same layout as CI):

```bash
./scripts/package-linux.sh
```

Verify:

```bash
oscar --help
oscar provider list
oscar tools catalog
```

## First-time config

Config lives at `~/.config/oscar/config.toml` (created on first run / save).

```bash
# Pick a provider (xAI / OpenAI-compat / custom gateway)
oscar provider set xai
oscar auth provider-key --provider xai --key-file ~/.oscar-xai.key

# Cloud sessions (secrets stay in keychain / CSP SSO — never in chat)
oscar auth aws-sso-login
oscar auth gcloud-login
oscar auth az-login

oscar identities check
```

Project overlay (optional): `.oscar/config.toml` walked up from cwd merges into user config (MCP servers, etc.).

## MCP servers (Code Mode)

MCP tools are **not** dumped into the system prompt. They mount as `mcp.<server>.<tool>` via `tools_search` / `tools_execute`.

```bash
oscar mcp presets
oscar mcp install filesystem          # cwd as allowed root
oscar mcp install git -- /path/to/repo
oscar mcp doctor
oscar tools search mcp
```

See [MCP-PLAN.md](./MCP-PLAN.md).

## Homebrew

```bash
# After a release with real sha256 in Formula/oscar.rb:
brew install --formula https://raw.githubusercontent.com/JacksonJRay/oscar/main/Formula/oscar.rb
# or tap this repo:
# brew tap JacksonJRay/oscar https://github.com/JacksonJRay/oscar && brew install oscar
```

Update `url` / `sha256` in [`Formula/oscar.rb`](../Formula/oscar.rb) from the release `SHA256SUMS` when cutting tags.

## Packaging notes

| Method | Status |
|---|---|
| GitHub Releases (Linux x86_64 / aarch64) | Supported — tag `v*` |
| GitHub Releases (macOS Intel / Apple Silicon) | Supported — tag `v*` |
| GitHub Releases (Windows x86_64 zip) | Supported — tag `v*` |
| Homebrew formula | Template in `Formula/oscar.rb` (fill sha256 per release) |
| `scripts/install-linux.sh` | Supported |
| `cargo install --path crates/oscar-cli` | Supported |
| Nix flake (`nix build` / `nix run`) | Supported (`flake.nix`) |
| apt / Windows MSI | Not yet |

### Plugins (third-party tools)

```bash
mkdir -p ~/.config/oscar/plugins
# see docs/plugins/example-echo.toml or: oscar mcp plugin-example
oscar tools search plugin
```

Maintainers: see [RELEASING.md](./RELEASING.md) for SemVer tags and the release checklist.

## Uninstall

```bash
# binary install
sudo rm -f /usr/local/bin/oscar
# or: rm -f ~/.local/bin/oscar

cargo uninstall oscar-cli   # if installed via cargo install
# remove config (optional):
# rm -rf ~/.config/oscar
```

## Troubleshooting

| Symptom | Check |
|---|---|
| No LLM responses | `oscar provider status`, keychain key via `oscar auth` |
| Empty inventory | `oscar inventory sync --cloud aws --kind dns` (needs CLI auth) |
| MCP tools missing | `mcp.enabled = true`, `oscar mcp doctor`, restart chat after config change |
| Write tools blocked | Default mode is **read-only**; switch mode / enable readwrite |

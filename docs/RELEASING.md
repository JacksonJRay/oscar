# Releasing oscar

## Tagging strategy (SemVer)

| Tag form | Meaning | Example |
|---|---|---|
| `vMAJOR.MINOR.PATCH` | Stable release | `v0.1.0`, `v1.0.0` |
| `vMAJOR.MINOR.PATCH-rc.N` | Release candidate (pre-release) | `v0.2.0-rc.1` |
| `vMAJOR.MINOR.PATCH-beta.N` | Beta (pre-release) | `v0.2.0-beta.1` |

Rules:

1. **Always prefix with `v`.** Tags must match `v*` so [`.github/workflows/release.yml`](../.github/workflows/release.yml) runs.
2. **Tag version = Cargo workspace version.** Before tagging, set `[workspace.package].version` in root `Cargo.toml` to `MAJOR.MINOR.PATCH` (no `v` prefix in Cargo).
3. **SemVer for the CLI binary API / flags / config:**
   - **MAJOR** — breaking CLI flags, config keys, or tool-id renames that break scripts
   - **MINOR** — new tools/commands/features, backward compatible
   - **PATCH** — fixes, docs, packaging only
4. **Pre-release tags** create a GitHub pre-release (`prerelease: true` when the tag contains `-`).
5. **Do not retag / force-push tags** that already have published assets. Bump and ship a new version.
6. Tags should point at `main` (or a release branch) after changelog + version bump are merged.

## Changelog

- Maintain [CHANGELOG.md](../CHANGELOG.md) (Keep a Changelog).
- For each release:
  1. Move items from `## [Unreleased]` into `## [X.Y.Z] — YYYY-MM-DD`.
  2. Update compare links at the bottom of the file.
- The release workflow attaches the matching `## [X.Y.Z]` section as the GitHub Release body (plus a download blurb).

## Cut a release (maintainers)

```bash
# 1. Clean tree on main
git checkout main && git pull

# 2. Version + changelog
#    Edit Cargo.toml [workspace.package] version = "X.Y.Z"
#    Edit CHANGELOG.md (Unreleased → [X.Y.Z])

git add Cargo.toml CHANGELOG.md Cargo.lock
git commit -m "Release vX.Y.Z"

# 3. Tag (annotated)
git tag -a "vX.Y.Z" -m "oscar vX.Y.Z"

# 4. Push commit + tag (triggers Linux build + GitHub Release)
git push origin main
git push origin "vX.Y.Z"
```

Watch: **Actions → Release** on the tag. When green, assets appear on:

```text
https://github.com/JacksonJRay/oscar/releases/tag/vX.Y.Z
https://github.com/JacksonJRay/oscar/releases/latest
```

## Download URLs (stable templates)

Replace `VERSION` with e.g. `v0.1.0`, or use `latest`:

| Artifact | URL |
|---|---|
| Linux x86_64 (gnu) | `…/oscar-VERSION-x86_64-unknown-linux-gnu.tar.gz` |
| Linux aarch64 (gnu) | `…/oscar-VERSION-aarch64-unknown-linux-gnu.tar.gz` |
| macOS arm64 | `…/oscar-VERSION-aarch64-apple-darwin.tar.gz` |
| macOS x86_64 | `…/oscar-VERSION-x86_64-apple-darwin.tar.gz` |
| Checksums | `…/SHA256SUMS` |
| Latest Linux x86_64 | `…/latest/download/oscar-x86_64-unknown-linux-gnu.tar.gz` |
| Latest macOS arm64 | `…/latest/download/oscar-aarch64-apple-darwin.tar.gz` |

Base: `https://github.com/JacksonJRay/oscar/releases/download/VERSION/`

> **Note:** `latest/download/…` uses **stable names** (no version in the filename). Versioned tags also upload versioned tarball names for reproducibility.

## Local package smoke (optional)

```bash
./scripts/package-linux.sh
# → dist/oscar-<version>-<target>.tar.gz + SHA256SUMS
```

## Install from a release

```bash
# One-liner (x86_64 Linux)
curl -fsSL https://raw.githubusercontent.com/JacksonJRay/oscar/main/scripts/install-linux.sh | bash

# Manual
curl -fL -o oscar.tgz \
  https://github.com/JacksonJRay/oscar/releases/latest/download/oscar-x86_64-unknown-linux-gnu.tar.gz
tar -xzf oscar.tgz
sudo install -m 755 oscar /usr/local/bin/oscar
oscar --version
```

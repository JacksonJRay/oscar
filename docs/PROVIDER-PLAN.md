# Provider system rework (OpenCode-aligned)

## Goal

Rework oscar’s LLM provider system using OpenCode patterns:

1. **Unified AuthStore** — `~/.config/oscar/auth.json` (mode `0600`), typed `api` | `oauth` entries
2. **models.dev catalog** — dynamic provider/model list with disk cache + static fallback
3. **Connect flow** — `/connect` + `oscar auth connect` over the full catalog
4. **Secure resolve** — secrets never in `config.toml` or chat; keychain mirror optional

Inspired by OpenCode (`Auth` store, models.dev, `/connect`) but hardened for oscar’s keychain-first posture.

## Status: **shipped (v1)**

All phases below are implemented. Non-goals remain out of scope.

## Architecture

```
/connect · /model · oscar auth …
            │
            ▼
   oscar-providers registry
     ├─ CatalogService (models.dev + fallback + allow/deny filters)
     └─ AuthStore (auth.json 0600 + optional keychain mirror)
            │
            ▼
   OpenAiCompat / Anthropic / xAI OAuth
```

### Credential resolve order

1. AuthStore OAuth access token (refresh if needed)
2. AuthStore API key
3. OS keychain `oscar/provider/<id>` (legacy + mirror)
4. Explicit `provider.api_key_env` only
5. Catalog env vars (`XAI_API_KEY`, …) **only if** `auth.allow_catalog_env = true`

### Auth file schema (v1)

```json
{
  "version": 1,
  "providers": {
    "xai": {
      "type": "oauth",
      "access": "…",
      "refresh": "…",
      "expires": 1710000000,
      "client_id": "…",
      "issuer": "https://auth.x.ai",
      "auth_mode": "browser"
    },
    "openai": { "type": "api", "key": "sk-…" }
  }
}
```

Legacy xAI-only files (`access_token` without `type`) are read and rewritten on save.

## Task board

### Phase 0 — Design
- [x] Author this plan
- [x] Point AUTH-GROK at multi-provider AuthStore

### Phase 1 — AuthStore
- [x] `AuthEntry` + versioned file, atomic 0600 writes
- [x] Legacy OAuth migration
- [x] set_api_key / set_oauth / remove / list / has_credentials
- [x] Resolve: auth.json → keychain → optional env
- [x] Wire factory + provider-key / OAuth login through AuthStore
- [x] Dual-write API keys to keychain (mirror) + `auth.mirror_keychain` flag

### Phase 2 — models.dev Catalog
- [x] Fetch + cache + TTL + offline fallback
- [x] Catalog types + static builtin fallback
- [x] catalog_models / list_provider_ids catalog-backed
- [x] Config `[catalog]` / `[auth]` settings
- [x] `enabled_providers` / `disabled_providers` filters
- [x] `list_provider_ui_meta` for TUI/settings

### Phase 3 — Factory
- [x] Backend from catalog npm/id + base URL from catalog
- [x] OpenAI-compat generics for catalog providers
- [x] Keep Anthropic + xAI OAuth special cases
- [x] `create_provider_from_oscar_config` / `_sync` entry points
- [x] `connect_api_key` respects mirror policy

### Phase 4 — Connect UX
- [x] CLI: `oscar auth connect|list|remove`
- [x] `/connect` slash command
- [x] Provider pane catalog-aware (OpenRouter, Groq, DeepSeek, …)
- [x] Settings provider enum expanded + AuthStore credential check
- [x] `/model` fills `base_url` from catalog when switching

### Phase 5 — Hardening
- [x] Docs (AUTH-GROK, README, CHANGELOG)
- [x] Unit tests for AuthStore + catalog parse + factory connect/resolve
- [x] cargo test oscar-providers + oscar-core green

## User guide (quick)

```bash
# Grok OAuth
oscar auth login

# Any OpenAI-compatible provider from models.dev
oscar auth connect                         # list
oscar auth connect openrouter --key-file ~/.key
oscar auth list
oscar auth remove --provider openrouter

# Chat
/connect openrouter
/model list
/model openrouter/<model-id>
/provider                                  # full picker + secure paste
```

```toml
[auth]
mirror_keychain = true
allow_catalog_env = false

[catalog]
enabled = true
# enabled_providers = ["xai", "openai", "openrouter"]
# disabled_providers = ["amazon-bedrock"]
```

Env: `OSCAR_MODELS_URL`, `OSCAR_DISABLE_MODELS_FETCH=1`, `OSCAR_AUTH_CONTENT` (CI inject).

## Non-goals (v1)

- Full AI SDK (Bedrock chain, Vertex ADC, 30 packages)
- Claude Pro / ChatGPT subscription OAuth plugins
- Cloud CSP secrets in LLM auth.json
- Moving auth path to XDG data dir (OpenCode uses `~/.local/share`)

## Success criteria

1. `/connect` or `oscar auth connect openrouter` + key → `/model` works
2. Grok OAuth unchanged in UX
3. No keys in config.toml / logs / chat
4. Offline fallback for core providers
5. Keychain-only users still resolve
6. Tests green for oscar-providers / oscar-core

## Code map

| Module | Role |
|--------|------|
| `oscar-providers/auth_store.rs` | Unified typed credentials |
| `oscar-providers/catalog.rs` | models.dev + static fallback + UI meta |
| `oscar-providers/factory.rs` | Resolve + build OpenAI-compat / Anthropic / xAI |
| `oscar-providers/xai_oauth.rs` | Grok OAuth → AuthStore |
| `oscar-tui/provider_pane.rs` | Catalog-driven connect UI |
| `docs/AUTH-GROK.md` | User-facing multi-provider auth |

## References

- OpenCode Auth: `packages/opencode/src/auth/index.ts`
- OpenCode providers: `packages/opencode/src/provider/provider.ts`
- models.dev: https://models.dev/api.json
- Docs: https://opencode.ai/docs/providers/

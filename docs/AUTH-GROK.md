# Grok (xAI) auth & multi-provider models

Grok is oscar’s **primary** LLM provider. You can load **several providers at once** and switch models without unloading the others.

> **Full design:** [PROVIDER-PLAN.md](./PROVIDER-PLAN.md) — OpenCode-aligned AuthStore, models.dev catalog, `/connect`.

## Credential storage (AuthStore)

All LLM credentials use a unified store (OpenCode-style):

| Path | Contents |
|------|----------|
| `~/.config/oscar/auth.json` | Typed entries `api` \| `oauth` (mode `0600`) |
| OS keychain `oscar/provider/<id>` | Optional mirror of API / access tokens |

Secrets never go in `config.toml` or the chat transcript.

## Grok SuperGrok OAuth (subscription — recommended)

Uses your **SuperGrok / Grok Build subscription** via SpaceXAI OAuth at `auth.x.ai`.
Sign in with **Google** (or other IdP linked to your SuperGrok account).

**This is not an API key.** Do **not** use `oscar auth connect xai --key-file` for SuperGrok
subscription models — that path is pay-as-you-go console keys only.

```bash
# Desktop — browser PKCE (may open accounts.x.ai; complete Google sign-in there)
oscar auth login

# Headless / SSH / when browser automation is Cloudflare-blocked
oscar auth login --device
# → open https://accounts.x.ai/oauth2/device
# → enter the printed code
# → continue with Google login if prompted
# → approve Grok Build access
```

Scopes used (User principals — do not add team/org scopes):

```text
openid profile email offline_access api:access grok-cli:access
```

When an OAuth entry exists for `xai`, oscar uses the **OAuth access token only**
for Grok/xAI chat — it will **not** fall back to a payg API key.

**Logout**

```bash
oscar auth logout
# or remove any provider:
oscar auth remove --provider xai
```

**Status**

```bash
oscar auth status   # should show type=oauth for grok/xai
oscar auth list
oscar provider status
```

### After login

```bash
oscar provider set grok
# In chat:
/model list
/model grok-build-0.1   # subscription Build model when available
/model grok-4.5
```

## Connect any provider (OpenCode-style)

```bash
# List catalog (models.dev + builtins)
oscar auth connect
oscar auth connect --search openrouter

# Store API key (AuthStore + keychain mirror)
oscar auth connect openrouter --key-file ~/.openrouter.key
oscar auth connect openai --key-file ~/.openai.key
oscar auth connect anthropic --key-file ~/.anthropic.key

# Same as provider-key:
oscar auth provider-key --provider grok --key-file ~/.oscar-xai.key
```

In the TUI:

```text
/connect              # list providers
/connect openrouter   # filter
/provider             # paste key via secure bar
/model list
```

Env vars like `XAI_API_KEY` are **not** read unless you set `provider.api_key_env` or `auth.allow_catalog_env = true` in config.

## Multi-provider slots

```toml
[provider]
id = "grok"
model = "grok-4"

[providers.grok]
model = "grok-4"

[providers.openai]
model = "gpt-4o"

[auth]
mirror_keychain = true
allow_catalog_env = false

[catalog]
enabled = true
```

## Slash reference

| Command | Effect |
|---------|--------|
| `/connect [search]` | List connectable providers (models.dev) |
| `/model` / `/models` | List loaded providers and numbered models |
| `/model N` | Activate model #N |
| `/model provider/model` | Explicit provider + model |
| `/provider` | Full provider setup UI |

## CLI reference

```bash
oscar auth login [--device]
oscar auth logout
oscar auth status
oscar auth list
oscar auth connect [provider] [--key-file …] [--search …]
oscar auth remove --provider <id>
oscar auth provider-key --provider <id> --key-file <path>
oscar provider list|status|set <id>
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Not signed in | `oscar auth login` or `login --device` |
| OAuth OK, chat 403 | Use API key path; check SuperGrok tier |
| Token expired | oscar refreshes automatically; if refresh fails, `oscar auth login` again |
| `/model` shows “not authenticated” | `oscar auth connect <id>` then `/model list` |
| Offline / no models.dev | Static builtins still work; set `OSCAR_DISABLE_MODELS_FETCH=1` |

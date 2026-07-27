# Grok (xAI) auth & multi-provider models

Grok is oscar’s **primary** LLM provider. You can load **several providers at once** and switch models without unloading the others.

## Grok OAuth (recommended)

Browser sign-in via SpaceXAI at `auth.x.ai` (same family of flow as Grok Build):

```bash
# Desktop / local terminal — opens browser (PKCE)
oscar auth login

# SSH / headless — print URL + device code
oscar auth login --device
```

**What gets stored**

| Path | Contents |
|------|----------|
| `~/.config/oscar/auth.json` | OAuth access + refresh tokens (mode `0600`) |
| OS keychain `oscar/provider/xai` (+ `grok`) | Mirrored access token for resolve paths |

**Logout**

```bash
oscar auth logout
```

**Status**

```bash
oscar auth status
oscar provider status
```

### Requirements

- Eligible **SuperGrok** / xAI subscription for OAuth API use (xAI may 403 some tiers).
- If OAuth works in the browser but inference returns **403**, use an API key instead (below).

### After login

```bash
oscar provider set grok          # or leave default
# In chat:
/model list
/model grok-4
```

## Grok API key (fallback / CI)

```bash
# Create a key at https://console.x.ai → API Keys
oscar auth provider-key --provider grok --key-file ~/.oscar-xai.key
# alias:
oscar auth provider-key --provider xai --key-file ~/.oscar-xai.key
```

Headless one-shot:

```bash
oscar ask --provider grok --llm-api-key "xai-…" "summarize this repo"
```

Env vars like `XAI_API_KEY` are **not** read unless you set `provider.api_key_env` in config for a custom setup.

## Multi-provider: keep several loaded

1. Authenticate each provider you want (OAuth or key).
2. Each successful auth / set creates a **slot** under `[providers.*]` in `config.toml`.
3. Switch anytime with `/model` — other slots stay loaded.

```bash
oscar auth login                                    # Grok OAuth
oscar auth provider-key --provider openai --key-file ~/.openai.key
oscar auth provider-key --provider anthropic --key-file ~/.anthropic.key
```

In the TUI chat:

```text
/model              # list all loaded providers + models
/model list
/model 3            # pick by number
/model grok-4
/model openai/gpt-4o
/model anthropic claude-sonnet-4-5
/model help
```

Config shape (simplified):

```toml
[provider]
id = "grok"
model = "grok-4"

[providers.grok]
model = "grok-4"

[providers.openai]
model = "gpt-4o"

[providers.anthropic]
model = "claude-sonnet-4-5"
```

## Slash reference

| Command | Effect |
|---------|--------|
| `/model` / `/models` | List loaded providers and numbered models |
| `/model N` | Activate model #N from the list |
| `/model <id>` | Switch to model id (prefers active provider, then any loaded) |
| `/model provider/model` | Explicit provider + model |
| `/provider` | Full provider setup UI |

## CLI reference

```bash
oscar auth login [--device]
oscar auth logout
oscar auth status
oscar auth policy
oscar auth provider-key --provider <id> --key-file <path>
oscar provider list|status|set <id>
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Not signed in | `oscar auth login` or `login --device` |
| OAuth OK, chat 403 | Use API key path; check SuperGrok tier |
| Token expired | oscar refreshes automatically; if refresh fails, `oscar auth login` again |
| `/model` shows “not authenticated” | Auth that provider, then re-run `/model list` |
| Wrong model after switch | `/model list` and pick again; check `oscar provider status` |

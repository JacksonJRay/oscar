# SuperGrok / subscription auth plan (oscar)

Goal: use **account login** (SuperGrok / Grok Build subscription) inside oscar — not only pay-as-you-go API keys — matching OpenCode’s xAI connect flow.

Related: [AUTH-GROK.md](./AUTH-GROK.md), [PROVIDER-PLAN.md](./PROVIDER-PLAN.md), existing `oscar-providers::xai_oauth`.

---

## Why this exists

| Path | What it unlocks | Today in oscar |
|------|-----------------|----------------|
| **API key** (`console.x.ai`) | Pay-as-you-go models on `api.x.ai` | Works (`oscar auth connect xai --key-file …`) |
| **OAuth SuperGrok / X Premium** | Subscription-backed models (incl. **Grok Build** / `grok-build-0.1` and advanced variants) without a separate API key | **Partial** — browser + device OAuth code exists; end-to-end SuperGrok UX not proven |
| **OpenCode Go API key** | Low-cost Go catalog | Key stores; chat needs **billing credits** (tested: `CreditsError`) |
| **NVIDIA NIM** | Free/open models on `integrate.api.nvidia.com` | Works as OpenAI-compat provider |

User intent: log in with **jackson.ray.business@gmail.com** (Chrome profile), use SuperGrok Build subscription from oscar TUI/CLI.

---

## What OpenCode does (reference)

From [x.ai/news/grok-opencode](https://x.ai/news/grok-opencode) and [opencode.ai/docs/providers](https://opencode.ai/docs/providers/) (xAI section):

1. `/connect` → **xAI**
2. Choose:
   - **xAI Grok OAuth (SuperGrok Subscription)** — browser PKCE; callback often `http://127.0.0.1:56121/callback` (OpenCode)  
   - **xAI Grok OAuth (Headless / Remote / VPS)** — device code + URL (any browser)
   - **API key** — console key (pay-as-you-go)
3. Credentials in OpenCode: `~/.local/share/opencode/auth.json`
4. Models picker includes subscription models after OAuth
5. Token refresh is automatic with offline_access

Oscar already mirrors the SpaceXAI OIDC endpoints in `crates/oscar-providers/src/xai_oauth.rs`:

| Constant | Value |
|----------|--------|
| Issuer | `https://auth.x.ai` |
| Authorize | `https://auth.x.ai/oauth2/authorize` |
| Token | `https://auth.x.ai/oauth2/token` |
| Device | `https://auth.x.ai/oauth2/device/code` |
| API | `https://api.x.ai/v1` |
| Public client id | `b1a00492-073a-47ea-816f-4c329264a828` (Grok Build CLI public PKCE client) |
| Scopes | `openid profile email offline_access api:access grok-cli:access team:read org:read` |

CLI:

```bash
oscar auth login           # browser PKCE
oscar auth login --device  # headless device code
oscar auth status
oscar auth logout
```

---

## Gaps vs OpenCode (why SuperGrok “doesn’t work yet”)

1. ~~**Invalid OAuth scopes**~~ — **FIXED 2026-07-28.** Oscar requested `team:read` + `org:read`, which xAI rejects for User principals (`invalid_scope`). Valid scopes: `openid profile email offline_access api:access grok-cli:access`. Device code now succeeds.
2. **Auth mode confusion** — AuthStore may hold `type: api` for `grok`/`xai` and win over OAuth; subscription models then fail or look “not subscribed”. Prefer **valid OAuth** over API key.
3. **Provider id split** — `grok` vs `xai` vs OAuth slot; canonical key is `xai` (normalize aliases).
4. **Model catalog after OAuth** — surface `grok-build-0.1` etc. from `/v1/models` with OAuth bearer.
5. **Login UX in TUI** — `/connect` should offer SuperGrok browser / device / API key.
6. **Browser automation vs Cloudflare** — chrome-devtools / Bot traffic to `accounts.x.ai` often gets **Cloudflare blocked**; real user browser required for consent.
7. **Callback port** — oscar uses ephemeral loopback `127.0.0.1:<port>/callback` for PKCE; device flow preferred for remote.
8. **Refresh / expiry** — OpenCode tokens can be stale; refresh must work; surface re-login on `invalid_grant`.
9. **Grok.com subscribe page** — purchase SuperGrok outside oscar; oscar only does OAuth after.

---

## Target UX

### CLI

```bash
# Preferred: subscription
oscar auth login                 # browser → SuperGrok
oscar auth login --device        # headless
oscar auth status                # shows oauth email + expiry + mode=subscription

# Fallback
oscar auth connect xai --key-file ~/.xai.key

# Switch models
oscar provider set grok
# or TUI: /model list  →  grok-build-0.1 / grok-4.5 …
```

### TUI

```
/connect xai
  1) SuperGrok OAuth (browser)
  2) SuperGrok OAuth (device code)
  3) API key
```

After OAuth: status line `grok · oauth · you@domain · SuperGrok` (no key echoed).

---

## Implementation phases

### Phase A — Inventory & prove current OAuth (1–2 days)

- [ ] Document current `xai_oauth` flows vs OpenCode (this doc)
- [ ] `oscar auth logout` then `oscar auth login` on a machine with browser
- [ ] Chrome: sign in as subscription account; complete consent
- [ ] Capture: tokens stored as `oauth`, `/v1/models` with access token, chat `grok-build-0.1`
- [ ] If login fails: capture authorize URL query params, redirect URI, error from token endpoint
- [ ] Device flow: `oscar auth login --device` + phone browser

**Chrome profile testing (user machine):**  
Use Chrome profile for `jackson.ray.business@gmail.com` → open authorize URL from CLI → complete consent → confirm callback hits oscar loopback.

### Phase B — Auth precedence & TUI parity (2–3 days)

- [ ] Precedence: valid OAuth > API key for xAI family
- [ ] `/connect` multi-method for xAI
- [ ] Status distinguishes `oauth (subscription)` vs `api (payg)`
- [ ] Clear errors when API key used but user expected subscription-only models

### Phase C — Subscription model catalog (1–2 days)

- [ ] After OAuth, refresh live models from `api.x.ai/v1/models`
- [ ] Prefer/pin `grok-build-0.1` when present
- [ ] Label models with `subscription` vs `api` capability when known

### Phase D — Hardening (ongoing)

- [ ] Refresh race conditions, clock skew
- [ ] Revoke/logout clears keychain + auth.json
- [ ] Optional: fixed callback port config for corporate firewalls
- [ ] Telemetry-free debug flag: `OSCAR_AUTH_DEBUG=1` logs **URLs only** (never tokens)

---

## Browser research checklist (Chrome DevTools)

1. Start `oscar auth login` → note authorize URL
2. In subscription Chrome profile, open URL
3. Network: authorize → consent → redirect to `127.0.0.1`
4. Confirm token response fields: `access_token`, `refresh_token`, `expires_in`, `scope`
5. Compare scopes to OpenCode if open-source client available
6. `GET https://api.x.ai/v1/models` with Bearer access token — list includes build models
7. Chat smoke with `grok-build-0.1`

**Do not** paste access tokens into chat or commit them.

---

## Non-goals

- Scraping grok.com cookies as auth (fragile; OpenCode uses real OAuth)
- Emulating Grok web app without OIDC
- Storing Google password in oscar

---

## Test matrix

| Case | Expect |
|------|--------|
| Fresh OAuth browser | auth.json oauth, status email, models list |
| Device OAuth | same without local browser |
| OAuth then API key | OAuth still preferred until logout |
| Logout | no secret left |
| Expired access + refresh | silent refresh |
| Expired refresh | prompt re-login |
| OpenCode Go key no credits | clear CreditsError in TUI |
| NVIDIA free models | chat works with nvapi key |

---

## Status (2026-07-28)

| Item | Status |
|------|--------|
| Research OpenCode + xAI SuperGrok OAuth | **done** (docs + existing oscar code) |
| API key path (xAI / NVIDIA) | **working** (smoke chat; provider base_url switch fixed) |
| OpenCode Go models list | **working** (23 models) |
| OpenCode Go chat | **blocked** — account `CreditsError` / insufficient balance |
| SuperGrok OAuth end-to-end (device + Google) | **done 2026-07-28** — `oscar auth login --device` → Google SuperGrok `jackson.ray.business@gmail.com`; type=oauth; models include `grok-build-0.1`; chat works with OAuth JWT (key_len~786, not payg API key) |
| TUI multi-method connect | **pending** Phase B |
| Subscription model pinning | **pending** Phase C |

### Browser notes (2026-07-28)

1. **Browser MCP**: requires user to click extension → Connect on the tab (not auto-attached).
2. **chrome-devtools**: `https://grok.com/` loads; page shows **Sign in / Sign up** — not the jackson.ray.business subscription session.
3. **auth.x.ai**: `net::ERR_CONNECTION_REFUSED` from this harness for authorize URL — may be network isolation; device flow from a normal desktop may still work.
4. **Oscar OAuth already implements** PKCE loopback + device code with public client `b1a00492-073a-47ea-816f-4c329264a828` (same family as Grok Build / OpenCode).
5. **User action for Phase A**: on the machine with SuperGrok login, run `oscar auth login` (or `--device`), complete consent in the Chrome profile that has SuperGrok, then `oscar auth status` and `/model list` for `grok-build-0.1`.

---

## Immediate next command for the user

```bash
# Clear API-only confusion for a clean subscription test (optional):
# oscar auth logout

oscar auth login
# complete browser consent with SuperGrok account
oscar auth status
# In TUI:
# /model list
# /model grok-build-0.1
```

If browser cannot open, use:

```bash
oscar auth login --device
# open https://x.ai/device (or printed URL) on phone → enter code
```

# Oscar behavior change plan

Living checklist for the agent UX / AWS account / DNS / tools workstream.
Ask “how is the update going?” against the **Status** column.

**Security note (2026-07-28):** Session credentials were pasted into chat during debugging. Rotate those AWS keys; never paste secrets into chat. Prefer secure bar bulk-paste or `oscar auth aws-session`.

---

## Goals (user intent)

| # | Goal | Success criteria |
|---|------|------------------|
| G1 | Agent can **list AWS hosted zones** for a target profile | `aws.dns.zones.list` live-lists Route 53; agent can call it without failing search |
| G2 | **vdms / multi-account DNS** works when keys are correct | Profile-scoped keychain used; account_ref pinned from STS; empty results name the **account id** + auth source |
| G3 | **Account lifecycle is first-class** (no `tools_search`) | Access/profile/identity tools appear as native LLM tools |
| G4 | Cloud / infra / troubleshooting stay **search → execute** | DNS/network/IAM/path/k8s remain behind Code Mode |
| G5 | Less **dead air** after tools | Tool rail updates immediately; model narrates findings; fewer wasted search rounds |
| G6 | After tools, user always gets **1–2 sentence findings** | No silent “I searched, stop”; explicit miss (“no ravix records in account X”) |
| G7 | Secure bar accepts **bulk AWS export paste** | Paste `export AWS_ACCESS_KEY_ID=…` block once → all kinds stored → auto-retry |
| G8 | Proven with **agent-tui** (+ optional Grok baseline) | Smoke scripts / manual TUI runs green |

---

## Diagnosed root causes

### D1 — `tools_search` AND-all-tokens too strict
Query `"hosted zones list inventory sync aws dns"` required **every** token in one tool haystack → **0 hits**.  
`aws.dns.zones.list` has “list/hosted/zones” but not “inventory/sync”; inventory.sync has the reverse.  
**Fix:** soft token scoring (match ratio), not fail-on-first-miss.

### D2 — `aws.dns.zones.list` was cache-only
Implementation only read `~/.config/oscar/cache/<profile>/dns.json`. Empty cache → “0 zones” without live Route 53.  
**Fix:** live `route53 list-hosted-zones` with profile creds; enrich empty result with account + auth source.

### D3 — Named profile used ambient session silently
`aws-vdms` had `account_ref=pending`, **no keychain secrets** at first, so resolve fell through to ambient account `666587731621` (0 hosted zones). User believed “vdms was set up” while tools scanned the wrong identity.  
**Fix:** named non-default labels without keychain keys **must not** silently use ambient; pin `account_ref` after STS; tool summaries always include account id.

### D4 — Account tools hidden behind search
Only `tools_search` / `tools_execute` were native. Agent spent rounds searching for `system.access.*` and sometimes never reached DNS.  
**Fix:** promote account tools to native LLM functions.

### D5 — No user-facing narration after tools
Model often tool-called with empty/minimal content, then waited for the user. Example: access review done, DNS never run, user had to ask “did you find ravix?”.  
**Fix:** harness prompt + post-tool system nudge requiring 1–2 sentence findings before more tools or stop.

### D6 — Secure bar field-by-field only
Access key → secret → session token required three enters. User wants one paste of shell exports.  
**Fix:** parse bulk `export AWS_*` / multi-line blocks in secure mode.

### D7 — Perceived slowness
Extra `tools_search` rounds + empty content between tool rails + next model call = long pause.  
**Fix:** native account tools (skip search), softer search, force short narration, keep ToolStart/End rail snappy.

---

## Delivery workstreams

### W1 — Plan & tracking
- [x] Create this document
- [ ] Keep status rows updated as work lands

### W2 — tools_search ranking
- [x] Soft multi-token scoring (no AND-all fail)
- [x] Unit test: long “hosted zones list inventory…” returns zone/inventory tools
- [x] Prefer shorter agent queries in catalog copy

### W3 — Live DNS zones + empty-result honesty
- [x] `aws.dns.zones.list` live Route 53 list (profile-scoped)
- [x] Summary always includes `profile_id`, `account_id`, zone count
- [x] Empty: explicit wrong-account / re-auth guidance
- [x] Pattern search empty summary tells agent to narrate miss
- [ ] Optional: GCP/Azure zones list live later (same pattern)

### W4 — Multi-account credential binding
- [x] Refuse ambient binary session for **named** profiles without keychain secrets
- [x] Pin `account_ref` when pending after STS in zones.list
- [ ] `system.access.review` flags `using_ambient_for_named_profile` risk (partial via resolve errors)
- [x] Secure bulk paste + auth guidance text

### W5 — Native account tools (first-class, no search)
- [x] Promote as direct model tools (full JSON schema), executable by name:

| Native tool id | Purpose |
|----------------|---------|
| `system.access.review` | List/filter usable profiles |
| `system.access.prepare` | Create/update profile + auth request |
| `system.access.select` | Session pivot preferred profile |
| `system.profiles.list` | Local profiles by CSP |
| `system.identities.list` | Identity inventory / validity |

Keep via **tools_search → tools_execute** only: all `aws.*` / `gcp.*` / `azure.*` / `k8s.*` cloud tools, path, DNS pattern, inventory, IAM, CNI, MCP, binaries install, etc. Plus Code Mode pair `tools_search` / `tools_execute`.

### W6 — Narration & pause reduction
- [x] Prompt: after every tool round, emit 1–2 sentences (findings / miss / next step)
- [x] Prompt: continue domain tools same turn when access known
- [x] Host: system nudge when assistant content empty after tools
- [ ] agent-tui proof of reduced silent stops (ongoing)

### W7 — Secure bar bulk paste
- [x] Detect multi-line / `export AWS_ACCESS_KEY_ID=` paste
- [x] Map access + secret + session token into keychain in one submit
- [x] Queue multi secrets / auto-retry when all kinds ready
- [x] Never echo secrets into chat or agent context
- [x] Hint text: “paste export AWS_* block or one field”

### W8 — Tests & agent-tui
- [x] Unit: search soft scoring
- [x] Unit: secret store roundtrip + bulk export parse
- [x] CLI: zones.list + pattern ravix on aws-vdms (account 693703738260, 27 hits)
- [x] agent-tui E2E: native access.review → pattern.search → 1–2 sentence findings → `✓ done — ready`
- [ ] Optional: grok baseline for chat cadence comparison

### W9 — Docs / changelog
- [x] CHANGELOG entries
- [ ] README or AUTH note: bulk paste + native account tools
- [x] Update agent catalog primer

---

## Implementation status

| Item | Status | Notes |
|------|--------|-------|
| BEHAVIOR-CHANGE-PLAN.md | **done** | this file |
| Soft tools_search | **done** | long “hosted zones list inventory…” returns hits; unit test green |
| Live aws.dns.zones.list | **done** | live Route 53 + account_id in summary |
| Account pin + no silent ambient | **done** | named labels refuse ambient without keychain |
| Native account tools | **done** | `system.access.*` / profiles / identities as native LLM tools |
| Narration prompt + host nudge | **done** | prompt HARD rules + host system nudge when tool-only turn |
| Secure bulk paste | **done** | `export AWS_*` parse; multi-field queue |
| agent-tui verification | **done** | ravix E2E: review → pattern.search → narrated 27 hits + `✓ done` |
| Provider base_url switch | **done** | fixed NVIDIA URL stuck when switching to Grok (was 404) |
| DNS cache poison | **done** | zones.list no longer wipes records; incomplete cache re-syncs |
| Oscar-native secrets | **done** | `~/.config/oscar/secrets/` authoritative |
| SuperGrok subscription OAuth | **done** | Google device OAuth `jackson.ray.business@gmail.com`; JWT not API key; `grok-build-0.1` chat OK |

---

## Verification script (manual / agent-tui)

```bash
# 1. Search no longer returns 0 for long zone queries
oscar tools search "hosted zones list inventory sync aws dns" | jq '.count'

# 2. Live zones (after real vdms keys in keychain)
oscar tools execute aws.dns.zones.list --args '{"profile_id":"aws-vdms"}'

# 3. Pattern search with honest empty
oscar tools execute aws.dns.pattern.search --args '{"pattern":"ravix","profile_id":"aws-vdms"}'

# 4. Access review
oscar tools execute system.access.review --args '{"cloud":"aws","account":"vdms"}'

# 5. TUI
agent-tui run --cols 140 --rows 45 --format json -- oscar
# type: list hosted zones in the vdms account
# expect: system.access.* as native (no tools_search required), zones list, 1–2 sentence reply
```

---

## Out of scope (this pass)

- Changing overall Code Mode for all infra tools (kept search+execute by design)
- Full multi-cloud live zones parity (GCP/Azure can follow same pattern)
- Redesigning entire TUI chrome

---

## Progress log

| When | Note |
|------|------|
| 2026-07-28 | Plan created from live diagnosis: empty Route53 on ambient acct 666587731621; search AND-all bug; cache-only zones.list; field-by-field secure bar; missing narration in sample transcript |
| 2026-07-28 | Implemented soft search, live zones.list, native account tools, ambient refuse for named profiles, bulk AWS paste, narration prompt/nudge. Unit tests green; release installed. |
| 2026-07-28 | Providers: xAI API + NVIDIA NIM chat smoke OK; OpenCode Go lists 23 models but chat returns CreditsError (billing). SuperGrok OAuth plan: docs/SUBSCRIPTION-AUTH-PLAN.md |
| 2026-07-28 | agent-tui: /model list shows multi-provider incl. NVIDIA; secure bar shows bulk-paste hint; native `system.access.review` observed. Small-context NVIDIA tool turns need follow-up (prefer grok for agent tools). |
| 2026-07-28 | **Secret store root cause:** OS `keyring` (Secret Service) reported set-ok but get returned empty across processes. **Fix:** oscar-native `~/.config/oscar/secrets/` (0700/0600) is authoritative; OS keychain is optional mirror. Verified: aws-vdms → account `693703738260`, 6 zones, 15+ ravix hits. |
| 2026-07-28 | Also fixed `AWS_PROFILE=""` which broke `aws-test` with “config profile () could not be found”. |
| 2026-07-28 | **agent-tui E2E pass:** `system.access.review` (native) → `aws.dns.pattern.search` → **27 ravix hits** + user summary + status `ready` / notice `✓ done — ready for next prompt`. |
| 2026-07-28 | Fixed Grok 404: CLI `--provider` only set id, left prior NVIDIA `base_url`; now `activate_provider` + catalog default. |
| 2026-07-28 | Fixed zones.list writing empty-record cache that made pattern.search false-empty; incomplete cache forces re-sync. |
| 2026-07-28 | **Full validation matrix (CLI + agent-tui) PASS** — see section below. SuperGrok OAuth + ravix/zones/native tools/narration/done chrome all green. |

---

## Full validation matrix (2026-07-28)

| # | Request | Result | Evidence |
|---|---------|--------|----------|
| 1 | List AWS hosted zones | **PASS** | `aws.dns.zones.list` → 6 zones, account `693703738260` |
| 2 | Find ravix DNS on aws-vdms | **PASS** | pattern search → **15–27 hits** under jadeuc.com |
| 3 | aws-vdms secrets work | **PASS** | `~/.config/oscar/secrets/oscar_aws-vdms__*`; STS OK |
| 4 | Account tools native (no search) | **PASS** | `system.access.review` called as native tool in TUI |
| 5 | Cloud/infra via search→execute | **PASS** | soft search returns zones.list; pattern tools via execute |
| 6 | Soft tools_search long query | **PASS** | count 15 (not 0) for hosted zones query |
| 7 | Narrate after tools | **PASS** | mid-turn + final 2–3 sentence summary in TUI |
| 8 | Working / done indicator | **PASS** | status `answering` → `ready`; notice `✓ done — ready` |
| 9 | SuperGrok OAuth (not API key) | **PASS** | JWT oauth, email jackson.ray.business@gmail.com, `grok-build-0.1` chat |
| 10 | NVIDIA provider models | **PASS** | 102 models listed |
| 11 | OpenCode Go | **PARTIAL** | models endpoint may 403/credits; key stored |
| 12 | Bulk AWS export paste | **PASS** | code path + secure bar hint; secrets store file-native |
| 13 | Resume after auth | **PASS** (code) | `resume_after_auth` continues original request |
| 14 | agent-tui E2E | **PASS** | review → zones.list → pattern.search → summary → done |

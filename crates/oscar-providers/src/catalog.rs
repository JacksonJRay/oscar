//! Static model catalogs and multi-provider load inventory (no network).
//!
//! "Loaded" = has credentials (keychain / OAuth) and/or a saved `[providers.*]` slot.

use crate::traits::ModelInfo;
use crate::xai_oauth::{is_xai_family, oauth_status, xai_canonical_id};
use oscar_core::config::{OscarConfig, ProviderSettings};
use oscar_core::Paths;
use oscar_identity::load_provider_api_key;

/// Built-in provider ids in display order (Grok first).
pub fn list_provider_ids() -> &'static [&'static str] {
    &[
        "grok",
        "xai",
        "openai",
        "anthropic",
        "opencode-zen",
        "opencode-go",
    ]
}

/// Human label for a provider id.
pub fn provider_display_name(id: &str) -> &'static str {
    match id {
        "grok" | "xai" | "x-ai" => "Grok (xAI)",
        "openai" => "OpenAI",
        "anthropic" | "claude" => "Anthropic (Claude)",
        "opencode-zen" | "zen" => "OpenCode Zen",
        "opencode-go" | "go" => "OpenCode Go",
        _ => "Custom",
    }
}

/// Normalize aliases so keychain / catalog resolve consistently.
pub fn normalize_provider_id(id: &str) -> &str {
    match id {
        "x-ai" | "xai-oauth" | "grok-oauth" | "xai-grok-oauth" => "xai",
        "claude" => "anthropic",
        "zen" => "opencode-zen",
        "go" => "opencode-go",
        other => other,
    }
}

/// Models for a provider (static catalog — no API key required).
pub fn catalog_models(provider_id: &str) -> Vec<ModelInfo> {
    match normalize_provider_id(provider_id) {
        "grok" | "xai" => vec![
            ModelInfo {
                id: "grok-4".into(),
                context_window: 256_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "grok-4-fast".into(),
                context_window: 256_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "grok-3".into(),
                context_window: 131_072,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "grok-3-mini".into(),
                context_window: 131_072,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
        ],
        "openai" => vec![
            ModelInfo {
                id: "gpt-4.1".into(),
                context_window: 1_047_576,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "gpt-4.1-mini".into(),
                context_window: 1_047_576,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "gpt-4o".into(),
                context_window: 128_000,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "o3".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "o4-mini".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
        ],
        "anthropic" => vec![
            ModelInfo {
                id: "claude-sonnet-4-5".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "claude-opus-4-5".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "claude-haiku-4-5".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
        ],
        "opencode-zen" | "opencode-go" => vec![ModelInfo {
            id: "default".into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        }],
        _ => vec![ModelInfo {
            id: "default".into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        }],
    }
}

/// Default model id when activating a provider with no preferred model.
pub fn default_model_for(provider_id: &str) -> String {
    catalog_models(provider_id)
        .into_iter()
        .next()
        .map(|m| m.id)
        .unwrap_or_else(|| "default".into())
}

/// Whether credentials exist for this provider (keychain or Grok OAuth).
pub fn provider_has_credentials(paths: &Paths, provider_id: &str) -> bool {
    let id = normalize_provider_id(provider_id);
    if is_xai_family(id) || id == "grok" {
        if oauth_status(paths).is_some() {
            return true;
        }
        if matches!(load_provider_api_key("xai"), Ok(Some(k)) if !k.is_empty()) {
            return true;
        }
        if matches!(load_provider_api_key("grok"), Ok(Some(k)) if !k.is_empty()) {
            return true;
        }
        return false;
    }
    matches!(load_provider_api_key(id), Ok(Some(k)) if !k.is_empty())
        || matches!(load_provider_api_key(provider_id), Ok(Some(k)) if !k.is_empty())
}

/// One row in the multi-provider inventory.
#[derive(Debug, Clone)]
pub struct LoadedProvider {
    pub id: String,
    pub label: String,
    pub model: Option<String>,
    pub has_credentials: bool,
    pub is_active: bool,
    pub source: &'static str, // "slot" | "keychain" | "oauth" | "active"
}

/// Providers that are **loaded**: active + saved slots + any with credentials.
pub fn list_loaded_providers(cfg: &OscarConfig, paths: &Paths) -> Vec<LoadedProvider> {
    use std::collections::BTreeSet;
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.insert(cfg.provider.id.clone());
    for k in cfg.providers.keys() {
        ids.insert(k.clone());
    }
    // Include built-ins that already have credentials so they show up for /model
    for id in list_provider_ids() {
        if provider_has_credentials(paths, id) {
            ids.insert((*id).to_string());
        }
    }

    let mut out = Vec::new();
    for id in ids {
        if id.is_empty() {
            continue;
        }
        let has = provider_has_credentials(paths, &id);
        let is_active = cfg.provider.id == id
            || (is_xai_family(&cfg.provider.id)
                && is_xai_family(&id)
                && normalize_provider_id(&cfg.provider.id) == normalize_provider_id(&id));
        let model = if cfg.provider.id == id {
            cfg.provider.model.clone()
        } else {
            cfg.providers.get(&id).and_then(|s| s.model.clone())
        };
        let source = if oauth_status(paths).is_some() && is_xai_family(&id) {
            "oauth"
        } else if has {
            "keychain"
        } else if cfg.providers.contains_key(&id) {
            "slot"
        } else {
            "active"
        };
        // Prefer listing providers that are useful: creds OR slot OR active
        if !has && !cfg.providers.contains_key(&id) && cfg.provider.id != id {
            continue;
        }
        out.push(LoadedProvider {
            label: provider_display_name(&id).into(),
            id,
            model,
            has_credentials: has,
            is_active,
            source,
        });
    }
    // Stable order: active first, then catalog order, then alpha
    out.sort_by(|a, b| {
        b.is_active
            .cmp(&a.is_active)
            .then_with(|| {
                let ai = list_provider_ids()
                    .iter()
                    .position(|x| *x == a.id.as_str())
                    .unwrap_or(999);
                let bi = list_provider_ids()
                    .iter()
                    .position(|x| *x == b.id.as_str())
                    .unwrap_or(999);
                ai.cmp(&bi)
            })
            .then_with(|| a.id.cmp(&b.id))
    });
    out
}

/// Flat selectable model row for `/model` listing.
#[derive(Debug, Clone)]
pub struct ModelChoice {
    pub index: usize,
    pub provider_id: String,
    pub provider_label: String,
    pub model_id: String,
    pub context_window: u32,
    pub supports_thinking: bool,
    pub is_active: bool,
    pub provider_ready: bool,
}

/// Build numbered model choices across all loaded providers (for `/model` list/switch).
pub fn list_model_choices(cfg: &OscarConfig, paths: &Paths) -> Vec<ModelChoice> {
    let loaded = list_loaded_providers(cfg, paths);
    let mut choices = Vec::new();
    let mut idx = 1usize;

    // If nothing loaded yet, still show Grok catalog so users know what to pick after login
    let providers: Vec<(String, String, bool, Option<String>)> = if loaded.is_empty() {
        vec![(
            "grok".into(),
            provider_display_name("grok").into(),
            false,
            Some(default_model_for("grok")),
        )]
    } else {
        loaded
            .into_iter()
            .map(|p| (p.id, p.label, p.has_credentials, p.model))
            .collect()
    };

    for (pid, label, ready, preferred) in providers {
        let models = catalog_models(&pid);
        // Ensure preferred model appears even if custom
        let mut seen = std::collections::HashSet::new();
        let mut list = models;
        if let Some(ref pref) = preferred {
            if !list.iter().any(|m| &m.id == pref) {
                list.insert(
                    0,
                    ModelInfo {
                        id: pref.clone(),
                        context_window: 128_000,
                        supports_thinking: false,
                        supports_tools: true,
                        supports_streaming: true,
                    },
                );
            }
        }
        for m in list {
            if !seen.insert(m.id.clone()) {
                continue;
            }
            let is_active = cfg.provider.id == pid
                && cfg
                    .provider
                    .model
                    .as_deref()
                    .unwrap_or("")
                    == m.id
                || (cfg.provider.id == pid
                    && cfg.provider.model.is_none()
                    && preferred.as_deref() == Some(m.id.as_str()));
            // Also mark active when model matches and provider is xai/grok family
            let is_active = is_active
                || (is_xai_family(&cfg.provider.id)
                    && is_xai_family(&pid)
                    && cfg.provider.model.as_deref() == Some(m.id.as_str()));
            choices.push(ModelChoice {
                index: idx,
                provider_id: pid.clone(),
                provider_label: label.clone(),
                model_id: m.id.clone(),
                context_window: m.context_window,
                supports_thinking: m.supports_thinking,
                is_active,
                provider_ready: ready,
            });
            idx += 1;
        }
    }
    choices
}

/// Parse `/model` selection: `3`, `grok-4`, `xai/grok-4`, `openai gpt-4o`, `provider/model`.
pub fn resolve_model_selection(
    cfg: &OscarConfig,
    paths: &Paths,
    args: &str,
) -> Result<(String, String), String> {
    let args = args.trim();
    if args.is_empty() {
        return Err("usage: /model [list|N|model|provider/model|provider model]".into());
    }
    let choices = list_model_choices(cfg, paths);

    // Numeric index
    if let Ok(n) = args.parse::<usize>() {
        return choices
            .into_iter()
            .find(|c| c.index == n)
            .map(|c| (c.provider_id, c.model_id))
            .ok_or_else(|| format!("no model #{n} — run /model list"));
    }

    // provider/model
    if let Some((p, m)) = args.split_once('/') {
        let p = p.trim();
        let m = m.trim();
        if !p.is_empty() && !m.is_empty() {
            return Ok((normalize_provider_id(p).to_string(), m.to_string()));
        }
    }

    // provider model (two tokens)
    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() >= 2 {
        let maybe_prov = normalize_provider_id(parts[0]);
        if list_provider_ids().contains(&maybe_prov)
            || cfg.providers.contains_key(parts[0])
            || cfg.provider.id == parts[0]
        {
            return Ok((maybe_prov.to_string(), parts[1..].join(" ")));
        }
    }

    // bare model id — prefer active provider, then any loaded match, then catalog scan
    let model = args.to_string();
    if catalog_models(&cfg.provider.id)
        .iter()
        .any(|m| m.id == model)
    {
        return Ok((cfg.provider.id.clone(), model));
    }
    for c in &choices {
        if c.model_id == model {
            return Ok((c.provider_id.clone(), model));
        }
    }
    for id in list_provider_ids() {
        if catalog_models(id).iter().any(|m| m.id == model) {
            return Ok(((*id).to_string(), model));
        }
    }
    // Custom: keep active provider, set model literally
    Ok((cfg.provider.id.clone(), model))
}

/// Format a multi-provider model table for chat.
pub fn format_model_list(cfg: &OscarConfig, paths: &Paths) -> String {
    let choices = list_model_choices(cfg, paths);
    let loaded = list_loaded_providers(cfg, paths);
    let mut lines = Vec::new();
    lines.push("# models — switch with /model <N> or /model provider/model".into());
    lines.push(format!(
        "active: {} / {}",
        cfg.provider.id,
        cfg.provider
            .model
            .as_deref()
            .unwrap_or("(provider default)")
    ));
    lines.push(String::new());
    lines.push("## loaded providers".into());
    if loaded.is_empty() {
        lines.push("(none — oscar auth login  or  oscar auth provider-key --provider …)".into());
    } else {
        for p in &loaded {
            let mark = if p.is_active { "*" } else { " " };
            let ready = if p.has_credentials { "ready" } else { "no key" };
            lines.push(format!(
                "{mark} {:<14}  {:<8}  model={}  ({})",
                p.id,
                ready,
                p.model.as_deref().unwrap_or("—"),
                p.source
            ));
        }
    }
    lines.push(String::new());
    lines.push("## models".into());
    let mut last_p = String::new();
    for c in &choices {
        if c.provider_id != last_p {
            lines.push(format!(
                "\n### {} ({}){}",
                c.provider_label,
                c.provider_id,
                if c.provider_ready {
                    ""
                } else {
                    " — not authenticated"
                }
            ));
            last_p = c.provider_id.clone();
        }
        let mark = if c.is_active { "▶" } else { " " };
        let think = if c.supports_thinking { " think" } else { "" };
        lines.push(format!(
            "{mark} {:>3}.  {:<28}  ctx={}{}",
            c.index, c.model_id, c.context_window, think
        ));
    }
    lines.push(String::new());
    lines.push("examples:  /model 2  ·  /model grok-4  ·  /model openai/gpt-4o  ·  /model list".into());
    lines.push("auth:      oscar auth login (Grok OAuth)  ·  /provider  ·  oscar auth provider-key".into());
    let _ = xai_canonical_id();
    lines.join("\n")
}

/// Settings for create_provider after resolving multi-provider slot.
pub fn settings_for_provider(cfg: &OscarConfig, provider_id: &str) -> ProviderSettings {
    let id = normalize_provider_id(provider_id);
    if cfg.provider.id == provider_id || cfg.provider.id == id {
        return cfg.provider.clone();
    }
    if let Some(slot) = cfg.providers.get(provider_id).or_else(|| cfg.providers.get(id)) {
        return ProviderSettings {
            id: provider_id.to_string(),
            model: slot.model.clone(),
            base_url: slot.base_url.clone(),
            api_key_env: slot.api_key_env.clone(),
        };
    }
    ProviderSettings {
        id: provider_id.to_string(),
        model: Some(default_model_for(provider_id)),
        base_url: None,
        api_key_env: None,
    }
}

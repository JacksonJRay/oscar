//! Provider/model catalog: models.dev (cached) + static fallback.
//!
//! OpenCode loads ~170 providers from models.dev. oscar uses the same API for
//! ids, names, env var hints, base URLs, and model metadata, then maps backends
//! to OpenAI-compat or Anthropic.

use crate::auth_store;
use crate::traits::ModelInfo;
use crate::xai_oauth::{is_xai_family, oauth_status, xai_canonical_id};
use oscar_core::config::{CatalogSettings, OscarConfig, ProviderSettings};
use oscar_core::Paths;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, SystemTime};
use tracing::{debug, warn};

const DEFAULT_MODELS_URL: &str = "https://models.dev/api.json";
const CACHE_TTL_SECS: u64 = 300; // 5 minutes freshness for refresh decision

/// Which HTTP backend oscar uses for a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BackendKind {
    OpenAiCompat,
    Anthropic,
    Xai,
    Unsupported,
}

// ── models.dev types (subset) ────────────────────────────────────────────────

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModelsDevProvider {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub env: Vec<String>,
    pub api: Option<String>,
    pub npm: Option<String>,
    pub doc: Option<String>,
    #[serde(default)]
    pub models: BTreeMap<String, ModelsDevModel>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModelsDevModel {
    pub id: Option<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub reasoning: bool,
    #[serde(default)]
    pub tool_call: Option<bool>,
    pub limit: Option<ModelsDevLimit>,
    pub status: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ModelsDevLimit {
    pub context: Option<f64>,
    pub output: Option<f64>,
}

// ── Cache ────────────────────────────────────────────────────────────────────

struct CatalogCache {
    providers: BTreeMap<String, ModelsDevProvider>,
    loaded_at: SystemTime,
    source: &'static str,
}

static CATALOG: OnceLock<Mutex<Option<CatalogCache>>> = OnceLock::new();

fn catalog_lock() -> &'static Mutex<Option<CatalogCache>> {
    CATALOG.get_or_init(|| Mutex::new(None))
}

fn cache_path() -> Option<PathBuf> {
    dirs::cache_dir().map(|d| d.join("oscar").join("models.json"))
}

fn models_url() -> String {
    std::env::var("OSCAR_MODELS_URL").unwrap_or_else(|_| DEFAULT_MODELS_URL.into())
}

fn fetch_disabled() -> bool {
    matches!(
        std::env::var("OSCAR_DISABLE_MODELS_FETCH").as_deref(),
        Ok("1") | Ok("true") | Ok("yes")
    )
}

/// Load catalog: memory → disk cache → network → static empty map.
pub fn load_catalog(settings: &CatalogSettings) -> BTreeMap<String, ModelsDevProvider> {
    if !settings.enabled {
        return BTreeMap::new();
    }
    if let Ok(guard) = catalog_lock().lock() {
        if let Some(c) = guard.as_ref() {
            if c.loaded_at.elapsed().unwrap_or(Duration::MAX) < Duration::from_secs(CACHE_TTL_SECS) {
                return c.providers.clone();
            }
        }
    }

    // Disk — prefer cached catalog so TUI/async paths never block on network.
    if let Some(path) = cache_path() {
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(map) = parse_models_dev_json(&raw) {
                store_memory(map.clone(), "disk");
                // Soft-stale: return disk immediately; refresh only when explicitly
                // allowed. Never block the calling thread for up to 12s on models.dev
                // (that freezes the TUI event loop when called from async host).
                let stale = fs::metadata(&path)
                    .and_then(|m| m.modified())
                    .map(|t| t.elapsed().unwrap_or(Duration::MAX) > Duration::from_secs(CACHE_TTL_SECS))
                    .unwrap_or(true);
                if stale && !fetch_disabled() && std::env::var("OSCAR_MODELS_SYNC_REFRESH").is_ok() {
                    let _ = try_network_refresh();
                    if let Ok(guard) = catalog_lock().lock() {
                        if let Some(c) = guard.as_ref() {
                            return c.providers.clone();
                        }
                    }
                }
                return map;
            }
        }
    }

    // No disk cache: one network attempt (callers that care should use spawn_blocking).
    if !fetch_disabled() {
        if let Some(map) = try_network_refresh() {
            return map;
        }
    }

    BTreeMap::new()
}

fn try_network_refresh() -> Option<BTreeMap<String, ModelsDevProvider>> {
    let url = models_url();
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(12))
        .user_agent(format!("oscar/{}", env!("CARGO_PKG_VERSION")))
        .build()
        .ok()?;
    let resp = client.get(&url).send().ok()?;
    if !resp.status().is_success() {
        warn!(status = %resp.status(), "models.dev fetch failed");
        return None;
    }
    let raw = resp.text().ok()?;
    let map = parse_models_dev_json(&raw).ok()?;
    if let Some(path) = cache_path() {
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let _ = fs::write(&path, &raw);
    }
    store_memory(map.clone(), "network");
    debug!(count = map.len(), "models.dev catalog refreshed");
    Some(map)
}

fn store_memory(map: BTreeMap<String, ModelsDevProvider>, source: &'static str) {
    if let Ok(mut guard) = catalog_lock().lock() {
        *guard = Some(CatalogCache {
            providers: map,
            loaded_at: SystemTime::now(),
            source,
        });
    }
}

pub fn parse_models_dev_json(raw: &str) -> Result<BTreeMap<String, ModelsDevProvider>, String> {
    let v: serde_json::Value =
        serde_json::from_str(raw).map_err(|e| format!("models.dev json: {e}"))?;
    let obj = v
        .as_object()
        .ok_or_else(|| "models.dev root must be object".to_string())?;
    let mut out = BTreeMap::new();
    for (k, val) in obj {
        let mut p: ModelsDevProvider =
            serde_json::from_value(val.clone()).map_err(|e| format!("provider {k}: {e}"))?;
        if p.id.is_none() {
            p.id = Some(k.clone());
        }
        out.insert(k.clone(), p);
    }
    Ok(out)
}

// ── Public catalog API ───────────────────────────────────────────────────────

/// Built-in provider ids in display order (Grok first). Used when catalog empty
/// and for stable sorting.
///
/// Note: Grok/xAI is a single provider (`grok`). The id `xai` remains a storage
/// alias (AuthStore / models.dev) but is not listed separately.
pub fn list_provider_ids() -> &'static [&'static str] {
    &[
        "grok",
        "openai",
        "anthropic",
        "opencode-zen",
        "opencode-go",
        "openrouter",
        "groq",
        "deepseek",
        "togetherai",
        "fireworks-ai",
        "mistral",
        "google",
    ]
}

/// Canonical UI id for a provider (collapse Grok/xAI aliases to `grok`).
pub fn display_provider_id(id: &str) -> &str {
    if is_xai_family(id) || id == "xai" || id == "grok" {
        "grok"
    } else {
        normalize_provider_id(id)
    }
}

/// Human label for a provider id.
pub fn provider_display_name(id: &str) -> String {
    let id = normalize_provider_id(id);
    match id {
        "grok" | "xai" | "x-ai" => "Grok (xAI)".into(),
        "openai" => "OpenAI".into(),
        "anthropic" | "claude" => "Anthropic (Claude)".into(),
        "opencode-zen" | "zen" => "OpenCode Zen".into(),
        "opencode-go" | "go" => "OpenCode Go".into(),
        other => {
            if let Some(p) = lookup_dev(other) {
                return p.name.unwrap_or_else(|| other.into());
            }
            other.into()
        }
    }
}

/// Normalize aliases so keychain / catalog resolve consistently.
pub fn normalize_provider_id(id: &str) -> &str {
    match id {
        "x-ai" | "xai-oauth" | "grok-oauth" | "xai-grok-oauth" => "xai",
        "claude" => "anthropic",
        "zen" | "opencode" => "opencode-zen",
        "go" => "opencode-go",
        "together" => "togetherai",
        "fireworks" => "fireworks-ai",
        other => other,
    }
}

fn lookup_dev(id: &str) -> Option<ModelsDevProvider> {
    let settings = CatalogSettings::default();
    let map = load_catalog(&settings);
    let id = normalize_provider_id(id);
    map.get(id)
        .cloned()
        .or_else(|| {
            // grok → xai on models.dev
            if id == "grok" {
                map.get("xai").cloned()
            } else {
                None
            }
        })
        .or_else(|| {
            if id == "opencode-zen" || id == "opencode" {
                map.get("opencode").cloned()
            } else if id == "opencode-go" {
                map.get("opencode-go")
                    .cloned()
                    .or_else(|| map.get("opencode").cloned())
            } else {
                None
            }
        })
}

pub fn catalog_env_names(provider_id: &str) -> Vec<String> {
    if let Some(p) = lookup_dev(provider_id) {
        if !p.env.is_empty() {
            return p.env;
        }
    }
    match normalize_provider_id(provider_id) {
        "xai" | "grok" => vec!["XAI_API_KEY".into()],
        "openai" => vec!["OPENAI_API_KEY".into()],
        "anthropic" => vec!["ANTHROPIC_API_KEY".into()],
        "openrouter" => vec!["OPENROUTER_API_KEY".into()],
        "groq" => vec!["GROQ_API_KEY".into()],
        "deepseek" => vec!["DEEPSEEK_API_KEY".into()],
        _ => vec![],
    }
}

pub fn default_base_url(provider_id: &str) -> Option<String> {
    if let Some(p) = lookup_dev(provider_id) {
        if let Some(api) = p.api {
            if !api.is_empty() {
                return Some(api);
            }
        }
    }
    match normalize_provider_id(provider_id) {
        "xai" | "grok" => Some("https://api.x.ai/v1".into()),
        "openai" => Some("https://api.openai.com/v1".into()),
        "anthropic" => Some("https://api.anthropic.com".into()),
        "opencode-zen" => Some("https://opencode.ai/zen/v1".into()),
        // Go subscription catalog is under /zen/go/v1 (distinct from Zen).
        "opencode-go" => Some("https://opencode.ai/zen/go/v1".into()),
        "openrouter" => Some("https://openrouter.ai/api/v1".into()),
        "groq" => Some("https://api.groq.com/openai/v1".into()),
        "deepseek" => Some("https://api.deepseek.com".into()),
        "togetherai" => Some("https://api.together.xyz/v1".into()),
        "fireworks-ai" => Some("https://api.fireworks.ai/inference/v1".into()),
        "mistral" => Some("https://api.mistral.ai/v1".into()),
        "google" => Some("https://generativelanguage.googleapis.com/v1beta/openai".into()),
        _ => None,
    }
}

pub fn backend_kind(provider_id: &str) -> BackendKind {
    let id = normalize_provider_id(provider_id);
    if id == "anthropic" {
        return BackendKind::Anthropic;
    }
    if is_xai_family(id) || id == "xai" || id == "grok" {
        return BackendKind::Xai;
    }
    if let Some(p) = lookup_dev(id) {
        let npm = p.npm.as_deref().unwrap_or("");
        if npm.contains("anthropic") {
            return BackendKind::Anthropic;
        }
        // Most providers are openai-compatible chat
        if npm.contains("openai")
            || npm.contains("compatible")
            || npm.contains("xai")
            || npm.contains("groq")
            || npm.contains("openrouter")
            || npm.contains("together")
            || npm.contains("deepinfra")
            || npm.contains("cerebras")
            || npm.contains("mistral")
            || npm.contains("cohere")
            || npm.is_empty()
        {
            return BackendKind::OpenAiCompat;
        }
        // Unknown npm with api URL → try openai compat
        if p.api.as_ref().map(|a| !a.is_empty()).unwrap_or(false) {
            return BackendKind::OpenAiCompat;
        }
        return BackendKind::Unsupported;
    }
    // Static known
    match id {
        "openai" | "opencode-zen" | "opencode-go" | "openrouter" | "groq" | "deepseek"
        | "togetherai" | "fireworks-ai" | "mistral" | "google" => BackendKind::OpenAiCompat,
        _ => {
            if default_base_url(id).is_some() {
                BackendKind::OpenAiCompat
            } else {
                BackendKind::Unsupported
            }
        }
    }
}

/// Models for a provider (catalog or static — no API key required).
pub fn catalog_models(provider_id: &str) -> Vec<ModelInfo> {
    catalog_models_resolved(provider_id, None)
}

pub fn catalog_models_resolved(provider_id: &str, _paths: Option<&Paths>) -> Vec<ModelInfo> {
    let id = normalize_provider_id(provider_id);
    let mut models: Vec<ModelInfo> = Vec::new();
    let mut seen = std::collections::HashSet::new();

    // models.dev (or alias: grok→xai, opencode-zen→opencode)
    if let Some(p) = lookup_dev(id) {
        for (mid, m) in &p.models {
            if m.status.as_deref() == Some("deprecated") {
                continue;
            }
            let model_id = m.id.clone().unwrap_or_else(|| mid.clone());
            if !seen.insert(model_id.clone()) {
                continue;
            }
            models.push(ModelInfo {
                id: model_id,
                context_window: m
                    .limit
                    .as_ref()
                    .and_then(|l| l.context)
                    .map(|c| c as u32)
                    .unwrap_or(128_000),
                supports_thinking: m.reasoning,
                supports_tools: m.tool_call.unwrap_or(true),
                supports_streaming: true,
            });
        }
    }

    // Always merge static builtins so known flagships (grok-4, …) stay listed
    // even when models.dev renames/omits them.
    for m in static_catalog_models(id) {
        if seen.insert(m.id.clone()) {
            models.push(m);
        }
    }

    if models.is_empty() {
        return static_catalog_models(id);
    }

    // Chat / code models first; media (image/video) last. Then name sort within band.
    models.sort_by(|a, b| {
        model_list_rank(&a.id)
            .cmp(&model_list_rank(&b.id))
            .then_with(|| a.id.cmp(&b.id))
    });
    models
}

/// Lower rank = earlier in `/model list`. Media models sort after chat.
fn model_list_rank(id: &str) -> u8 {
    let low = id.to_ascii_lowercase();
    if low.contains("imagine")
        || low.contains("image")
        || low.contains("video")
        || low.contains("tts")
        || low.contains("voice")
        || low.contains("embedding")
    {
        2
    } else if low.contains("non-reasoning") || low.contains("fast") {
        1
    } else {
        0
    }
}

fn static_catalog_models(provider_id: &str) -> Vec<ModelInfo> {
    match normalize_provider_id(provider_id) {
        "grok" | "xai" => vec![
            ModelInfo {
                id: "grok-4.5".into(),
                context_window: 500_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "grok-4.3".into(),
                context_window: 1_000_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
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
                id: "grok-code-fast-1".into(),
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
        "opencode-zen" => vec![ModelInfo {
            id: "default".into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        }],
        // Static fallbacks for OpenCode Go (live list comes from /v1/models when online).
        "opencode-go" => [
            "minimax-m2.5",
            "minimax-m3",
            "kimi-k2.5",
            "glm-5",
            "deepseek-v4-flash",
            "grok-4.5",
        ]
        .into_iter()
        .map(|id| ModelInfo {
            id: id.into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        })
        .collect(),
        "nvidia" => [
            "meta/llama-3.1-8b-instruct",
            "nvidia/nemotron-3-super-120b-a12b",
            "meta/llama-3.3-70b-instruct",
            "mistralai/mistral-large",
        ]
        .into_iter()
        .map(|id| ModelInfo {
            id: id.into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        })
        .collect(),
        "openrouter" => vec![
            ModelInfo {
                id: "anthropic/claude-sonnet-4".into(),
                context_window: 200_000,
                supports_thinking: true,
                supports_tools: true,
                supports_streaming: true,
            },
            ModelInfo {
                id: "openai/gpt-4o".into(),
                context_window: 128_000,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            },
        ],
        "groq" => vec![ModelInfo {
            id: "llama-3.3-70b-versatile".into(),
            context_window: 128_000,
            supports_thinking: false,
            supports_tools: true,
            supports_streaming: true,
        }],
        "deepseek" => vec![ModelInfo {
            id: "deepseek-chat".into(),
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
///
/// Prefer well-known flagship ids when present in the catalog (models.dev order
/// is not preference order). Fall back to static catalog, then first listed model.
pub fn default_model_for(provider_id: &str) -> String {
    let id = normalize_provider_id(provider_id);
    let preferred: &[&str] = match id {
        "grok" | "xai" => &[
            "grok-4.5",
            "grok-4.3",
            "grok-4",
            "grok-4-fast",
            "grok-code-fast-1",
            "grok-3",
            "grok-3-mini",
        ],
        "openai" => &["gpt-4.1", "gpt-4o", "o4-mini", "o3"],
        "anthropic" => &[
            "claude-sonnet-4-5",
            "claude-opus-4-5",
            "claude-haiku-4-5",
            "claude-sonnet-4-20250514",
        ],
        "openrouter" => &["anthropic/claude-sonnet-4", "openai/gpt-4o"],
        "opencode-zen" | "opencode" => &["claude-sonnet-4-5", "gpt-5", "grok-4.5", "big-pickle"],
        "opencode-go" => &["grok-4.5", "minimax-m2.5", "glm-5", "kimi-k2.5"],
        "groq" => &["llama-3.3-70b-versatile"],
        "deepseek" => &["deepseek-chat", "deepseek-reasoner"],
        _ => &[],
    };
    let models = catalog_models(id);
    for p in preferred {
        if models.iter().any(|m| m.id == *p) {
            return (*p).into();
        }
    }
    // Prefer static catalog order for builtins over models.dev alpha sort.
    static_catalog_models(id)
        .into_iter()
        .next()
        .or_else(|| models.into_iter().next())
        .map(|m| m.id)
        .unwrap_or_else(|| "default".into())
}

/// Whether credentials exist for this provider (AuthStore / keychain / OAuth).
pub fn provider_has_credentials(paths: &Paths, provider_id: &str) -> bool {
    auth_store::has_credentials(paths, provider_id)
}

/// One row in the multi-provider inventory.
#[derive(Debug, Clone)]
pub struct LoadedProvider {
    pub id: String,
    pub label: String,
    pub model: Option<String>,
    pub has_credentials: bool,
    pub is_active: bool,
    pub source: &'static str, // "slot" | "keychain" | "oauth" | "api" | "active"
}

/// Providers that are **loaded**: active + saved slots + any with credentials.
pub fn list_loaded_providers(cfg: &OscarConfig, paths: &Paths) -> Vec<LoadedProvider> {
    use std::collections::BTreeSet;
    let mut ids: BTreeSet<String> = BTreeSet::new();
    ids.insert(display_provider_id(&cfg.provider.id).to_string());
    for k in cfg.providers.keys() {
        ids.insert(display_provider_id(k).to_string());
    }
    for id in list_provider_ids() {
        if provider_has_credentials(paths, id) {
            ids.insert((*id).to_string());
        }
    }
    // AuthStore entries not in builtin list (collapse xai → grok)
    for st in auth_store::list_status(paths) {
        ids.insert(display_provider_id(&st.provider_id).to_string());
    }

    let mut out = Vec::new();
    for id in ids {
        if id.is_empty() || id == "xai" {
            // Never list the raw xai alias; Grok covers it.
            continue;
        }
        let has = provider_has_credentials(paths, &id);
        let is_active = display_provider_id(&cfg.provider.id) == id
            || (is_xai_family(&cfg.provider.id) && id == "grok");
        let model = if display_provider_id(&cfg.provider.id) == id {
            cfg.provider.model.clone()
        } else {
            cfg.providers
                .get(&id)
                .or_else(|| {
                    if id == "grok" {
                        cfg.providers.get("xai")
                    } else {
                        None
                    }
                })
                .and_then(|s| s.model.clone())
        };
        let source = if oauth_status(paths).is_some() && is_xai_family(&id) {
            "oauth"
        } else if has {
            if auth_store::get(paths, &id).map(|e| e.kind_label()) == Some("api") {
                "api"
            } else {
                "keychain"
            }
        } else if cfg.providers.contains_key(&id) {
            "slot"
        } else {
            "active"
        };
        if !has && !cfg.providers.contains_key(&id) && cfg.provider.id != id {
            continue;
        }
        out.push(LoadedProvider {
            label: provider_display_name(&id),
            id,
            model,
            has_credentials: has,
            is_active,
            source,
        });
    }
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
///
/// Providers without credentials only get their preferred/default model (one row),
/// so the list stays scannable in the TUI. Authenticated providers get full catalogs.
pub fn list_model_choices(cfg: &OscarConfig, paths: &Paths) -> Vec<ModelChoice> {
    let loaded = list_loaded_providers(cfg, paths);
    let mut choices = Vec::new();
    let mut idx = 1usize;

    let providers: Vec<(String, String, bool, Option<String>)> = if loaded.is_empty() {
        vec![(
            "grok".into(),
            provider_display_name("grok"),
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
        // Unauthenticated: single placeholder row (avoid dumping 40+ OpenAI models).
        let models = if ready {
            catalog_models(&pid)
        } else if let Some(ref pref) = preferred {
            vec![ModelInfo {
                id: pref.clone(),
                context_window: 128_000,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            }]
        } else {
            catalog_models(&pid)
                .into_iter()
                .take(3)
                .collect()
        };
        let mut seen = std::collections::HashSet::new();
        let mut list = models;
        // Preferred / active slot model floats to the top of that provider block.
        if let Some(ref pref) = preferred {
            if let Some(pos) = list.iter().position(|m| &m.id == pref) {
                let m = list.remove(pos);
                list.insert(0, m);
            } else {
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
                && cfg.provider.model.as_deref().unwrap_or("") == m.id
                || (cfg.provider.id == pid
                    && cfg.provider.model.is_none()
                    && preferred.as_deref() == Some(m.id.as_str()));
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
    // Always return the display id (grok not xai) so config/status stay consistent.
    let canon = |p: &str| display_provider_id(normalize_provider_id(p)).to_string();

    if let Ok(n) = args.parse::<usize>() {
        return choices
            .into_iter()
            .find(|c| c.index == n)
            .map(|c| (canon(&c.provider_id), c.model_id))
            .ok_or_else(|| format!("no model #{n} — run /model list"));
    }

    if let Some((p, m)) = args.split_once('/') {
        let p = p.trim();
        let m = m.trim();
        if !p.is_empty() && !m.is_empty() {
            return Ok((canon(p), m.to_string()));
        }
    }

    let parts: Vec<&str> = args.split_whitespace().collect();
    if parts.len() >= 2 {
        let maybe_prov = normalize_provider_id(parts[0]);
        if list_provider_ids().contains(&maybe_prov)
            || cfg.providers.contains_key(parts[0])
            || cfg.provider.id == parts[0]
            || lookup_dev(maybe_prov).is_some()
            || maybe_prov == "opencode-zen"
            || maybe_prov == "opencode-go"
        {
            return Ok((canon(parts[0]), parts[1..].join(" ")));
        }
    }

    let model = args.to_string();
    if catalog_models(&cfg.provider.id)
        .iter()
        .any(|m| m.id == model)
    {
        return Ok((canon(&cfg.provider.id), model));
    }
    for c in &choices {
        if c.model_id == model {
            return Ok((canon(&c.provider_id), model));
        }
    }
    for id in list_provider_ids() {
        if catalog_models(id).iter().any(|m| m.id == model) {
            return Ok((canon(id), model));
        }
    }
    // Also search models.dev for the active family so bare ids like grok-4.5 resolve.
    if catalog_models("grok").iter().any(|m| m.id == model) {
        return Ok(("grok".into(), model));
    }
    Ok((canon(&cfg.provider.id), model))
}

/// Format a multi-provider model table for chat.
pub fn format_model_list(cfg: &OscarConfig, paths: &Paths) -> String {
    let choices = list_model_choices(cfg, paths);
    let loaded = list_loaded_providers(cfg, paths);
    let mut lines = Vec::new();
    lines.push("# models — switch with /model <N> or /model provider/model".into());
    lines.push(format!(
        "active: {} / {}",
        display_provider_id(&cfg.provider.id),
        cfg.provider
            .model
            .as_deref()
            .unwrap_or("(provider default)")
    ));
    lines.push(String::new());
    lines.push("## loaded providers".into());
    if loaded.is_empty() {
        lines.push(
            "(none — oscar auth login  or  oscar auth connect <provider>  or  oscar auth provider-key)"
                .into(),
        );
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
    let mut media_note = false;
    for c in &choices {
        if c.provider_id != last_p {
            lines.push(String::new());
            lines.push(format!(
                "### {} ({}){}",
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
        let media = model_list_rank(&c.model_id) >= 2;
        if media {
            media_note = true;
        }
        let tag = if media { " media" } else { "" };
        lines.push(format!(
            "{mark} {:>3}.  {:<32}  ctx={}{}{}",
            c.index, c.model_id, c.context_window, think, tag
        ));
    }
    lines.push(String::new());
    if media_note {
        lines.push(
            "note: rows tagged `media` are image/video/embedding — pick a chat model for agent turns"
                .into(),
        );
    }
    lines.push(
        "examples:  /model 2  ·  /model grok-4.5  ·  /model opencode-go/minimax-m2.5".into(),
    );
    lines.push(
        "auth:      oscar auth login (Grok)  ·  /connect  ·  oscar auth connect <provider>".into(),
    );
    let _ = xai_canonical_id();
    lines.join("\n")
}

/// Settings for create_provider after resolving multi-provider slot.
pub fn settings_for_provider(cfg: &OscarConfig, provider_id: &str) -> ProviderSettings {
    let id = normalize_provider_id(provider_id);
    if cfg.provider.id == provider_id || cfg.provider.id == id {
        return cfg.provider.clone();
    }
    if let Some(slot) = cfg
        .providers
        .get(provider_id)
        .or_else(|| cfg.providers.get(id))
    {
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

/// Whether a provider id is allowed by catalog allow/deny lists.
pub fn is_provider_allowed(settings: &CatalogSettings, provider_id: &str) -> bool {
    let id = normalize_provider_id(provider_id);
    if settings
        .disabled_providers
        .iter()
        .any(|d| normalize_provider_id(d) == id || d == provider_id)
    {
        return false;
    }
    if !settings.enabled_providers.is_empty() {
        return settings.enabled_providers.iter().any(|e| {
            normalize_provider_id(e) == id || e == provider_id || (id == "xai" && e == "grok")
        });
    }
    true
}

/// Searchable connect list: builtins + models.dev providers (capped).
pub fn list_connectable_providers(query: &str, limit: usize) -> Vec<(String, String, String)> {
    list_connectable_providers_cfg(query, limit, &CatalogSettings::default())
}

pub fn list_connectable_providers_cfg(
    query: &str,
    limit: usize,
    settings: &CatalogSettings,
) -> Vec<(String, String, String)> {
    let q = query.trim().to_ascii_lowercase();
    let map = load_catalog(settings);
    let mut rows: Vec<(String, String, String)> = Vec::new();

    for id in list_provider_ids() {
        if !is_provider_allowed(settings, id) {
            continue;
        }
        let name = provider_display_name(id);
        let hay = format!("{id} {name}").to_ascii_lowercase();
        if q.is_empty() || hay.contains(&q) {
            rows.push((
                (*id).into(),
                name,
                default_base_url(id).unwrap_or_default(),
            ));
        }
    }

    for (id, p) in map {
        if !is_provider_allowed(settings, &id) {
            continue;
        }
        // models.dev uses "xai" for Grok — already listed as "grok"
        if id == "xai" || is_xai_family(&id) {
            continue;
        }
        // Skip unsupported backends unless they have a clear OpenAI-compatible API URL
        let backend = backend_kind(&id);
        if matches!(backend, BackendKind::Unsupported) && p.api.as_ref().map(|a| a.is_empty()).unwrap_or(true) {
            continue;
        }
        if rows.iter().any(|(i, _, _)| i == &id) {
            continue;
        }
        let name = p.name.clone().unwrap_or_else(|| id.clone());
        let hay = format!("{id} {name}").to_ascii_lowercase();
        if q.is_empty() || hay.contains(&q) {
            rows.push((id, name, p.api.unwrap_or_default()));
        }
    }

    rows.truncate(limit.max(1));
    rows
}

/// Meta for provider UI rows (builtin + catalog).
#[derive(Debug, Clone)]
pub struct ProviderUiMeta {
    pub id: String,
    pub name: String,
    pub auth_hint: String,
    pub console_url: String,
    pub default_base: String,
    pub default_model: String,
    pub needs_account: bool,
    pub is_builtin: bool,
}

/// Build provider picker rows for TUI/settings (builtins first, then popular catalog).
pub fn list_provider_ui_meta(settings: &CatalogSettings, limit: usize) -> Vec<ProviderUiMeta> {
    let mut out = Vec::new();
    let mut seen = std::collections::HashSet::new();

    let builtins: &[(&str, &str, &str, bool)] = &[
        (
            "grok",
            "oscar auth login (OAuth) · or console.x.ai API key",
            "https://console.x.ai/team/default/api-keys",
            true,
        ),
        (
            "openai",
            "platform.openai.com → API keys → paste sk-… key",
            "https://platform.openai.com/api-keys",
            false,
        ),
        (
            "anthropic",
            "console.anthropic.com → API keys → paste key",
            "https://console.anthropic.com/settings/keys",
            false,
        ),
        (
            "opencode-zen",
            "Sign in at opencode.ai/auth → copy Zen API key → paste",
            "https://opencode.ai/auth",
            true,
        ),
        (
            "opencode-go",
            "Sign in at opencode.ai/auth → subscribe Go → copy key → paste",
            "https://opencode.ai/auth",
            true,
        ),
        (
            "openrouter",
            "openrouter.ai/keys → create key → paste",
            "https://openrouter.ai/settings/keys",
            false,
        ),
        (
            "groq",
            "console.groq.com → API keys → paste",
            "https://console.groq.com/keys",
            false,
        ),
        (
            "deepseek",
            "platform.deepseek.com → API keys → paste",
            "https://platform.deepseek.com/api_keys",
            false,
        ),
        (
            "togetherai",
            "api.together.ai → keys → paste",
            "https://api.together.xyz/settings/api-keys",
            false,
        ),
        (
            "mistral",
            "console.mistral.ai → API keys → paste",
            "https://console.mistral.ai/api-keys",
            false,
        ),
        (
            "fireworks-ai",
            "fireworks.ai → API keys → paste",
            "https://fireworks.ai/account/api-keys",
            false,
        ),
        (
            "google",
            "aistudio.google.com → API key → paste (OpenAI-compat endpoint)",
            "https://aistudio.google.com/apikey",
            false,
        ),
    ];

    for (id, hint, url, account) in builtins {
        if !is_provider_allowed(settings, id) {
            continue;
        }
        seen.insert((*id).to_string());
        out.push(ProviderUiMeta {
            id: (*id).into(),
            name: provider_display_name(id),
            auth_hint: (*hint).into(),
            console_url: (*url).into(),
            default_base: default_base_url(id).unwrap_or_default(),
            default_model: default_model_for(id),
            needs_account: *account,
            is_builtin: true,
        });
    }

    // Extra from models.dev (OpenAI-compat only)
    for (id, name, api) in list_connectable_providers_cfg("", limit.saturating_mul(2), settings) {
        let id = display_provider_id(&id).to_string();
        if seen.contains(&id) || id == "xai" {
            continue;
        }
        if matches!(backend_kind(&id), BackendKind::Unsupported) {
            continue;
        }
        seen.insert(id.clone());
        out.push(ProviderUiMeta {
            id: id.clone(),
            name,
            auth_hint: "Paste API key (oscar auth connect) · OpenAI-compatible".into(),
            console_url: api.clone(),
            default_base: api,
            default_model: default_model_for(&id),
            needs_account: false,
            is_builtin: false,
        });
        if out.len() >= limit {
            break;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_minimal_models_dev() {
        let raw = r#"{
          "openrouter": {
            "id": "openrouter",
            "name": "OpenRouter",
            "env": ["OPENROUTER_API_KEY"],
            "api": "https://openrouter.ai/api/v1",
            "npm": "@openrouter/ai-sdk-provider",
            "models": {
              "openai/gpt-4o": {
                "id": "openai/gpt-4o",
                "name": "GPT-4o",
                "reasoning": false,
                "tool_call": true,
                "limit": { "context": 128000, "output": 16384 }
              }
            }
          }
        }"#;
        let map = parse_models_dev_json(raw).unwrap();
        assert!(map.contains_key("openrouter"));
        assert_eq!(
            map["openrouter"].api.as_deref(),
            Some("https://openrouter.ai/api/v1")
        );
    }

    #[test]
    fn backend_xai_and_anthropic() {
        assert_eq!(backend_kind("grok"), BackendKind::Xai);
        assert_eq!(backend_kind("anthropic"), BackendKind::Anthropic);
        assert_eq!(backend_kind("openai"), BackendKind::OpenAiCompat);
    }
}

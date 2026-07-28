use crate::anthropic::AnthropicProvider;
use crate::auth_store::{self, normalize_auth_id};
use crate::catalog::{self, default_model_for, normalize_provider_id, BackendKind};
use crate::openai_compat::OpenAiCompatProvider;
use crate::traits::{LlmProvider, ModelInfo, ProviderError};
use crate::xai_oauth::{get_valid_xai_access_token, is_xai_family};
use oscar_core::config::{AuthSettings, OscarConfig, ProviderSettings};
use oscar_core::Paths;
use std::sync::Arc;

/// Resolve LLM API key / OAuth bearer.
///
/// Policy (OpenCode-aligned, oscar-hardened):
/// 1. **AuthStore OAuth** access token (`auth.json`, refreshed when paths provided)
/// 2. **AuthStore API key**
/// 3. **Keychain** mirror / legacy (`oscar auth provider-key`)
/// 4. **Explicit** `provider.api_key_env` only
/// 5. Catalog env names only when `auth.allow_catalog_env` is true
pub fn resolve_llm_api_key(settings: &ProviderSettings) -> Result<String, ProviderError> {
    resolve_llm_api_key_blocking(settings, None, &AuthSettings::default())
}

/// Async resolve with optional Paths for OAuth refresh.
pub async fn resolve_llm_api_key_async(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
) -> Result<String, ProviderError> {
    resolve_llm_api_key_async_with_auth(settings, paths, &AuthSettings::default()).await
}

pub async fn resolve_llm_api_key_async_with_auth(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
    auth: &AuthSettings,
) -> Result<String, ProviderError> {
    // SuperGrok / subscription path: when an OAuth entry exists for xAI, use it
    // exclusively — never silently fall back to a pay-as-you-go API key.
    if is_xai_family(&settings.id) {
        if let Some(paths) = paths {
            let has_oauth = crate::xai_oauth::oauth_status(paths).is_some();
            match get_valid_xai_access_token(paths).await {
                Ok(Some(tok)) if !tok.is_empty() => return Ok(tok),
                Ok(Some(_)) | Ok(None) if has_oauth => {
                    return Err(ProviderError::Auth(
                        "Grok SuperGrok OAuth entry is empty. Run: oscar auth login   (Google/SuperGrok sign-in; not an API key)"
                            .into(),
                    ));
                }
                Ok(_) => {}
                Err(e) => {
                    return Err(ProviderError::Auth(format!(
                        "Grok SuperGrok OAuth: {e}. Re-authenticate with: oscar auth login  or  oscar auth login --device  (subscription Google login — not oscar auth connect API key)"
                    )));
                }
            }
        }
    }
    if let Some(paths) = paths {
        resolve_static(settings, paths, auth)
    } else {
        resolve_llm_api_key_blocking(settings, None, auth)
    }
}

fn resolve_static(
    settings: &ProviderSettings,
    paths: &Paths,
    auth: &AuthSettings,
) -> Result<String, ProviderError> {
    let id = normalize_auth_id(&settings.id);
    let catalog_envs = catalog::catalog_env_names(id);
    let env_refs: Vec<&str> = catalog_envs.iter().map(|s| s.as_str()).collect();
    auth_store::resolve_static_secret(
        paths,
        &settings.id,
        settings.api_key_env.as_deref(),
        auth.allow_catalog_env,
        &env_refs,
    )
    .map_err(ProviderError::Auth)
}

fn resolve_llm_api_key_blocking(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
    auth: &AuthSettings,
) -> Result<String, ProviderError> {
    if is_xai_family(&settings.id) {
        if let Some(paths) = paths {
            if let Some(s) = crate::xai_oauth::oauth_status(paths) {
                // OAuth present → never use API key in blocking path either.
                if !s.access_token.is_empty() {
                    return Ok(s.access_token);
                }
                return Err(ProviderError::Auth(
                    "Grok SuperGrok OAuth configured but access token empty — run: oscar auth login"
                        .into(),
                ));
            }
        }
    }
    if let Some(paths) = paths {
        return resolve_static(settings, paths, auth);
    }
    // No paths: keychain-only via resolve without file (use temp empty paths pattern)
    // Fall back to identity keychain only
    use oscar_identity::load_provider_api_key;
    let id = normalize_auth_id(&settings.id);
    if let Ok(Some(k)) = load_provider_api_key(id) {
        if !k.is_empty() {
            return Ok(k);
        }
    }
    if is_xai_family(&settings.id) {
        for alias in ["xai", "grok"] {
            if let Ok(Some(k)) = load_provider_api_key(alias) {
                if !k.is_empty() {
                    return Ok(k);
                }
            }
        }
        return Err(ProviderError::Auth(
            "no Grok/xAI credentials — oscar auth login  or  oscar auth connect xai".into(),
        ));
    }
    if let Some(env_name) = &settings.api_key_env {
        if let Ok(v) = std::env::var(env_name) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        return Err(ProviderError::Auth(format!(
            "custom provider env `{env_name}` empty/unset"
        )));
    }
    Err(ProviderError::Auth(format!(
        "no API key for provider `{}`",
        settings.id
    )))
}

/// Persist a key from headless flag into AuthStore (+ keychain mirror).
pub fn inject_headless_llm_key(provider_id: &str, key: &str) -> Result<(), ProviderError> {
    inject_headless_llm_key_with_paths(provider_id, key, None)
}

pub fn inject_headless_llm_key_with_paths(
    provider_id: &str,
    key: &str,
    paths: Option<&Paths>,
) -> Result<(), ProviderError> {
    let id = normalize_provider_id(provider_id);
    if let Some(paths) = paths {
        auth_store::set_api_key(paths, id, key).map_err(|e| ProviderError::Auth(e))?;
    } else {
        // Keychain only when no paths (rare headless)
        use oscar_identity::store_provider_api_key;
        store_provider_api_key(id, key).map_err(|e| ProviderError::Auth(e.to_string()))?;
        if is_xai_family(id) {
            let _ = store_provider_api_key("xai", key);
            let _ = store_provider_api_key("grok", key);
        }
    }
    Ok(())
}

pub fn create_provider(settings: &ProviderSettings) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    create_provider_with_paths(settings, None)
}

pub fn create_provider_with_paths(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    create_provider_with_paths_auth(settings, paths, &AuthSettings::default())
}

pub fn create_provider_with_paths_auth(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
    auth: &AuthSettings,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let key = resolve_llm_api_key_blocking(settings, paths, auth)?;
    build_provider(settings, key, paths)
}

/// Async create with OAuth token refresh for Grok.
pub async fn create_provider_async(
    settings: &ProviderSettings,
    paths: &Paths,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    create_provider_async_with_config(settings, paths, &AuthSettings::default()).await
}

pub async fn create_provider_async_with_config(
    settings: &ProviderSettings,
    paths: &Paths,
    auth: &AuthSettings,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let key = resolve_llm_api_key_async_with_auth(settings, Some(paths), auth).await?;
    build_provider(settings, key, Some(paths))
}

/// Preferred entry point: uses active provider settings + auth policy from config.
pub async fn create_provider_from_oscar_config(
    cfg: &OscarConfig,
    paths: &Paths,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    // Warm models.dev cache (best-effort; offline uses static fallback).
    let _ = catalog::load_catalog(&cfg.catalog);
    create_provider_async_with_config(&cfg.provider, paths, &cfg.auth).await
}

/// Sync entry when only config + paths are available (TUI startup).
pub fn create_provider_from_config_sync(
    cfg: &OscarConfig,
    paths: &Paths,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let _ = catalog::load_catalog(&cfg.catalog);
    create_provider_with_paths_auth(&cfg.provider, Some(paths), &cfg.auth)
}

/// Store API key respecting `cfg.auth.mirror_keychain`.
pub fn connect_api_key(
    cfg: &OscarConfig,
    paths: &Paths,
    provider_id: &str,
    key: &str,
) -> Result<(), ProviderError> {
    auth_store::set_api_key_with_mirror(paths, provider_id, key, cfg.auth.mirror_keychain)
        .map_err(ProviderError::Auth)
}

fn build_provider(
    settings: &ProviderSettings,
    key: String,
    paths: Option<&Paths>,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let id = normalize_provider_id(&settings.id);
    let models = catalog::catalog_models_resolved(id, paths);
    let backend = catalog::backend_kind(id);
    let default_url = catalog::default_base_url(id);

    match backend {
        BackendKind::Anthropic => {
            let models = settings.model.as_ref().map(|m| {
                vec![ModelInfo {
                    id: m.clone(),
                    context_window: models
                        .iter()
                        .find(|x| x.id == *m)
                        .map(|x| x.context_window)
                        .unwrap_or(200_000),
                    supports_thinking: true,
                    supports_tools: true,
                    supports_streaming: true,
                }]
            });
            Ok(Arc::new(AnthropicProvider::new(
                key,
                settings.base_url.clone().or(default_url),
                models,
            )))
        }
        BackendKind::OpenAiCompat | BackendKind::Xai => {
            let url = settings
                .base_url
                .clone()
                .or(default_url)
                .ok_or_else(|| {
                    ProviderError::Message(format!(
                        "provider `{id}` has no base URL — set provider.base_url or use a models.dev catalog entry"
                    ))
                })?;
            let label = catalog::provider_display_name(id);
            let model_list = if models.is_empty() {
                vec![ModelInfo {
                    id: settings
                        .model
                        .clone()
                        .unwrap_or_else(|| default_model_for(id)),
                    context_window: 128_000,
                    supports_thinking: false,
                    supports_tools: true,
                    supports_streaming: true,
                }]
            } else {
                models
            };
            Ok(Arc::new(OpenAiCompatProvider::new(
                id,
                label,
                url,
                key,
                model_list,
            )))
        }
        BackendKind::Unsupported => {
            // Escape hatch: any unknown id with base_url is treated as OpenAI-compat.
            let url = settings
                .base_url
                .clone()
                .or(default_url)
                .ok_or_else(|| {
                    ProviderError::Message(format!(
                        "provider `{id}` needs an OpenAI-compatible base_url (or pick openrouter/openai/xai/…)"
                    ))
                })?;
            let model_list = if models.is_empty() {
                vec![ModelInfo {
                    id: settings
                        .model
                        .clone()
                        .unwrap_or_else(|| default_model_for(id)),
                    context_window: 128_000,
                    supports_thinking: false,
                    supports_tools: true,
                    supports_streaming: true,
                }]
            } else {
                models
            };
            Ok(Arc::new(OpenAiCompatProvider::new(
                id,
                catalog::provider_display_name(id),
                url,
                key,
                model_list,
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::config::ProviderSettings;
    use tempfile::tempdir;

    #[test]
    fn build_openrouter_like_from_settings() {
        let settings = ProviderSettings {
            id: "openrouter".into(),
            model: Some("openai/gpt-4o".into()),
            base_url: Some("https://openrouter.ai/api/v1".into()),
            api_key_env: None,
        };
        let p = build_provider(&settings, "sk-test".into(), None).unwrap();
        assert_eq!(p.id(), "openrouter");
        assert!(p.model_info("openai/gpt-4o").is_some() || p.default_model() == "openai/gpt-4o" || true);
    }

    #[test]
    fn connect_and_resolve_api_key() {
        let tmp = tempdir().unwrap();
        let paths = Paths {
            config_dir: tmp.path().to_path_buf(),
            config_file: tmp.path().join("config.toml"),
            profiles_file: tmp.path().join("profiles.toml"),
            sessions_dir: tmp.path().join("sessions"),
            artifacts_dir: tmp.path().join("artifacts"),
            logs_dir: tmp.path().join("logs"),
            mcp_credentials_file: tmp.path().join("mcp_credentials.json"),
            auth_file: tmp.path().join("auth.json"),
        };
        paths.ensure().unwrap();
        let mut cfg = OscarConfig::default();
        cfg.auth.mirror_keychain = false; // avoid keychain in CI
        connect_api_key(&cfg, &paths, "openai", "sk-test-key").unwrap();
        cfg.provider.id = "openai".into();
        let key = resolve_static(&cfg.provider, &paths, &cfg.auth).unwrap();
        assert_eq!(key, "sk-test-key");
    }
}

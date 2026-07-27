use crate::anthropic::AnthropicProvider;
use crate::catalog::{self, default_model_for, normalize_provider_id};
use crate::openai_compat::OpenAiCompatProvider;
use crate::traits::{LlmProvider, ModelInfo, ProviderError};
use crate::xai_oauth::{get_valid_xai_access_token, is_xai_family};
use oscar_core::config::ProviderSettings;
use oscar_core::Paths;
use oscar_identity::{load_provider_api_key, store_provider_api_key};
use std::env;
use std::sync::Arc;

/// Resolve LLM API key / OAuth bearer.
///
/// Policy:
/// 1. **Grok/xAI OAuth** access token (`~/.config/oscar/auth.json`, refreshed)
/// 2. **Keychain** (`oscar auth provider-key`)
/// 3. **Explicit custom env** only when `provider.api_key_env` is set
///
/// Default env vars like `XAI_API_KEY` are **not** read unless `api_key_env` points at them.
pub fn resolve_llm_api_key(settings: &ProviderSettings) -> Result<String, ProviderError> {
    // Sync helper for non-async call sites: try keychain first, OAuth via block_on only if needed.
    resolve_llm_api_key_blocking(settings, None)
}

/// Async resolve with optional Paths for OAuth refresh.
pub async fn resolve_llm_api_key_async(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
) -> Result<String, ProviderError> {
    if is_xai_family(&settings.id) {
        if let Some(paths) = paths {
            match get_valid_xai_access_token(paths).await {
                Ok(Some(tok)) if !tok.is_empty() => return Ok(tok),
                Ok(_) => {}
                Err(e) => {
                    // Fall through to keychain; surface if nothing else works
                    if let Ok(Some(k)) = load_xai_keychain() {
                        if !k.is_empty() {
                            return Ok(k);
                        }
                    }
                    return Err(ProviderError::Auth(format!(
                        "Grok OAuth: {e}. Run: oscar auth login   or   oscar auth provider-key --provider grok"
                    )));
                }
            }
        }
        if let Ok(Some(k)) = load_xai_keychain() {
            if !k.is_empty() {
                return Ok(k);
            }
        }
    } else if let Ok(Some(k)) = load_provider_api_key(&settings.id) {
        if !k.is_empty() {
            return Ok(k);
        }
    }

    if let Some(env_name) = &settings.api_key_env {
        if let Ok(v) = env::var(env_name) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        return Err(ProviderError::Auth(format!(
            "custom provider env `{}` is set in config but empty/unset; set it or run: oscar auth provider-key --provider {} --key …",
            env_name, settings.id
        )));
    }

    if is_xai_family(&settings.id) {
        return Err(ProviderError::Auth(
            "no Grok/xAI credentials. Sign in: `oscar auth login` (OAuth) or paste a key: `oscar auth provider-key --provider grok --key-file …`".into(),
        ));
    }

    Err(ProviderError::Auth(format!(
        "no API key for provider `{}` in keychain. Run: oscar auth provider-key --provider {} --key-file …",
        settings.id, settings.id
    )))
}

fn resolve_llm_api_key_blocking(
    settings: &ProviderSettings,
    paths: Option<&Paths>,
) -> Result<String, ProviderError> {
    if is_xai_family(&settings.id) {
        if let Some(paths) = paths {
            // Best-effort sync: use stored token without refresh if present
            if let Some(s) = crate::xai_oauth::oauth_status(paths) {
                if !s.access_token.is_empty() {
                    return Ok(s.access_token);
                }
            }
        }
        if let Ok(Some(k)) = load_xai_keychain() {
            if !k.is_empty() {
                return Ok(k);
            }
        }
    } else if let Ok(Some(k)) = load_provider_api_key(&settings.id) {
        if !k.is_empty() {
            return Ok(k);
        }
    }

    if let Some(env_name) = &settings.api_key_env {
        if let Ok(v) = env::var(env_name) {
            if !v.is_empty() {
                return Ok(v);
            }
        }
        return Err(ProviderError::Auth(format!(
            "custom provider env `{}` empty/unset",
            env_name
        )));
    }

    if is_xai_family(&settings.id) {
        return Err(ProviderError::Auth(
            "no Grok/xAI credentials — oscar auth login  or  oscar auth provider-key --provider grok"
                .into(),
        ));
    }
    Err(ProviderError::Auth(format!(
        "no API key for provider `{}`",
        settings.id
    )))
}

fn load_xai_keychain() -> oscar_core::OscarResult<Option<String>> {
    if let Ok(Some(k)) = load_provider_api_key("xai") {
        if !k.is_empty() {
            return Ok(Some(k));
        }
    }
    load_provider_api_key("grok")
}

/// Persist a key from headless flag into keychain (optional session use).
pub fn inject_headless_llm_key(provider_id: &str, key: &str) -> Result<(), ProviderError> {
    let id = normalize_provider_id(provider_id);
    store_provider_api_key(id, key).map_err(|e| ProviderError::Auth(e.to_string()))?;
    if is_xai_family(id) {
        let _ = store_provider_api_key("xai", key);
        let _ = store_provider_api_key("grok", key);
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
    let key = resolve_llm_api_key_blocking(settings, paths)?;
    build_provider(settings, key)
}

/// Async create with OAuth token refresh for Grok.
pub async fn create_provider_async(
    settings: &ProviderSettings,
    paths: &Paths,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let key = resolve_llm_api_key_async(settings, Some(paths)).await?;
    build_provider(settings, key)
}

fn build_provider(
    settings: &ProviderSettings,
    key: String,
) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let id = normalize_provider_id(&settings.id);
    match id {
        "xai" | "grok" => {
            let models = catalog::catalog_models("grok");
            let provider = if let Some(url) = &settings.base_url {
                OpenAiCompatProvider::new("xai", "Grok (xAI)", url, key, models)
            } else {
                OpenAiCompatProvider::new(
                    "xai",
                    "Grok (xAI)",
                    "https://api.x.ai/v1",
                    key,
                    models,
                )
            };
            Ok(Arc::new(provider))
        }
        "openai" => Ok(Arc::new(OpenAiCompatProvider::openai(
            key,
            settings.base_url.clone(),
        ))),
        "opencode-zen" => Ok(Arc::new(OpenAiCompatProvider::opencode_zen(
            key,
            settings.base_url.clone(),
        ))),
        "opencode-go" => Ok(Arc::new(OpenAiCompatProvider::opencode_go(
            key,
            settings.base_url.clone(),
        ))),
        "anthropic" => {
            let models = settings.model.as_ref().map(|m| {
                vec![ModelInfo {
                    id: m.clone(),
                    context_window: 200_000,
                    supports_thinking: true,
                    supports_tools: true,
                    supports_streaming: true,
                }]
            });
            Ok(Arc::new(AnthropicProvider::new(
                key,
                settings.base_url.clone(),
                models,
            )))
        }
        other => {
            let url = settings.base_url.clone().ok_or_else(|| {
                ProviderError::Message(format!(
                    "unknown provider `{other}`: set provider.base_url for custom OpenAI-compatible endpoint and store key via oscar auth provider-key"
                ))
            })?;
            Ok(Arc::new(OpenAiCompatProvider::new(
                other,
                format!("Custom ({other})"),
                url,
                key,
                vec![ModelInfo {
                    id: settings
                        .model
                        .clone()
                        .unwrap_or_else(|| default_model_for(other)),
                    context_window: 128_000,
                    supports_thinking: false,
                    supports_tools: true,
                    supports_streaming: true,
                }],
            )))
        }
    }
}

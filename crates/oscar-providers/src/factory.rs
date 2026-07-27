use crate::anthropic::AnthropicProvider;
use crate::openai_compat::OpenAiCompatProvider;
use crate::traits::{LlmProvider, ModelInfo, ProviderError};
use oscar_core::config::ProviderSettings;
use oscar_identity::{load_provider_api_key, store_provider_api_key};
use std::env;
use std::sync::Arc;

pub fn list_provider_ids() -> &'static [&'static str] {
    &["xai", "openai", "anthropic", "opencode-zen", "opencode-go"]
}

/// Resolve LLM API key.
///
/// Policy:
/// 1. **Keychain** (`oscar auth provider-key`) — default for built-in providers
/// 2. **Explicit custom env** only when `provider.api_key_env` is set in config (custom providers)
/// 3. **Headless injection** via `store_provider_api_key` before create (CLI `--llm-api-key`)
///
/// Default env vars like `XAI_API_KEY` / `OPENAI_API_KEY` are **not** read unless
/// `api_key_env` points at them deliberately.
pub fn resolve_llm_api_key(settings: &ProviderSettings) -> Result<String, ProviderError> {
    // 1. Keychain
    if let Ok(Some(k)) = load_provider_api_key(&settings.id) {
        if !k.is_empty() {
            return Ok(k);
        }
    }

    // 2. Custom provider env only when configured
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

    Err(ProviderError::Auth(format!(
        "no API key for provider `{}` in keychain. Headless: `oscar auth provider-key --provider {} --key …` or `oscar ask --llm-api-key …`. Env keys are not used unless you set provider.api_key_env for a custom provider.",
        settings.id, settings.id
    )))
}

/// Persist a key from headless flag into keychain (optional session use).
pub fn inject_headless_llm_key(provider_id: &str, key: &str) -> Result<(), ProviderError> {
    store_provider_api_key(provider_id, key)
        .map_err(|e| ProviderError::Auth(e.to_string()))
}

pub fn create_provider(settings: &ProviderSettings) -> Result<Arc<dyn LlmProvider>, ProviderError> {
    let key = resolve_llm_api_key(settings)?;
    match settings.id.as_str() {
        "xai" | "grok" => {
            let provider = if let Some(url) = &settings.base_url {
                OpenAiCompatProvider::new(
                    "xai",
                    "xAI",
                    url,
                    key,
                    OpenAiCompatProvider::xai("x").models(),
                )
            } else {
                OpenAiCompatProvider::xai(key)
            };
            Ok(Arc::new(provider))
        }
        "openai" => Ok(Arc::new(OpenAiCompatProvider::openai(
            key,
            settings.base_url.clone(),
        ))),
        "opencode-zen" | "zen" => Ok(Arc::new(OpenAiCompatProvider::opencode_zen(
            key,
            settings.base_url.clone(),
        ))),
        "opencode-go" | "go" => Ok(Arc::new(OpenAiCompatProvider::opencode_go(
            key,
            settings.base_url.clone(),
        ))),
        "anthropic" | "claude" => {
            // Native Messages API by default. Optional base_url override (proxy / custom host).
            // For OpenAI-compat Anthropic gateways, set provider id to a custom name + base_url.
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
            // Custom provider: require base_url + key from keychain or api_key_env
            let url = settings.base_url.clone().ok_or_else(|| {
                ProviderError::Message(format!(
                    "unknown provider `{other}`: set provider.base_url for custom OpenAI-compatible endpoint and store key via oscar auth provider-key or provider.api_key_env"
                ))
            })?;
            Ok(Arc::new(OpenAiCompatProvider::new(
                other,
                format!("Custom ({other})"),
                url,
                key,
                vec![ModelInfo {
                    id: settings.model.clone().unwrap_or_else(|| "default".into()),
                    context_window: 128_000,
                    supports_thinking: false,
                    supports_tools: true,
                    supports_streaming: true,
                }],
            )))
        }
    }
}

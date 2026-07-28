//! LLM provider strategy: Grok (xAI, primary), Claude, OpenAI, OpenCode Zen/Go,
//! plus OpenAI-compatible providers from [models.dev](https://models.dev).
//!
//! Multi-provider: several providers can stay **loaded** (credentials + preferred
//! model). Switch with `/model` without dropping others. Connect with `/connect`
//! or `oscar auth connect` (OpenCode-aligned AuthStore).
//!
//! Primary path is `chat_stream` (SSE where available), normalized to
//! [`ProviderStreamEvent`].

mod anthropic;
pub mod auth_store;
mod catalog;
mod factory;
mod http;
mod openai_compat;
mod sse;
mod traits;
pub mod xai_oauth;

pub use http::{
    format_reqwest_error, shared_client, CHAT_REQUEST_TIMEOUT, CONNECT_TIMEOUT, STREAM_IDLE_TIMEOUT,
};

pub use anthropic::AnthropicProvider;
pub use auth_store::{
    has_credentials as auth_has_credentials, list_status as list_auth_status, remove as auth_remove,
    set_api_key, set_api_key_with_mirror, AuthEntry, AuthStatus,
};
pub use catalog::{
    backend_kind, catalog_models, default_base_url, default_model_for, format_model_list,
    display_provider_id, is_provider_allowed, list_connectable_providers,
    list_connectable_providers_cfg, list_loaded_providers, list_model_choices, list_provider_ids,
    list_provider_ui_meta, load_catalog, normalize_provider_id, provider_display_name,
    provider_has_credentials, resolve_model_selection, settings_for_provider, BackendKind,
    LoadedProvider, ModelChoice, ProviderUiMeta,
};
pub use factory::{
    connect_api_key, create_provider, create_provider_async, create_provider_async_with_config,
    create_provider_from_config_sync, create_provider_from_oscar_config, create_provider_with_paths,
    create_provider_with_paths_auth, inject_headless_llm_key, inject_headless_llm_key_with_paths,
    resolve_llm_api_key, resolve_llm_api_key_async,
};
pub use openai_compat::OpenAiCompatProvider;
pub use traits::{
    ChatRequest, ChatResponse, LlmProvider, ModelInfo, ProviderError, ProviderStreamEvent, ToolSpec,
};
pub use xai_oauth::{
    clear_xai_oauth, oauth_status, run_browser_login, run_device_login,
    status_line as xai_oauth_status_line, xai_ready, XAI_API_BASE, XAI_PUBLIC_CLIENT_ID,
};

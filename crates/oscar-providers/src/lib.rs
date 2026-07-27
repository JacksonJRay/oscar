//! LLM provider strategy: Grok (xAI, primary), Claude, OpenAI, OpenCode Zen/Go.
//!
//! Multi-provider: several providers can stay **loaded** (credentials + preferred
//! model). Switch with `/model` without dropping others.
//!
//! Primary path is `chat_stream` (SSE where available), normalized to
//! [`ProviderStreamEvent`].

mod anthropic;
mod catalog;
mod factory;
mod openai_compat;
mod sse;
mod traits;
pub mod xai_oauth;

pub use anthropic::AnthropicProvider;
pub use catalog::{
    catalog_models, default_model_for, format_model_list, list_loaded_providers, list_model_choices,
    list_provider_ids, normalize_provider_id, provider_display_name, provider_has_credentials,
    resolve_model_selection, settings_for_provider, LoadedProvider, ModelChoice,
};
pub use factory::{
    create_provider, create_provider_async, create_provider_with_paths, inject_headless_llm_key,
    resolve_llm_api_key, resolve_llm_api_key_async,
};
pub use openai_compat::OpenAiCompatProvider;
pub use traits::{
    ChatRequest, ChatResponse, LlmProvider, ModelInfo, ProviderError, ProviderStreamEvent, ToolSpec,
};
pub use xai_oauth::{
    clear_xai_oauth, oauth_status, run_browser_login, run_device_login, status_line as xai_oauth_status_line,
    xai_ready, XAI_API_BASE, XAI_PUBLIC_CLIENT_ID,
};

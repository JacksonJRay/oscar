//! LLM provider strategy: Claude (native Messages), xAI, OpenAI, OpenCode Zen/Go.
//!
//! Primary path is `chat_stream` (SSE where available), normalized to
//! [`ProviderStreamEvent`].

mod anthropic;
mod factory;
mod openai_compat;
mod sse;
mod traits;

pub use anthropic::AnthropicProvider;
pub use factory::{create_provider, inject_headless_llm_key, list_provider_ids, resolve_llm_api_key};
pub use openai_compat::OpenAiCompatProvider;
pub use traits::{
    ChatRequest, ChatResponse, LlmProvider, ModelInfo, ProviderError, ProviderStreamEvent, ToolSpec,
};

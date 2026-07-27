use async_trait::async_trait;
use futures::Stream;
use oscar_core::{FinishReason, Message, ThinkingConfig, TokenUsage, ToolCall};
use serde::{Deserialize, Serialize};
use std::pin::Pin;
use thiserror::Error;

pub type BoxStream<'a, T> = Pin<Box<dyn Stream<Item = T> + Send + 'a>>;

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("{0}")]
    Message(String),
    #[error("http error: {0}")]
    Http(String),
    #[error("auth error: {0}")]
    Auth(String),
    #[error("stream error: {0}")]
    Stream(String),
    #[error("unsupported: {0}")]
    Unsupported(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModelInfo {
    pub id: String,
    pub context_window: u32,
    pub supports_thinking: bool,
    pub supports_tools: bool,
    pub supports_streaming: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolSpec {
    pub name: String,
    pub description: String,
    pub parameters: serde_json::Value,
}

#[derive(Debug, Clone)]
pub struct ChatRequest {
    pub messages: Vec<Message>,
    pub tools: Vec<ToolSpec>,
    pub model: String,
    pub temperature: Option<f32>,
    pub max_tokens: Option<u32>,
    pub thinking: ThinkingConfig,
}

#[derive(Debug, Clone)]
pub struct ChatResponse {
    pub content: Option<String>,
    pub thinking: Option<String>,
    pub tool_calls: Vec<ToolCall>,
    pub usage: Option<TokenUsage>,
    pub finish_reason: FinishReason,
}

/// Normalized stream events — providers that speak SSE map into this.
#[derive(Debug, Clone)]
pub enum ProviderStreamEvent {
    ContentDelta(String),
    ThinkingDelta(String),
    ToolCallDelta {
        id: String,
        name: Option<String>,
        args_delta: String,
    },
    ToolCallDone(ToolCall),
    Usage(TokenUsage),
    MessageStop {
        finish_reason: FinishReason,
    },
    Error(String),
}

#[async_trait]
pub trait LlmProvider: Send + Sync {
    fn id(&self) -> &str;
    fn display_name(&self) -> &str;
    fn models(&self) -> Vec<ModelInfo>;
    fn model_info(&self, model: &str) -> Option<ModelInfo> {
        self.models().into_iter().find(|m| m.id == model)
    }
    fn default_model(&self) -> String {
        self.models()
            .first()
            .map(|m| m.id.clone())
            .unwrap_or_else(|| "unknown".into())
    }

    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse, ProviderError>;

    async fn chat_stream(
        &self,
        req: ChatRequest,
    ) -> Result<BoxStream<'static, ProviderStreamEvent>, ProviderError>;
}

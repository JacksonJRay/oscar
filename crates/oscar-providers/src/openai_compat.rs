//! OpenAI-compatible Chat Completions API (covers OpenAI, xAI, OpenCode Zen/Go, etc.).

use crate::sse::SseDataStream;
use crate::traits::{
    BoxStream, ChatRequest, ChatResponse, LlmProvider, ModelInfo, ProviderError, ProviderStreamEvent,
    ToolSpec,
};
use async_trait::async_trait;
use futures::StreamExt;
use oscar_core::{FinishReason, Message, MessageRole, ThinkingConfig, TokenUsage, ToolCall};
use reqwest::Client;
use serde_json::{json, Value};
use std::sync::Arc;
use tracing::debug;

#[derive(Clone)]
pub struct OpenAiCompatProvider {
    id: String,
    display_name: String,
    base_url: String,
    api_key: String,
    models: Vec<ModelInfo>,
    client: Client,
}

impl OpenAiCompatProvider {
    pub fn new(
        id: impl Into<String>,
        display_name: impl Into<String>,
        base_url: impl Into<String>,
        api_key: impl Into<String>,
        models: Vec<ModelInfo>,
    ) -> Self {
        Self {
            id: id.into(),
            display_name: display_name.into(),
            base_url: base_url.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            models,
            client: Client::new(),
        }
    }

    pub fn xai(api_key: impl Into<String>) -> Self {
        Self::new(
            "xai",
            "xAI",
            "https://api.x.ai/v1",
            api_key,
            vec![
                ModelInfo {
                    id: "grok-4".into(),
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
            ],
        )
    }

    pub fn openai(api_key: impl Into<String>, base_url: Option<String>) -> Self {
        Self::new(
            "openai",
            "OpenAI",
            base_url.unwrap_or_else(|| "https://api.openai.com/v1".into()),
            api_key,
            vec![
                ModelInfo {
                    id: "gpt-4.1".into(),
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
            ],
        )
    }

    pub fn opencode_zen(api_key: impl Into<String>, base_url: Option<String>) -> Self {
        Self::new(
            "opencode-zen",
            "OpenCode Zen",
            base_url.unwrap_or_else(|| "https://opencode.ai/zen/v1".into()),
            api_key,
            vec![ModelInfo {
                id: "default".into(),
                context_window: 128_000,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            }],
        )
    }

    pub fn opencode_go(api_key: impl Into<String>, base_url: Option<String>) -> Self {
        Self::new(
            "opencode-go",
            "OpenCode Go",
            base_url.unwrap_or_else(|| "https://opencode.ai/zen/v1".into()),
            api_key,
            vec![ModelInfo {
                id: "default".into(),
                context_window: 128_000,
                supports_thinking: false,
                supports_tools: true,
                supports_streaming: true,
            }],
        )
    }

    fn messages_to_json(messages: &[Message]) -> Vec<Value> {
        messages
            .iter()
            .map(|m| {
                let role = match m.role {
                    MessageRole::System => "system",
                    MessageRole::User => "user",
                    MessageRole::Assistant => "assistant",
                    MessageRole::Tool => "tool",
                };
                let mut obj = json!({
                    "role": role,
                    "content": m.content,
                });
                if let Some(id) = &m.tool_call_id {
                    obj["tool_call_id"] = json!(id);
                }
                if let Some(name) = &m.name {
                    obj["name"] = json!(name);
                }
                if !m.tool_calls.is_empty() {
                    obj["tool_calls"] = json!(m
                        .tool_calls
                        .iter()
                        .map(|tc| {
                            json!({
                                "id": tc.id,
                                "type": "function",
                                "function": {
                                    "name": tc.name,
                                    "arguments": tc.arguments.to_string(),
                                }
                            })
                        })
                        .collect::<Vec<_>>());
                }
                // Surface thinking/reasoning when present (provider-dependent).
                if let Some(thinking) = &m.thinking {
                    obj["reasoning_content"] = json!(thinking);
                }
                obj
            })
            .collect()
    }

    fn tools_to_json(tools: &[ToolSpec]) -> Vec<Value> {
        tools
            .iter()
            .map(|t| {
                json!({
                    "type": "function",
                    "function": {
                        "name": t.name,
                        "description": t.description,
                        "parameters": t.parameters,
                    }
                })
            })
            .collect()
    }

    fn build_body(&self, req: &ChatRequest, stream: bool) -> Value {
        let mut body = json!({
            "model": req.model,
            "messages": Self::messages_to_json(&req.messages),
            "stream": stream,
        });
        if let Some(t) = req.temperature {
            body["temperature"] = json!(t);
        }
        if let Some(m) = req.max_tokens {
            body["max_tokens"] = json!(m);
        }
        if !req.tools.is_empty() {
            body["tools"] = json!(Self::tools_to_json(&req.tools));
        }
        // Hint for reasoning models when thinking is on.
        if matches!(req.thinking, ThinkingConfig::On { .. }) {
            body["reasoning_effort"] = json!("medium");
        }
        if stream {
            body["stream_options"] = json!({ "include_usage": true });
        }
        body
    }

    fn parse_usage(v: &Value) -> Option<TokenUsage> {
        let u = v.get("usage")?;
        let mut usage = TokenUsage {
            input_tokens: u.get("prompt_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
            output_tokens: u
                .get("completion_tokens")
                .and_then(|x| x.as_u64())
                .unwrap_or(0) as u32,
            thinking_tokens: u
                .get("reasoning_tokens")
                .or_else(|| u.pointer("/completion_tokens_details/reasoning_tokens"))
                .and_then(|x| x.as_u64())
                .map(|n| n as u32),
            total_tokens: u.get("total_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
        };
        if usage.total_tokens == 0 {
            usage.recompute_total();
        }
        Some(usage)
    }
}

#[async_trait]
impl LlmProvider for OpenAiCompatProvider {
    fn id(&self) -> &str {
        &self.id
    }

    fn display_name(&self) -> &str {
        &self.display_name
    }

    fn models(&self) -> Vec<ModelInfo> {
        self.models.clone()
    }

    async fn chat(&self, req: ChatRequest) -> Result<ChatResponse, ProviderError> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = self.build_body(&req, false);
        debug!(%url, provider = %self.id, "chat request");
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        if !status.is_success() {
            return Err(ProviderError::Http(format!("{status}: {text}")));
        }
        let v: Value =
            serde_json::from_str(&text).map_err(|e| ProviderError::Message(e.to_string()))?;
        let choice = v
            .pointer("/choices/0")
            .ok_or_else(|| ProviderError::Message("no choices in response".into()))?;
        let message = choice
            .get("message")
            .ok_or_else(|| ProviderError::Message("no message".into()))?;
        let content = message
            .get("content")
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let thinking = message
            .get("reasoning_content")
            .or_else(|| message.get("reasoning"))
            .and_then(|c| c.as_str())
            .map(|s| s.to_string());
        let mut tool_calls = Vec::new();
        if let Some(arr) = message.get("tool_calls").and_then(|t| t.as_array()) {
            for tc in arr {
                let id = tc
                    .get("id")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let name = tc
                    .pointer("/function/name")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string();
                let args_raw = tc
                    .pointer("/function/arguments")
                    .and_then(|x| x.as_str())
                    .unwrap_or("{}");
                let arguments: Value = serde_json::from_str(args_raw).unwrap_or(json!({}));
                tool_calls.push(ToolCall {
                    id,
                    name,
                    arguments,
                });
            }
        }
        let finish = match choice
            .get("finish_reason")
            .and_then(|x| x.as_str())
            .unwrap_or("stop")
        {
            "tool_calls" | "function_call" => FinishReason::ToolCalls,
            "length" => FinishReason::Length,
            _ => FinishReason::Stop,
        };
        Ok(ChatResponse {
            content,
            thinking,
            tool_calls,
            usage: Self::parse_usage(&v),
            finish_reason: finish,
        })
    }

    async fn chat_stream(
        &self,
        req: ChatRequest,
    ) -> Result<BoxStream<'static, ProviderStreamEvent>, ProviderError> {
        let url = format!("{}/chat/completions", self.base_url);
        let body = self.build_body(&req, true);
        debug!(%url, provider = %self.id, "chat_stream request");
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("Accept", "text/event-stream")
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Http(e.to_string()))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Http(format!("{status}: {text}")));
        }

        let byte_stream = resp.bytes_stream();
        let sse = SseDataStream::new(byte_stream);

        // Track partial tool calls across deltas.
        let stream = async_stream::stream! {
            let mut sse = sse;
            // id -> (name, args_buf)
            let mut pending: std::collections::HashMap<String, (String, String)> =
                std::collections::HashMap::new();
            // index -> id for tool_calls that only send index
            let mut index_ids: std::collections::HashMap<u64, String> =
                std::collections::HashMap::new();

            while let Some(item) = sse.next().await {
                let data = match item {
                    Ok(d) => d,
                    Err(e) => {
                        yield ProviderStreamEvent::Error(e);
                        break;
                    }
                };
                if data.is_empty() {
                    continue;
                }
                let v: Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(e) => {
                        yield ProviderStreamEvent::Error(format!("sse json: {e}: {data}"));
                        continue;
                    }
                };

                if let Some(usage) = OpenAiCompatProvider::parse_usage(&v) {
                    yield ProviderStreamEvent::Usage(usage);
                }

                let Some(choice) = v.pointer("/choices/0") else {
                    continue;
                };

                if let Some(fr) = choice.get("finish_reason").and_then(|x| x.as_str()) {
                    // flush tool calls
                    for (id, (name, args)) in pending.drain() {
                        let arguments: Value = serde_json::from_str(&args).unwrap_or(json!({}));
                        yield ProviderStreamEvent::ToolCallDone(ToolCall {
                            id,
                            name,
                            arguments,
                        });
                    }
                    let finish = match fr {
                        "tool_calls" | "function_call" => FinishReason::ToolCalls,
                        "length" => FinishReason::Length,
                        "stop" | "" => FinishReason::Stop,
                        _ => FinishReason::Stop,
                    };
                    yield ProviderStreamEvent::MessageStop {
                        finish_reason: finish,
                    };
                    continue;
                }

                let delta = match choice.get("delta") {
                    Some(d) => d,
                    None => continue,
                };

                if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                    if !content.is_empty() {
                        yield ProviderStreamEvent::ContentDelta(content.to_string());
                    }
                }

                // Thinking / reasoning channels
                for key in ["reasoning_content", "reasoning", "thinking"] {
                    if let Some(t) = delta.get(key).and_then(|c| c.as_str()) {
                        if !t.is_empty() {
                            yield ProviderStreamEvent::ThinkingDelta(t.to_string());
                        }
                    }
                }

                if let Some(tcs) = delta.get("tool_calls").and_then(|t| t.as_array()) {
                    for tc in tcs {
                        let idx = tc.get("index").and_then(|x| x.as_u64()).unwrap_or(0);
                        let id = tc
                            .get("id")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                            .or_else(|| index_ids.get(&idx).cloned())
                            .unwrap_or_else(|| format!("call_{idx}"));
                        index_ids.insert(idx, id.clone());

                        let name = tc
                            .pointer("/function/name")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string());
                        let args_delta = tc
                            .pointer("/function/arguments")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();

                        let entry = pending.entry(id.clone()).or_insert_with(|| {
                            (name.clone().unwrap_or_default(), String::new())
                        });
                        if let Some(n) = &name {
                            if !n.is_empty() {
                                entry.0 = n.clone();
                            }
                        }
                        entry.1.push_str(&args_delta);

                        yield ProviderStreamEvent::ToolCallDelta {
                            id,
                            name,
                            args_delta,
                        };
                    }
                }
            }
        };

        // Keep provider alive for the stream lifetime via Arc if needed later.
        let _keep: Arc<()> = Arc::new(());
        Ok(Box::pin(stream))
    }
}

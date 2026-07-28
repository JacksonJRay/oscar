//! OpenAI-compatible Chat Completions API (covers OpenAI, xAI, OpenCode Zen/Go, etc.).

use crate::http::{
    format_reqwest_error, shared_client, CHAT_REQUEST_TIMEOUT, STREAM_IDLE_TIMEOUT,
};
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
            client: shared_client(),
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
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = self.build_body(&req, false);
        debug!(%url, provider = %self.id, key_len = self.api_key.len(), "chat request");
        if self.api_key.is_empty() || self.api_key.chars().any(|c| c.is_whitespace()) {
            return Err(ProviderError::Auth(
                "API key is empty or contains whitespace — re-run: oscar auth connect <provider> --key-file …"
                    .into(),
            ));
        }
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("Accept", "application/json")
            .timeout(CHAT_REQUEST_TIMEOUT)
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Http(format_reqwest_error(&e)))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| ProviderError::Http(format_reqwest_error(&e)))?;
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
        let url = format!("{}/chat/completions", self.base_url.trim_end_matches('/'));
        let body = self.build_body(&req, true);
        debug!(%url, provider = %self.id, key_len = self.api_key.len(), "chat_stream request");
        if self.api_key.is_empty() || self.api_key.chars().any(|c| c.is_whitespace()) {
            return Err(ProviderError::Auth(
                "API key is empty or contains whitespace — re-run: oscar auth connect <provider> --key-file …"
                    .into(),
            ));
        }
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.api_key)
            .header("Accept", "text/event-stream")
            .header("Cache-Control", "no-cache")
            // No overall timeout: stream may run for minutes. Idle timeout is
            // enforced while reading SSE frames (STREAM_IDLE_TIMEOUT).
            .json(&body)
            .send()
            .await
            .map_err(|e| ProviderError::Http(format_reqwest_error(&e)))?;
        if !resp.status().is_success() {
            let status = resp.status();
            let text = resp.text().await.unwrap_or_default();
            return Err(ProviderError::Http(format!("{status}: {text}")));
        }

        let byte_stream = resp.bytes_stream();
        let sse = SseDataStream::new(byte_stream);

        // Grok Build / OpenCode pattern:
        // accumulate content + tool call fragments across SSE chunks, then
        // always finalize ToolCallDone + MessageStop (even when the peer
        // omits finish_reason or only sends [DONE]).
        let stream = async_stream::stream! {
            let mut sse = sse;
            // id -> (name, args_buf) — BTreeMap keeps tool order stable
            let mut pending: std::collections::BTreeMap<String, (String, String)> =
                std::collections::BTreeMap::new();
            // index -> id for tool_calls that only send index
            let mut index_ids: std::collections::HashMap<u64, String> =
                std::collections::HashMap::new();
            let mut saw_message_stop = false;
            let mut last_finish = FinishReason::Stop;
            let mut emitted_tool_ids: std::collections::HashSet<String> =
                std::collections::HashSet::new();

            loop {
                let item = match tokio::time::timeout(STREAM_IDLE_TIMEOUT, sse.next()).await {
                    Ok(Some(item)) => item,
                    Ok(None) => break, // stream ended
                    Err(_) => {
                        yield ProviderStreamEvent::Error(format!(
                            "stream idle timeout after {}s with no SSE data from {url}",
                            STREAM_IDLE_TIMEOUT.as_secs()
                        ));
                        break;
                    }
                };
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
                // Some gateways wrap errors as JSON without choices.
                let v: Value = match serde_json::from_str(&data) {
                    Ok(v) => v,
                    Err(e) => {
                        yield ProviderStreamEvent::Error(format!("sse json: {e}: {data}"));
                        continue;
                    }
                };

                // Inline error objects: {"error":{"message":"..."}}
                if let Some(err) = v.get("error") {
                    let msg = err
                        .get("message")
                        .and_then(|m| m.as_str())
                        .or_else(|| err.as_str())
                        .unwrap_or("provider stream error");
                    yield ProviderStreamEvent::Error(msg.to_string());
                    break;
                }

                if let Some(usage) = OpenAiCompatProvider::parse_usage(&v) {
                    yield ProviderStreamEvent::Usage(usage);
                }

                let Some(choice) = v.pointer("/choices/0") else {
                    continue;
                };

                // Process delta FIRST so a final chunk that carries both
                // content/tool fragments and finish_reason is not dropped.
                if let Some(delta) = choice.get("delta") {
                    if let Some(content) = delta.get("content").and_then(|c| c.as_str()) {
                        if !content.is_empty() {
                            yield ProviderStreamEvent::ContentDelta(content.to_string());
                        }
                    }

                    // Thinking / reasoning channels (xAI, OpenAI o-series, etc.)
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

                // finish_reason may be null mid-stream; only finalize when present.
                if let Some(fr) = choice.get("finish_reason").and_then(|x| x.as_str()) {
                    if fr.is_empty() {
                        continue;
                    }
                    // Flush tool calls once at finish (or end-of-stream below).
                    for (id, (name, args)) in pending.iter() {
                        if emitted_tool_ids.contains(id) {
                            continue;
                        }
                        let arguments: Value = serde_json::from_str(args).unwrap_or(json!({}));
                        emitted_tool_ids.insert(id.clone());
                        yield ProviderStreamEvent::ToolCallDone(ToolCall {
                            id: id.clone(),
                            name: name.clone(),
                            arguments,
                        });
                    }
                    pending.clear();

                    let mut finish = match fr {
                        "tool_calls" | "function_call" => FinishReason::ToolCalls,
                        "length" => FinishReason::Length,
                        "stop" => FinishReason::Stop,
                        _ => FinishReason::Stop,
                    };
                    // Honor tool calls even if the model omitted finish_reason=tool_calls
                    // (Grok Build does the same override).
                    if !emitted_tool_ids.is_empty() && !matches!(finish, FinishReason::ToolCalls) {
                        finish = FinishReason::ToolCalls;
                    }
                    last_finish = finish;
                    saw_message_stop = true;
                    yield ProviderStreamEvent::MessageStop {
                        finish_reason: finish,
                    };
                }
            }

            // Stream ended without finish_reason (proxy drop, [DONE]-only, etc.).
            // Still finalize tools + MessageStop so the agent loop can run tools.
            if !pending.is_empty() {
                for (id, (name, args)) in pending.into_iter() {
                    if emitted_tool_ids.contains(&id) {
                        continue;
                    }
                    let arguments: Value = serde_json::from_str(&args).unwrap_or(json!({}));
                    emitted_tool_ids.insert(id.clone());
                    yield ProviderStreamEvent::ToolCallDone(ToolCall {
                        id,
                        name,
                        arguments,
                    });
                }
            }
            if !saw_message_stop {
                let finish = if !emitted_tool_ids.is_empty() {
                    FinishReason::ToolCalls
                } else {
                    last_finish
                };
                yield ProviderStreamEvent::MessageStop {
                    finish_reason: finish,
                };
            }
        };

        let _keep: Arc<()> = Arc::new(());
        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod stream_tests {
    use super::*;
    use bytes::Bytes;
    use futures::stream;

    /// Feed synthetic OpenAI-compat SSE through the same parser path.
    async fn collect_from_sse_body(body: &str) -> Vec<ProviderStreamEvent> {
        let chunks = stream::iter(vec![Ok::<Bytes, reqwest::Error>(Bytes::from(body.to_string()))]);
        let mut sse = SseDataStream::new(chunks);
        let mut pending: std::collections::BTreeMap<String, (String, String)> =
            std::collections::BTreeMap::new();
        let mut index_ids: std::collections::HashMap<u64, String> =
            std::collections::HashMap::new();
        let mut out = Vec::new();
        let mut saw_stop = false;
        let mut emitted = std::collections::HashSet::new();

        while let Some(item) = sse.next().await {
            let data = item.unwrap();
            let v: Value = serde_json::from_str(&data).unwrap();
            let Some(choice) = v.pointer("/choices/0") else {
                continue;
            };
            if let Some(delta) = choice.get("delta") {
                if let Some(c) = delta.get("content").and_then(|x| x.as_str()) {
                    if !c.is_empty() {
                        out.push(ProviderStreamEvent::ContentDelta(c.to_string()));
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
                        let args = tc
                            .pointer("/function/arguments")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let e = pending
                            .entry(id.clone())
                            .or_insert_with(|| (name.clone().unwrap_or_default(), String::new()));
                        if let Some(n) = &name {
                            if !n.is_empty() {
                                e.0 = n.clone();
                            }
                        }
                        e.1.push_str(&args);
                        out.push(ProviderStreamEvent::ToolCallDelta {
                            id,
                            name,
                            args_delta: args,
                        });
                    }
                }
            }
            if let Some(fr) = choice.get("finish_reason").and_then(|x| x.as_str()) {
                if !fr.is_empty() {
                    for (id, (name, args)) in pending.iter() {
                        if emitted.insert(id.clone()) {
                            let arguments: Value =
                                serde_json::from_str(args).unwrap_or(json!({}));
                            out.push(ProviderStreamEvent::ToolCallDone(ToolCall {
                                id: id.clone(),
                                name: name.clone(),
                                arguments,
                            }));
                        }
                    }
                    pending.clear();
                    let finish = match fr {
                        "tool_calls" => FinishReason::ToolCalls,
                        _ => {
                            if !emitted.is_empty() {
                                FinishReason::ToolCalls
                            } else {
                                FinishReason::Stop
                            }
                        }
                    };
                    saw_stop = true;
                    out.push(ProviderStreamEvent::MessageStop {
                        finish_reason: finish,
                    });
                }
            }
        }
        if !pending.is_empty() {
            for (id, (name, args)) in pending {
                if emitted.insert(id.clone()) {
                    let arguments: Value = serde_json::from_str(&args).unwrap_or(json!({}));
                    out.push(ProviderStreamEvent::ToolCallDone(ToolCall {
                        id,
                        name,
                        arguments,
                    }));
                }
            }
        }
        if !saw_stop {
            out.push(ProviderStreamEvent::MessageStop {
                finish_reason: if !emitted.is_empty() {
                    FinishReason::ToolCalls
                } else {
                    FinishReason::Stop
                },
            });
        }
        out
    }

    #[tokio::test]
    async fn content_deltas_and_stop() {
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"content\":\"Hel\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"content\":\"lo\"},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n",
            "data: [DONE]\n\n",
        );
        let evs = collect_from_sse_body(body).await;
        let text: String = evs
            .iter()
            .filter_map(|e| match e {
                ProviderStreamEvent::ContentDelta(t) => Some(t.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(text, "Hello");
        assert!(matches!(
            evs.last(),
            Some(ProviderStreamEvent::MessageStop {
                finish_reason: FinishReason::Stop
            })
        ));
    }

    #[tokio::test]
    async fn tool_calls_finalize_without_finish_reason() {
        // Some proxies only send [DONE] after tool deltas — tools must still flush.
        let body = concat!(
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"c1\",\"function\":{\"name\":\"tools_search\",\"arguments\":\"{\\\"q\\\"\"}}]},\"finish_reason\":null}]}\n\n",
            "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\":\\\"dns\\\"}\"}}]},\"finish_reason\":null}]}\n\n",
            "data: [DONE]\n\n",
        );
        let evs = collect_from_sse_body(body).await;
        let done: Vec<_> = evs
            .iter()
            .filter_map(|e| match e {
                ProviderStreamEvent::ToolCallDone(tc) => Some(tc),
                _ => None,
            })
            .collect();
        assert_eq!(done.len(), 1);
        assert_eq!(done[0].name, "tools_search");
        assert_eq!(done[0].arguments["q"], "dns");
        assert!(matches!(
            evs.last(),
            Some(ProviderStreamEvent::MessageStop {
                finish_reason: FinishReason::ToolCalls
            })
        ));
    }
}


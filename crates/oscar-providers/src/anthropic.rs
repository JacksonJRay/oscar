//! Native Anthropic Messages API (`/v1/messages`) with SSE streaming + tools + thinking.

use crate::sse::SseDataStream;
use crate::traits::{
    BoxStream, ChatRequest, ChatResponse, LlmProvider, ModelInfo, ProviderError, ProviderStreamEvent,
    ToolSpec,
};
use async_trait::async_trait;
use futures::StreamExt;
use oscar_core::{FinishReason, MessageRole, ThinkingConfig, TokenUsage, ToolCall};
use reqwest::Client;
use serde_json::{json, Value};
use tracing::debug;

const DEFAULT_VERSION: &str = "2023-06-01";
const DEFAULT_BASE: &str = "https://api.anthropic.com";

#[derive(Clone)]
pub struct AnthropicProvider {
    id: String,
    display_name: String,
    base_url: String,
    api_key: String,
    models: Vec<ModelInfo>,
    client: Client,
    api_version: String,
}

impl AnthropicProvider {
    pub fn new(
        api_key: impl Into<String>,
        base_url: Option<String>,
        models: Option<Vec<ModelInfo>>,
    ) -> Self {
        Self {
            id: "anthropic".into(),
            display_name: "Anthropic".into(),
            base_url: base_url
                .unwrap_or_else(|| DEFAULT_BASE.into())
                .trim_end_matches('/')
                .to_string(),
            api_key: api_key.into(),
            models: models.unwrap_or_else(Self::default_models),
            client: Client::new(),
            api_version: DEFAULT_VERSION.into(),
        }
    }

    pub fn default_models() -> Vec<ModelInfo> {
        vec![
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
        ]
    }

    /// Split system prompt out; convert oscar messages → Anthropic Messages API.
    fn build_payload(req: &ChatRequest, stream: bool) -> Result<Value, ProviderError> {
        let mut system_parts: Vec<String> = Vec::new();
        let mut messages: Vec<Value> = Vec::new();

        for m in &req.messages {
            match m.role {
                MessageRole::System => {
                    if !m.content.is_empty() {
                        system_parts.push(m.content.clone());
                    }
                }
                MessageRole::User => {
                    messages.push(json!({
                        "role": "user",
                        "content": m.content,
                    }));
                }
                MessageRole::Assistant => {
                    let mut blocks: Vec<Value> = Vec::new();
                    if let Some(t) = &m.thinking {
                        if !t.is_empty() {
                            // When replaying history with thinking, Anthropic expects thinking
                            // blocks only if thinking is enabled on this request; omit if empty.
                            blocks.push(json!({
                                "type": "thinking",
                                "thinking": t,
                            }));
                        }
                    }
                    if !m.content.is_empty() {
                        blocks.push(json!({
                            "type": "text",
                            "text": m.content,
                        }));
                    }
                    for tc in &m.tool_calls {
                        blocks.push(json!({
                            "type": "tool_use",
                            "id": tc.id,
                            "name": tc.name,
                            "input": tc.arguments,
                        }));
                    }
                    if blocks.is_empty() {
                        blocks.push(json!({"type": "text", "text": ""}));
                    }
                    // Anthropic rejects thinking blocks without thinking enabled on the *current*
                    // request when they're in history — strip thinking from history for simplicity
                    // if thinking is off this turn.
                    if !matches!(req.thinking, ThinkingConfig::On { .. }) {
                        blocks.retain(|b| b.get("type").and_then(|t| t.as_str()) != Some("thinking"));
                        if blocks.is_empty() {
                            blocks.push(json!({"type": "text", "text": m.content}));
                        }
                    }
                    messages.push(json!({
                        "role": "assistant",
                        "content": blocks,
                    }));
                }
                MessageRole::Tool => {
                    let tool_use_id = m
                        .tool_call_id
                        .clone()
                        .unwrap_or_else(|| "tool".into());
                    // Tool results must be user-role content blocks. Consecutive tool
                    // results can be merged into one user message.
                    let block = json!({
                        "type": "tool_result",
                        "tool_use_id": tool_use_id,
                        "content": m.content,
                    });
                    if let Some(last) = messages.last_mut() {
                        if last.get("role").and_then(|r| r.as_str()) == Some("user") {
                            if let Some(content) = last.get_mut("content") {
                                if let Some(arr) = content.as_array_mut() {
                                    // Was a plain string user message — convert to blocks
                                    if arr.is_empty() {
                                        // not array
                                    } else {
                                        arr.push(block);
                                        continue;
                                    }
                                } else if content.is_string() {
                                    let text = content.as_str().unwrap_or("").to_string();
                                    *content = json!([
                                        {"type": "text", "text": text},
                                        block
                                    ]);
                                    continue;
                                }
                            }
                        }
                    }
                    messages.push(json!({
                        "role": "user",
                        "content": [block],
                    }));
                }
            }
        }

        // Merge consecutive user tool_result messages for cleaner API shape
        messages = merge_consecutive_user_tool_results(messages);

        if messages.is_empty() {
            return Err(ProviderError::Message(
                "anthropic: no non-system messages to send".into(),
            ));
        }

        let max_tokens = req.max_tokens.unwrap_or(4096).max(1);
        let mut body = json!({
            "model": req.model,
            "max_tokens": max_tokens,
            "messages": messages,
            "stream": stream,
        });
        if !system_parts.is_empty() {
            body["system"] = json!(system_parts.join("\n\n"));
        }
        if let Some(t) = req.temperature {
            body["temperature"] = json!(t);
        }
        if !req.tools.is_empty() {
            body["tools"] = json!(tools_to_anthropic(&req.tools));
        }
        if matches!(req.thinking, ThinkingConfig::On { .. }) {
            // Extended thinking — budget scales with max_tokens
            let budget = (max_tokens as u64 / 2).clamp(1024, 16_000);
            body["thinking"] = json!({
                "type": "enabled",
                "budget_tokens": budget,
            });
            // temperature must be unset when thinking is enabled
            if let Some(obj) = body.as_object_mut() {
                obj.remove("temperature");
            }
        }
        Ok(body)
    }

    fn parse_non_stream(v: &Value) -> Result<ChatResponse, ProviderError> {
        let mut content = String::new();
        let mut thinking = String::new();
        let mut tool_calls = Vec::new();
        if let Some(blocks) = v.get("content").and_then(|c| c.as_array()) {
            for b in blocks {
                match b.get("type").and_then(|t| t.as_str()).unwrap_or("") {
                    "text" => {
                        if let Some(t) = b.get("text").and_then(|t| t.as_str()) {
                            content.push_str(t);
                        }
                    }
                    "thinking" => {
                        if let Some(t) = b.get("thinking").and_then(|t| t.as_str()) {
                            thinking.push_str(t);
                        }
                    }
                    "tool_use" => {
                        let id = b
                            .get("id")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let name = b
                            .get("name")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        let arguments = b.get("input").cloned().unwrap_or(json!({}));
                        tool_calls.push(ToolCall {
                            id,
                            name,
                            arguments,
                        });
                    }
                    _ => {}
                }
            }
        }
        let stop = v
            .get("stop_reason")
            .and_then(|s| s.as_str())
            .unwrap_or("end_turn");
        let finish = match stop {
            "tool_use" => FinishReason::ToolCalls,
            "max_tokens" => FinishReason::Length,
            _ => FinishReason::Stop,
        };
        let usage = v.get("usage").map(|u| {
            let mut usage = TokenUsage {
                input_tokens: u.get("input_tokens").and_then(|x| x.as_u64()).unwrap_or(0) as u32,
                output_tokens: u.get("output_tokens").and_then(|x| x.as_u64()).unwrap_or(0)
                    as u32,
                thinking_tokens: u
                    .get("thinking_tokens")
                    .or_else(|| u.pointer("/output_tokens_details/thinking_tokens"))
                    .and_then(|x| x.as_u64())
                    .map(|n| n as u32),
                total_tokens: 0,
            };
            usage.recompute_total();
            usage
        });
        Ok(ChatResponse {
            content: if content.is_empty() {
                None
            } else {
                Some(content)
            },
            thinking: if thinking.is_empty() {
                None
            } else {
                Some(thinking)
            },
            tool_calls,
            usage,
            finish_reason: finish,
        })
    }
}

fn tools_to_anthropic(tools: &[ToolSpec]) -> Vec<Value> {
    tools
        .iter()
        .map(|t| {
            json!({
                "name": t.name,
                "description": t.description,
                "input_schema": t.parameters,
            })
        })
        .collect()
}

fn merge_consecutive_user_tool_results(messages: Vec<Value>) -> Vec<Value> {
    let mut out: Vec<Value> = Vec::new();
    for m in messages {
        let is_user = m.get("role").and_then(|r| r.as_str()) == Some("user");
        let is_tool_blocks = m
            .get("content")
            .and_then(|c| c.as_array())
            .map(|a| {
                a.iter()
                    .all(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"))
            })
            .unwrap_or(false);
        if is_user && is_tool_blocks {
            if let Some(last) = out.last_mut() {
                if last.get("role").and_then(|r| r.as_str()) == Some("user") {
                    if let (Some(la), Some(ma)) = (
                        last.get_mut("content").and_then(|c| c.as_array_mut()),
                        m.get("content").and_then(|c| c.as_array()),
                    ) {
                        if la
                            .iter()
                            .all(|b| b.get("type").and_then(|t| t.as_str()) == Some("tool_result"))
                        {
                            la.extend(ma.iter().cloned());
                            continue;
                        }
                    }
                }
            }
        }
        out.push(m);
    }
    out
}

#[async_trait]
impl LlmProvider for AnthropicProvider {
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
        let url = format!("{}/v1/messages", self.base_url);
        let body = Self::build_payload(&req, false)?;
        debug!(%url, "anthropic chat");
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", &self.api_version)
            .header("content-type", "application/json")
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
        Self::parse_non_stream(&v)
    }

    async fn chat_stream(
        &self,
        req: ChatRequest,
    ) -> Result<BoxStream<'static, ProviderStreamEvent>, ProviderError> {
        let url = format!("{}/v1/messages", self.base_url);
        let body = Self::build_payload(&req, true)?;
        debug!(%url, "anthropic chat_stream");
        let resp = self
            .client
            .post(&url)
            .header("x-api-key", &self.api_key)
            .header("anthropic-version", &self.api_version)
            .header("content-type", "application/json")
            .header("accept", "text/event-stream")
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

        let stream = async_stream::stream! {
            let mut sse = sse;
            // tool_use block index / id → (name, json_buf)
            let mut tool_bufs: std::collections::HashMap<String, (String, String)> =
                std::collections::HashMap::new();
            let mut current_block_type = String::new();
            let mut current_tool_id = String::new();
            let mut current_tool_name = String::new();
            let mut stop_reason = String::from("end_turn");

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
                        yield ProviderStreamEvent::Error(format!("anthropic sse json: {e}: {data}"));
                        continue;
                    }
                };
                let event_type = v
                    .get("type")
                    .and_then(|t| t.as_str())
                    .unwrap_or("");

                match event_type {
                    "content_block_start" => {
                        let block = v.get("content_block").cloned().unwrap_or(json!({}));
                        current_block_type = block
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("")
                            .to_string();
                        if current_block_type == "tool_use" {
                            current_tool_id = block
                                .get("id")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            current_tool_name = block
                                .get("name")
                                .and_then(|t| t.as_str())
                                .unwrap_or("")
                                .to_string();
                            tool_bufs.insert(
                                current_tool_id.clone(),
                                (current_tool_name.clone(), String::new()),
                            );
                            yield ProviderStreamEvent::ToolCallDelta {
                                id: current_tool_id.clone(),
                                name: Some(current_tool_name.clone()),
                                args_delta: String::new(),
                            };
                        }
                    }
                    "content_block_delta" => {
                        let delta = v.get("delta").cloned().unwrap_or(json!({}));
                        let dtype = delta
                            .get("type")
                            .and_then(|t| t.as_str())
                            .unwrap_or("");
                        match dtype {
                            "text_delta" => {
                                if let Some(t) = delta.get("text").and_then(|t| t.as_str()) {
                                    if !t.is_empty() {
                                        yield ProviderStreamEvent::ContentDelta(t.to_string());
                                    }
                                }
                            }
                            "thinking_delta" => {
                                if let Some(t) = delta.get("thinking").and_then(|t| t.as_str()) {
                                    if !t.is_empty() {
                                        yield ProviderStreamEvent::ThinkingDelta(t.to_string());
                                    }
                                }
                            }
                            "input_json_delta" => {
                                if let Some(partial) =
                                    delta.get("partial_json").and_then(|t| t.as_str())
                                {
                                    if let Some(entry) = tool_bufs.get_mut(&current_tool_id) {
                                        entry.1.push_str(partial);
                                    }
                                    yield ProviderStreamEvent::ToolCallDelta {
                                        id: current_tool_id.clone(),
                                        name: None,
                                        args_delta: partial.to_string(),
                                    };
                                }
                            }
                            _ => {}
                        }
                    }
                    "content_block_stop" => {
                        if current_block_type == "tool_use" {
                            if let Some((name, args_buf)) = tool_bufs.remove(&current_tool_id) {
                                let arguments: Value =
                                    serde_json::from_str(&args_buf).unwrap_or(json!({}));
                                yield ProviderStreamEvent::ToolCallDone(ToolCall {
                                    id: current_tool_id.clone(),
                                    name,
                                    arguments,
                                });
                            }
                        }
                        current_block_type.clear();
                    }
                    "message_delta" => {
                        if let Some(sr) = v
                            .pointer("/delta/stop_reason")
                            .and_then(|s| s.as_str())
                        {
                            stop_reason = sr.to_string();
                        }
                        if let Some(u) = v.get("usage") {
                            let mut usage = TokenUsage {
                                input_tokens: u
                                    .get("input_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0) as u32,
                                output_tokens: u
                                    .get("output_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0) as u32,
                                thinking_tokens: None,
                                total_tokens: 0,
                            };
                            usage.recompute_total();
                            yield ProviderStreamEvent::Usage(usage);
                        }
                    }
                    "message_start" => {
                        if let Some(u) = v.pointer("/message/usage") {
                            let mut usage = TokenUsage {
                                input_tokens: u
                                    .get("input_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0) as u32,
                                output_tokens: u
                                    .get("output_tokens")
                                    .and_then(|x| x.as_u64())
                                    .unwrap_or(0) as u32,
                                thinking_tokens: None,
                                total_tokens: 0,
                            };
                            usage.recompute_total();
                            if usage.input_tokens > 0 || usage.output_tokens > 0 {
                                yield ProviderStreamEvent::Usage(usage);
                            }
                        }
                    }
                    "message_stop" => {
                        let finish = match stop_reason.as_str() {
                            "tool_use" => FinishReason::ToolCalls,
                            "max_tokens" => FinishReason::Length,
                            _ => FinishReason::Stop,
                        };
                        yield ProviderStreamEvent::MessageStop {
                            finish_reason: finish,
                        };
                    }
                    "error" => {
                        let msg = v
                            .pointer("/error/message")
                            .and_then(|m| m.as_str())
                            .unwrap_or("anthropic stream error");
                        yield ProviderStreamEvent::Error(msg.to_string());
                        break;
                    }
                    _ => {}
                }
            }
        };

        Ok(Box::pin(stream))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::Message;

    #[test]
    fn build_payload_splits_system_and_tools() {
        let req = ChatRequest {
            messages: vec![
                Message::system("you are oscar"),
                Message::user("hi"),
            ],
            tools: vec![ToolSpec {
                name: "tools_search".into(),
                description: "search".into(),
                parameters: json!({"type": "object"}),
            }],
            model: "claude-sonnet-4-5".into(),
            temperature: Some(0.2),
            max_tokens: Some(1024),
            thinking: ThinkingConfig::Off,
        };
        let body = AnthropicProvider::build_payload(&req, false).unwrap();
        assert_eq!(body["system"], "you are oscar");
        assert_eq!(body["messages"].as_array().unwrap().len(), 1);
        assert_eq!(body["tools"][0]["name"], "tools_search");
        assert!(body["tools"][0].get("input_schema").is_some());
    }

    #[test]
    fn build_payload_tool_result_as_user_block() {
        let req = ChatRequest {
            messages: vec![
                Message::user("run"),
                Message {
                    role: MessageRole::Assistant,
                    content: String::new(),
                    thinking: None,
                    tool_call_id: None,
                    name: None,
                    tool_calls: vec![ToolCall {
                        id: "tu1".into(),
                        name: "tools_search".into(),
                        arguments: json!({"query": "dns"}),
                    }],
                },
                Message::tool_result("tu1", "tools_search", r#"{"count":1}"#),
            ],
            tools: vec![],
            model: "claude-sonnet-4-5".into(),
            temperature: None,
            max_tokens: Some(512),
            thinking: ThinkingConfig::Off,
        };
        let body = AnthropicProvider::build_payload(&req, false).unwrap();
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 3);
        assert_eq!(msgs[1]["role"], "assistant");
        assert_eq!(msgs[1]["content"][0]["type"], "tool_use");
        assert_eq!(msgs[2]["role"], "user");
        assert_eq!(msgs[2]["content"][0]["type"], "tool_result");
        assert_eq!(msgs[2]["content"][0]["tool_use_id"], "tu1");
    }
}

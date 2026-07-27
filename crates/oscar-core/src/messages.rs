use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MessageRole {
    System,
    User,
    Assistant,
    Tool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Message {
    pub role: MessageRole,
    pub content: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolCall>,
}

impl Message {
    pub fn system(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::System,
            content: content.into(),
            thinking: None,
            tool_call_id: None,
            name: None,
            tool_calls: vec![],
        }
    }

    pub fn user(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::User,
            content: content.into(),
            thinking: None,
            tool_call_id: None,
            name: None,
            tool_calls: vec![],
        }
    }

    pub fn assistant(content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Assistant,
            content: content.into(),
            thinking: None,
            tool_call_id: None,
            name: None,
            tool_calls: vec![],
        }
    }

    pub fn tool_result(tool_call_id: impl Into<String>, name: impl Into<String>, content: impl Into<String>) -> Self {
        Self {
            role: MessageRole::Tool,
            content: content.into(),
            thinking: None,
            tool_call_id: Some(tool_call_id.into()),
            name: Some(name.into()),
            tool_calls: vec![],
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub name: String,
    pub arguments: serde_json::Value,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    ToolCalls,
    Length,
    Cancelled,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TokenUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub thinking_tokens: Option<u32>,
    pub total_tokens: u32,
}

impl TokenUsage {
    pub fn recompute_total(&mut self) {
        self.total_tokens =
            self.input_tokens + self.output_tokens + self.thinking_tokens.unwrap_or(0);
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ThinkingConfig {
    #[default]
    Off,
    On {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        budget_tokens: Option<u32>,
    },
}

impl ThinkingConfig {
    pub fn is_on(&self) -> bool {
        matches!(self, ThinkingConfig::On { .. })
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "no" => Some(ThinkingConfig::Off),
            "on" | "true" | "1" | "yes" => Some(ThinkingConfig::On {
                budget_tokens: None,
            }),
            _ => None,
        }
    }
}

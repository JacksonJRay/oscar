use thiserror::Error;

pub type OscarResult<T> = Result<T, OscarError>;

#[derive(Debug, Error)]
pub enum OscarError {
    #[error("{0}")]
    Message(String),

    #[error("configuration error: {0}")]
    Config(String),

    #[error("provider error: {0}")]
    Provider(String),

    #[error("tool error: {0}")]
    Tool(String),

    #[error("mode denied: tool `{tool_id}` requires write but session is read-only")]
    ModeDenied { tool_id: String },

    #[error("authentication required: {0}")]
    AuthRequired(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
}

impl OscarError {
    pub fn msg(s: impl Into<String>) -> Self {
        OscarError::Message(s.into())
    }
}

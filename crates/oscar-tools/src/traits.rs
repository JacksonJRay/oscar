use async_trait::async_trait;
use oscar_core::{
    AuthRequest, Capability, Cloud, Diagnostic, DiagnosticSeverity, ExecutionMode, ToolDomain,
};
use oscar_core::{SkillsSettings, ToolsSettings};
use oscar_identity::{BinaryInventory, ProfileStore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolMeta {
    pub id: String,
    pub name: String,
    pub description: String,
    pub domain: ToolDomain,
    pub clouds: Vec<Cloud>,
    pub capability: Capability,
    pub tags: Vec<String>,
    pub input_schema: serde_json::Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output_schema: Option<serde_json::Value>,
}

pub struct ToolContext {
    pub mode: ExecutionMode,
    pub profiles: Arc<ProfileStore>,
    pub cancel: CancellationToken,
    /// `~/.config/oscar` (or equivalent) for inventory cache files.
    pub config_dir: PathBuf,
    /// Session binary inventory (what CLIs the agent may invoke).
    pub binaries: Arc<BinaryInventory>,
    /// User settings: disabled tools/clouds, install policy.
    pub settings: Arc<ToolsSettings>,
    /// Skills discovery settings.
    pub skills_settings: Arc<SkillsSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolResult {
    pub ok: bool,
    pub data: serde_json::Value,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auth_required: Option<AuthRequest>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub diagnostics: Vec<Diagnostic>,
}

impl ToolResult {
    pub fn success(summary: impl Into<String>, data: serde_json::Value) -> Self {
        Self {
            ok: true,
            data,
            summary: summary.into(),
            auth_required: None,
            diagnostics: vec![],
        }
    }

    pub fn error(summary: impl Into<String>) -> Self {
        Self {
            ok: false,
            data: serde_json::json!({}),
            summary: summary.into(),
            auth_required: None,
            diagnostics: vec![],
        }
    }

    pub fn needs_auth(auth: AuthRequest) -> Self {
        let reauth = if auth.reauth { " [EXPIRED/REAUTH]" } else { "" };
        let hints = if auth.hint_commands.is_empty() {
            String::new()
        } else {
            format!(" | try: {}", auth.hint_commands.join(" · "))
        };
        let summary = format!("{}{}{}", auth.reason, reauth, hints);
        let diag_msg = auth
            .guidance
            .clone()
            .unwrap_or_else(|| "Authentication required before this tool can run".into());
        let reauth_flag = auth.reauth;
        let data = serde_json::json!({
            "auth_required": true,
            "reauth": auth.reauth,
            "cloud": auth.cloud.to_string(),
            "profile_hint": auth.profile_hint,
            "kinds": auth.kinds,
            "hint_commands": auth.hint_commands,
            "guidance": auth.guidance,
            "operator_steps": [
                "1. Follow hint_commands (SSO/login) or paste short-lived keys via TUI secure bar / oscar auth …",
                "2. oscar will auto-retry the paused tool after credentials are stored",
                "3. Prefer short-lived STS/session tokens over long-lived keys when available"
            ],
        });
        Self {
            ok: false,
            data,
            summary,
            auth_required: Some(auth),
            diagnostics: vec![Diagnostic {
                code: Some(if reauth_flag {
                    "auth_reauth".into()
                } else {
                    "auth_required".into()
                }),
                message: diag_msg,
                severity: DiagnosticSeverity::Warning,
            }],
        }
    }

    /// Map a tool/CLI error string into auth-aware ToolResult when applicable.
    pub fn from_error_text(cloud: Cloud, profile_id: Option<&str>, text: impl Into<String>) -> Self {
        let text = text.into();
        if let Some(auth) =
            oscar_identity::auth_request_from_error(cloud, profile_id, &text)
        {
            return Self::needs_auth(auth);
        }
        Self::error(text)
    }
}

#[async_trait]
pub trait Tool: Send + Sync {
    fn meta(&self) -> &ToolMeta;
    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult;
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::SecretKind;

    #[test]
    fn needs_auth_includes_education_and_retry_steps() {
        let auth = AuthRequest::new(
            Cloud::Aws,
            "token expired",
            vec![SecretKind::SessionToken],
        )
        .reauth()
        .with_guidance("Use short-lived STS")
        .with_hints(["aws sso login".to_string(), "oscar auth aws-session …".to_string()]);
        let r = ToolResult::needs_auth(auth);
        assert!(!r.ok);
        assert!(r.auth_required.as_ref().unwrap().reauth);
        assert!(r.summary.contains("EXPIRED"));
        assert!(r.summary.contains("aws sso login"));
        let steps = r.data.get("operator_steps").and_then(|v| v.as_array());
        assert!(steps.map(|a| a.len() >= 2).unwrap_or(false));
        assert_eq!(
            r.data.get("hint_commands").and_then(|v| v[0].as_str()),
            Some("aws sso login")
        );
    }
}

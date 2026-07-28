use crate::error::{OscarError, OscarResult};
use crate::messages::ThinkingConfig;
use crate::types::ExecutionMode;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Well-known filesystem locations for oscar.
#[derive(Debug, Clone)]
pub struct Paths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub profiles_file: PathBuf,
    pub sessions_dir: PathBuf,
    pub artifacts_dir: PathBuf,
    /// Local logs (tool audit JSONL, etc.).
    pub logs_dir: PathBuf,
    /// MCP OAuth tokens (owner-only 0600), never chat.
    pub mcp_credentials_file: PathBuf,
    /// LLM provider OAuth sessions (Grok/xAI, etc.) — owner-only 0600, never chat.
    pub auth_file: PathBuf,
}

impl Paths {
    pub fn discover() -> OscarResult<Self> {
        let config_dir = dirs::config_dir()
            .ok_or_else(|| OscarError::Config("could not resolve config directory".into()))?
            .join("oscar");
        let paths = Self {
            config_file: config_dir.join("config.toml"),
            profiles_file: config_dir.join("profiles.toml"),
            sessions_dir: config_dir.join("sessions"),
            artifacts_dir: config_dir.join("artifacts"),
            logs_dir: config_dir.join("logs"),
            mcp_credentials_file: config_dir.join("mcp_credentials.json"),
            auth_file: config_dir.join("auth.json"),
            config_dir,
        };
        Ok(paths)
    }

    pub fn ensure(&self) -> OscarResult<()> {
        fs::create_dir_all(&self.config_dir)?;
        fs::create_dir_all(&self.sessions_dir)?;
        fs::create_dir_all(&self.artifacts_dir)?;
        fs::create_dir_all(&self.logs_dir)?;
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OscarConfig {
    /// Active LLM provider + model for the agent.
    #[serde(default)]
    pub provider: ProviderSettings,
    /// Multiple **loaded** provider slots (credentials + preferred model per provider).
    /// Keys are provider ids (`xai`, `grok`, `openai`, …). Active selection is `provider`.
    /// Use `/model` or `/provider` to switch without losing other loaded configs.
    #[serde(default)]
    pub providers: std::collections::BTreeMap<String, ProviderSlot>,
    #[serde(default)]
    pub mode: ExecutionMode,
    #[serde(default)]
    pub thinking: ThinkingConfig,
    #[serde(default)]
    pub context: ContextSettings,
    #[serde(default)]
    pub ui: UiSettings,
    /// User settings menu: tool toggles, cloud filters, binary install policy.
    #[serde(default)]
    pub tools: ToolsSettings,
    /// Skills discovery (user steering packages).
    #[serde(default)]
    pub skills: crate::skills::SkillsSettings,
    /// MCP servers — tools mount as first-class inventory entries (Code Mode).
    #[serde(default)]
    pub mcp: crate::mcp_config::McpSettings,
    /// LLM auth policy (AuthStore + optional catalog env).
    #[serde(default)]
    pub auth: AuthSettings,
    /// models.dev catalog fetch / filter.
    #[serde(default)]
    pub catalog: CatalogSettings,
    /// Local SSE event bus (starts with TUI by default; watchdog restarts on failure).
    #[serde(default)]
    pub sse: SseSettings,
}

impl Default for OscarConfig {
    fn default() -> Self {
        Self {
            provider: ProviderSettings::default(),
            providers: std::collections::BTreeMap::new(),
            mode: ExecutionMode::ReadOnly,
            thinking: ThinkingConfig::Off,
            context: ContextSettings::default(),
            ui: UiSettings::default(),
            tools: ToolsSettings::default(),
            skills: crate::skills::SkillsSettings::default(),
            mcp: crate::mcp_config::McpSettings::default(),
            auth: AuthSettings::default(),
            catalog: CatalogSettings::default(),
            sse: SseSettings::default(),
        }
    }
}

/// LLM credential policy (OpenCode-aligned).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSettings {
    /// Dual-write API keys to OS keychain when setting AuthStore entries.
    #[serde(default = "default_true")]
    pub mirror_keychain: bool,
    /// Allow reading catalog-advertised env vars (e.g. `XAI_API_KEY`). Default off.
    #[serde(default)]
    pub allow_catalog_env: bool,
}

impl Default for AuthSettings {
    fn default() -> Self {
        Self {
            mirror_keychain: true,
            allow_catalog_env: false,
        }
    }
}

/// models.dev provider catalog settings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CatalogSettings {
    /// Fetch/use models.dev (disk cache). When false, static builtins only.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// If set, only these provider ids appear in connect lists.
    #[serde(default)]
    pub enabled_providers: Vec<String>,
    /// Provider ids to hide from connect lists.
    #[serde(default)]
    pub disabled_providers: Vec<String>,
}

impl Default for CatalogSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            enabled_providers: vec![],
            disabled_providers: vec![],
        }
    }
}

// Re-export for config consumers
pub use crate::mcp_config::{McpServerConfig, McpSettings};
pub use crate::skills::SkillsSettings;

/// How the agent should handle missing CLIs required by first-class tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum InstallBinariesPolicy {
    /// Never install; only report missing binaries.
    Off,
    /// Default: check and recommend install commands; do not elevate.
    #[default]
    Recommend,
    /// Agent may request admin/elevated install after explicit user approval.
    AskAdmin,
    /// Agent prefers installing the full set of binaries needed for **enabled** first-class tools (still needs user approval for elevation).
    InstallAll,
}

impl InstallBinariesPolicy {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "never" => Some(Self::Off),
            "recommend" | "suggest" | "default" => Some(Self::Recommend),
            "ask-admin" | "ask_admin" | "ask" | "admin" => Some(Self::AskAdmin),
            "install-all" | "install_all" | "all" => Some(Self::InstallAll),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Recommend => "recommend",
            Self::AskAdmin => "ask-admin",
            Self::InstallAll => "install-all",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolsSettings {
    /// First-class tool ids disabled in search/execute (user toggled off).
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Clouds to hide entirely: aws | gcp | azure | k8s
    #[serde(default)]
    pub disabled_clouds: Vec<String>,
    /// Binary install policy for missing CLIs.
    #[serde(default)]
    pub install_binaries: InstallBinariesPolicy,
    /// When true, agent may propose `sudo`/elevated package installs (still requires approval).
    #[serde(default = "default_true")]
    pub allow_admin_install_prompt: bool,
}

impl Default for ToolsSettings {
    fn default() -> Self {
        Self {
            disabled: vec![],
            disabled_clouds: vec![],
            install_binaries: InstallBinariesPolicy::Recommend,
            allow_admin_install_prompt: true,
        }
    }
}

impl ToolsSettings {
    pub fn is_tool_enabled(&self, tool_id: &str) -> bool {
        !self.disabled.iter().any(|d| d == tool_id)
    }

    pub fn is_cloud_enabled(&self, cloud: &str) -> bool {
        let c = cloud.to_ascii_lowercase();
        !self
            .disabled_clouds
            .iter()
            .any(|d| d.eq_ignore_ascii_case(&c))
    }

    pub fn disable_tool(&mut self, id: &str) {
        if !self.disabled.iter().any(|d| d == id) {
            self.disabled.push(id.to_string());
            self.disabled.sort();
        }
    }

    pub fn enable_tool(&mut self, id: &str) {
        self.disabled.retain(|d| d != id);
    }

    pub fn disable_cloud(&mut self, cloud: &str) {
        let c = cloud.to_ascii_lowercase();
        if !self.disabled_clouds.iter().any(|d| d.eq_ignore_ascii_case(&c)) {
            self.disabled_clouds.push(c);
            self.disabled_clouds.sort();
        }
    }

    pub fn enable_cloud(&mut self, cloud: &str) {
        self.disabled_clouds
            .retain(|d| !d.eq_ignore_ascii_case(cloud));
    }

    pub fn agent_summary(&self) -> String {
        let mut lines = vec!["## User settings (tools menu)".to_string()];
        lines.push(format!(
            "install_binaries_policy={} (off=never install; recommend=suggest only; ask-admin=request elevated install after approval; install-all=prefer full binary set for enabled tools)",
            self.install_binaries.as_str()
        ));
        lines.push(format!(
            "allow_admin_install_prompt={}",
            self.allow_admin_install_prompt
        ));
        if self.disabled.is_empty() {
            lines.push("disabled_tools: (none)".into());
        } else {
            lines.push(format!("disabled_tools: {}", self.disabled.join(", ")));
        }
        if self.disabled_clouds.is_empty() {
            lines.push("disabled_clouds: (none)".into());
        } else {
            lines.push(format!(
                "disabled_clouds: {} — do not use tools for these clouds",
                self.disabled_clouds.join(", ")
            ));
        }
        lines.push(
            "Respect disabled tools/clouds: never call them. For missing binaries: follow install_binaries_policy.".into(),
        );
        lines.join("\n")
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderSettings {
    /// Provider id: grok | xai | anthropic | openai | opencode-zen | opencode-go | custom
    #[serde(default = "default_provider")]
    pub id: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
}

/// Per-provider saved slot so multiple providers can stay loaded at once.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct ProviderSlot {
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default)]
    pub api_key_env: Option<String>,
    /// User-facing label override (optional).
    #[serde(default)]
    pub label: Option<String>,
}

fn default_provider() -> String {
    // Grok (xAI) is the primary default provider.
    "grok".into()
}

impl Default for ProviderSettings {
    fn default() -> Self {
        Self {
            id: default_provider(),
            model: Some("grok-4".into()),
            api_key_env: None,
            base_url: None,
        }
    }
}

impl OscarConfig {
    /// Remember the active provider in `providers` so multi-provider load persists.
    pub fn sync_active_provider_slot(&mut self) {
        let id = self.provider.id.clone();
        if id.is_empty() {
            return;
        }
        let slot = ProviderSlot {
            model: self.provider.model.clone(),
            base_url: self.provider.base_url.clone(),
            api_key_env: self.provider.api_key_env.clone(),
            label: self.providers.get(&id).and_then(|s| s.label.clone()),
        };
        self.providers.insert(id, slot);
    }

    /// Activate a loaded provider id (or new id) and optional model; updates `providers` map.
    ///
    /// Always replaces `provider.base_url` from the slot (or clears it so the
    /// factory can apply the catalog default). Never leaves a prior CSP's URL
    /// (e.g. NVIDIA) attached when switching to xAI/Grok.
    pub fn activate_provider(&mut self, provider_id: &str, model: Option<String>) {
        // Prefer saved slot settings when switching back.
        if let Some(slot) = self.providers.get(provider_id).cloned() {
            self.provider.id = provider_id.to_string();
            self.provider.model = model.or(slot.model);
            self.provider.base_url = slot.base_url;
            self.provider.api_key_env = slot.api_key_env;
        } else {
            self.provider.id = provider_id.to_string();
            // Drop previous provider's base_url so catalog default applies.
            self.provider.base_url = None;
            self.provider.api_key_env = None;
            if let Some(m) = model {
                self.provider.model = Some(m);
            }
        }
        self.sync_active_provider_slot();
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSettings {
    /// Fraction of **full model context_window** that triggers auto-compact.
    /// Grok Build: `[session] auto_compact_threshold_percent = 85` → `0.85`.
    #[serde(default = "default_threshold")]
    pub threshold: f32,
    /// Reserved for completion; used for usable-budget display (not the trip %).
    #[serde(default = "default_reserved")]
    pub reserved_output_tokens: u32,
    #[serde(default = "default_keep_recent")]
    pub keep_recent_turns: u32,
    #[serde(default = "default_true")]
    pub keep_latest_thinking: bool,
    #[serde(default = "default_true")]
    pub auto: bool,
    /// Soft headroom (tokens) before hard threshold for light tool folding only.
    /// Grok: `[compaction.memory_flush] soft_threshold_tokens` default 4000.
    #[serde(default = "default_soft_tokens")]
    pub soft_threshold_tokens: u32,
}

fn default_threshold() -> f32 {
    // Grok Build: auto_compact_threshold_percent = 85 of context_window
    0.85
}
fn default_reserved() -> u32 {
    4096
}
fn default_keep_recent() -> u32 {
    6
}
fn default_true() -> bool {
    true
}
fn default_soft_tokens() -> u32 {
    4000
}

impl Default for ContextSettings {
    fn default() -> Self {
        Self {
            threshold: default_threshold(),
            reserved_output_tokens: default_reserved(),
            keep_recent_turns: default_keep_recent(),
            keep_latest_thinking: true,
            auto: true,
            soft_threshold_tokens: default_soft_tokens(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UiSettings {
    #[serde(default = "default_true")]
    pub show_thinking: bool,
}

impl Default for UiSettings {
    fn default() -> Self {
        Self {
            show_thinking: true,
        }
    }
}

/// Local HTTP + SSE event bus (OpenCode-style). Enabled by default with the TUI.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SseSettings {
    /// Start SSE hub when `oscar` (TUI) or `oscar serve` runs.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Bind address (host:port). Env `OSCAR_SSE_BIND` / `OSCAR_SERVE_BIND` override.
    #[serde(default = "default_sse_bind")]
    pub bind: String,
    /// Restart the accept loop if it crashes or the socket dies.
    #[serde(default = "default_true")]
    pub watchdog: bool,
    /// Initial restart delay in milliseconds (doubles up to max).
    #[serde(default = "default_sse_backoff")]
    pub restart_backoff_ms: u64,
    #[serde(default = "default_sse_backoff_max")]
    pub restart_backoff_max_ms: u64,
}

fn default_sse_bind() -> String {
    "127.0.0.1:4096".into()
}
fn default_sse_backoff() -> u64 {
    500
}
fn default_sse_backoff_max() -> u64 {
    15_000
}

impl Default for SseSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            bind: default_sse_bind(),
            watchdog: true,
            restart_backoff_ms: default_sse_backoff(),
            restart_backoff_max_ms: default_sse_backoff_max(),
        }
    }
}

impl OscarConfig {
    /// Load user config then merge optional project-scoped `.oscar/config.toml` (G7).
    ///
    /// Merge order (later wins for overlays):
    /// 1. Defaults
    /// 2. `~/.config/oscar/config.toml` (user)
    /// 3. Nearest `./.oscar/config.toml` walking up from cwd (project)
    ///
    /// Project file is an overlay: non-empty MCP servers merge by name; disabled
    /// tools/clouds append; mode/thinking/provider override when set in project.
    pub fn load(paths: &Paths) -> OscarResult<Self> {
        let mut cfg = if paths.config_file.exists() {
            let raw = fs::read_to_string(&paths.config_file)?;
            toml::from_str(&raw)?
        } else {
            Self::default()
        };
        if let Some(project_path) = find_project_config() {
            if let Ok(raw) = fs::read_to_string(&project_path) {
                if let Ok(project) = toml::from_str::<OscarConfig>(&raw) {
                    cfg.merge_project(project);
                }
            }
        }
        Ok(cfg)
    }

    /// Merge a project overlay into this (user) config.
    ///
    /// Safe defaults: only **union** tools/clouds/skills/MCP. Does not wipe user
    /// mode/thinking/provider with empty project defaults. Same-name MCP servers
    /// from the project replace the user entry (project wins for that server).
    pub fn merge_project(&mut self, project: OscarConfig) {
        // Tools: append disabled lists (union)
        for t in project.tools.disabled {
            if !self.tools.disabled.iter().any(|x| x == &t) {
                self.tools.disabled.push(t);
            }
        }
        for c in project.tools.disabled_clouds {
            let cl = c.to_ascii_lowercase();
            if !self.tools.disabled_clouds.iter().any(|x| x == &cl) {
                self.tools.disabled_clouds.push(cl);
            }
        }
        // Project can force a stricter install policy (install-all / ask-admin)
        if !matches!(
            project.tools.install_binaries,
            InstallBinariesPolicy::Recommend
        ) {
            self.tools.install_binaries = project.tools.install_binaries;
        }
        if !project.tools.allow_admin_install_prompt {
            self.tools.allow_admin_install_prompt = false;
        }

        // Skills paths / disabled append
        for p in project.skills.paths {
            if !self.skills.paths.iter().any(|x| x == &p) {
                self.skills.paths.push(p);
            }
        }
        for d in project.skills.disabled {
            if !self.skills.disabled.iter().any(|x| x == &d) {
                self.skills.disabled.push(d);
            }
        }

        // MCP: project can force master on; always merge servers
        if project.mcp.enabled && !project.mcp.servers.is_empty() {
            self.mcp.enabled = true;
        }
        if !project.mcp.enabled && !project.mcp.servers.is_empty() {
            // Explicit project master-off only when they defined servers section intent:
            // leave user master alone unless project sets enabled=false with servers
            // (document: set enabled=false at project to disable all MCP for this repo)
            self.mcp.enabled = false;
        }
        if project.mcp.max_output_bytes != 20_000 {
            self.mcp.max_output_bytes = project.mcp.max_output_bytes;
        }
        for (name, sc) in project.mcp.servers {
            self.mcp.servers.insert(name, sc);
        }

        // Optional agent overrides only when project sets non-default mode (readwrite)
        // or non-default thinking On — avoids empty project TOML clobbering user prefs.
        if matches!(project.mode, ExecutionMode::ReadWrite) {
            self.mode = ExecutionMode::ReadWrite;
        }
        if !matches!(project.thinking, ThinkingConfig::Off) {
            self.thinking = project.thinking;
        }
        if project.provider.model.is_some() {
            self.provider.model = project.provider.model;
        }
        if project.provider.base_url.is_some() {
            self.provider.base_url = project.provider.base_url;
        }
        if project.provider.id != "xai" {
            self.provider.id = project.provider.id;
        }
    }

    /// Pretty-print the effective in-memory config as TOML (same shape as `save`).
    /// Secrets (API keys) are never part of `OscarConfig` — they live in the OS keychain.
    pub fn to_toml_pretty(&self) -> String {
        toml::to_string_pretty(self).unwrap_or_else(|e| format!("# serialize config failed: {e}\n"))
    }

    /// Persist **user** config only (never writes project `.oscar/config.toml`).
    pub fn save(&self, paths: &Paths) -> OscarResult<()> {
        paths.ensure()?;
        let raw = toml::to_string_pretty(self)
            .map_err(|e| OscarError::Config(format!("serialize config: {e}")))?;
        fs::write(&paths.config_file, raw)?;
        Ok(())
    }
}

/// Walk from cwd upward looking for `.oscar/config.toml` (G7).
pub fn find_project_config() -> Option<PathBuf> {
    let mut dir = std::env::current_dir().ok()?;
    for _ in 0..12 {
        let candidate = dir.join(".oscar").join("config.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        if !dir.pop() {
            break;
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tools_settings_disable_cloud_and_tool() {
        let mut s = ToolsSettings::default();
        assert!(s.is_tool_enabled("aws.dns.inventory.sync"));
        s.disable_tool("aws.dns.inventory.sync");
        assert!(!s.is_tool_enabled("aws.dns.inventory.sync"));
        s.enable_tool("aws.dns.inventory.sync");
        assert!(s.is_tool_enabled("aws.dns.inventory.sync"));

        s.disable_cloud("gcp");
        s.disable_cloud("Azure"); // case-insensitive store as lower
        assert!(!s.is_cloud_enabled("gcp"));
        assert!(!s.is_cloud_enabled("azure"));
        assert!(s.is_cloud_enabled("aws"));
        s.enable_cloud("GCP");
        assert!(s.is_cloud_enabled("gcp"));
    }

    #[test]
    fn install_policy_parse() {
        assert_eq!(
            InstallBinariesPolicy::parse("install-all"),
            Some(InstallBinariesPolicy::InstallAll)
        );
        assert_eq!(
            InstallBinariesPolicy::parse("ask_admin"),
            Some(InstallBinariesPolicy::AskAdmin)
        );
        assert_eq!(
            InstallBinariesPolicy::parse("off"),
            Some(InstallBinariesPolicy::Off)
        );
        assert_eq!(InstallBinariesPolicy::parse("nope"), None);
    }

    #[test]
    fn project_merge_unions_mcp_servers() {
        let mut user = OscarConfig::default();
        user.mcp.enabled = true;
        user.mcp.servers.insert("user-fs".into(), {
            let mut s = McpServerConfig::default();
            s.command = Some("npx".into());
            s
        });
        user.mode = ExecutionMode::ReadOnly;

        let mut project = OscarConfig::default();
        project.mcp.servers.insert("project-git".into(), {
            let mut s = McpServerConfig::default();
            s.command = Some("uvx".into());
            s.args = vec!["mcp-server-git".into()];
            s
        });
        project.tools.disable_cloud("azure");
        // default project mode must not wipe user readonly → still readonly
        user.merge_project(project);
        assert!(user.mcp.servers.contains_key("user-fs"));
        assert!(user.mcp.servers.contains_key("project-git"));
        assert!(!user.tools.is_cloud_enabled("azure"));
        assert_eq!(user.mode, ExecutionMode::ReadOnly);
    }

    #[test]
    fn tools_settings_roundtrip_toml() {
        let mut cfg = OscarConfig::default();
        cfg.tools.disable_cloud("gcp");
        cfg.tools.disable_cloud("azure");
        cfg.tools.install_binaries = InstallBinariesPolicy::InstallAll;
        cfg.tools.disable_tool("k8s.pods.list");
        let raw = toml::to_string_pretty(&cfg).unwrap();
        let back: OscarConfig = toml::from_str(&raw).unwrap();
        assert_eq!(back.tools.install_binaries, InstallBinariesPolicy::InstallAll);
        assert!(back.tools.disabled_clouds.contains(&"gcp".into()));
        assert!(back.tools.disabled.contains(&"k8s.pods.list".into()));
        assert!(back.tools.agent_summary().contains("install-all"));
    }
}

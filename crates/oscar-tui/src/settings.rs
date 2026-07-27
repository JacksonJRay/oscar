//! Interactive settings pane inspired by Grok Build `/settings`.
//!
//! **Arrow navigation (drill in/out):**
//! - ↑↓ move within the focused column
//! - → / Enter on categories drills into items
//! - ← / Esc on items returns to categories
//! - Enter/Space on items toggles or runs an action
//! - Esc on categories closes settings

use oscar_core::config::{InstallBinariesPolicy, OscarConfig, ToolsSettings};
use oscar_core::{ExecutionMode, ThinkingConfig};

/// Which column has keyboard focus in settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SettingsFocus {
    #[default]
    Categories,
    Items,
}

/// How the user authenticates an LLM provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderAuthMode {
    /// Paste API key only (OpenAI, Anthropic/Claude).
    ApiKey,
    /// Sign in with account in browser, then store key from console (xAI, OpenCode).
    AccountSignIn,
}

impl ProviderAuthMode {
    pub fn for_provider(id: &str) -> Self {
        match id {
            "openai" | "anthropic" | "claude" => Self::ApiKey,
            "xai" | "grok" | "opencode-zen" | "zen" | "opencode-go" | "go" => Self::AccountSignIn,
            _ => Self::ApiKey,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::ApiKey => "API key",
            Self::AccountSignIn => "Account sign-in + key",
        }
    }
}

/// Browser page to open for account sign-in / key creation.
pub fn provider_auth_url(id: &str) -> &'static str {
    match id {
        "xai" | "grok" => "https://console.x.ai/",
        "opencode-zen" | "zen" | "opencode-go" | "go" => "https://opencode.ai/auth",
        "openai" => "https://platform.openai.com/api-keys",
        "anthropic" | "claude" => "https://console.anthropic.com/settings/keys",
        _ => "https://console.x.ai/",
    }
}

/// Catalog row for first-class tool toggles.
#[derive(Debug, Clone)]
pub struct ToolCatalogEntry {
    pub id: String,
    pub name: String,
    pub domain: String,
    pub cloud: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SettingsCategory {
    Overview,
    Clouds,
    Tools,
    Mcp,
    Install,
    Agent,
    Ui,
    Provider,
    Identities,
    /// Live TOML of the effective user config (secrets stay in keychain, not shown).
    RawConfig,
}

impl SettingsCategory {
    pub const ALL: [SettingsCategory; 10] = [
        SettingsCategory::Overview,
        SettingsCategory::Identities,
        SettingsCategory::Clouds,
        SettingsCategory::Tools,
        SettingsCategory::Mcp,
        SettingsCategory::Install,
        SettingsCategory::Agent,
        SettingsCategory::Ui,
        SettingsCategory::Provider,
        SettingsCategory::RawConfig,
    ];

    pub fn title(self) -> &'static str {
        match self {
            Self::Overview => "Overview",
            Self::Identities => "Identities",
            Self::Clouds => "Clouds",
            Self::Tools => "First-class tools",
            Self::Mcp => "MCP servers",
            Self::Install => "Install binaries",
            Self::Agent => "Agent controls",
            Self::Ui => "Appearance",
            Self::Provider => "Provider",
            Self::RawConfig => "Raw config",
        }
    }

    pub fn hint(self) -> &'static str {
        match self {
            Self::Overview => "Summary of active settings",
            Self::Identities => "Open full identities panel: Ctrl+I or /identities",
            Self::Clouds => "Enable/disable entire CSPs in tools_search",
            Self::Tools => "Turn off individual tools (AWS-only shops, etc.)",
            Self::Mcp => "TOML [mcp.servers.*] — mount via tools_search, not system prompt",
            Self::Install => "How the agent handles missing CLIs",
            Self::Agent => "Mode, thinking, context compaction",
            Self::Ui => "What the chat UI shows",
            Self::Provider => "LLM provider and model (opens dedicated Providers UI)",
            Self::RawConfig => "View effective ~/.config/oscar/config.toml (TOML; no secrets)",
        }
    }
}

#[derive(Debug, Clone)]
pub enum ItemKind {
    /// Boolean toggle.
    Toggle { on: bool },
    /// Cycle through fixed options.
    Enum {
        options: Vec<&'static str>,
        index: usize,
    },
    /// Non-interactive info line.
    Info { value: String },
    /// Header / section spacer.
    Header,
}

#[derive(Debug, Clone)]
pub struct SettingsItem {
    pub id: String,
    pub label: String,
    pub description: String,
    pub kind: ItemKind,
}

/// Side-effect requests from the settings pane (handled by App).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SettingsAction {
    /// Close settings and open secure paste for the selected LLM provider key.
    PasteProviderApiKey { provider_id: String },
    /// Open browser for account sign-in (xAI / OpenCode), then secure-paste key from console.
    SignInProvider { provider_id: String },
}

/// Live settings editor state (modal overlay).
pub struct SettingsPane {
    pub config: OscarConfig,
    pub catalog: Vec<ToolCatalogEntry>,
    pub category_idx: usize,
    pub item_idx: usize,
    pub dirty: bool,
    pub tool_filter: String,
    /// Scroll offset into items list.
    pub item_scroll: usize,
    /// Flash message after toggle.
    pub flash: Option<String>,
    /// One-shot action for the host App (e.g. open secure API-key paste).
    pub pending_action: Option<SettingsAction>,
    /// Focus: category column vs item column (arrow drill-in).
    pub focus: SettingsFocus,
    /// Path to user config.toml (for raw view header).
    pub config_path: std::path::PathBuf,
    /// Scroll offset for raw TOML viewer (line-based).
    pub raw_scroll: usize,
}

impl SettingsPane {
    pub fn open(config: OscarConfig, catalog: Vec<ToolCatalogEntry>) -> Self {
        let config_path = oscar_core::Paths::discover()
            .map(|p| p.config_file)
            .unwrap_or_else(|_| {
                std::path::PathBuf::from("~/.config/oscar/config.toml")
            });
        Self {
            config,
            catalog,
            category_idx: 0,
            item_idx: 0,
            dirty: false,
            tool_filter: String::new(),
            item_scroll: 0,
            flash: Some(
                "↑↓ move · →/Enter open menu · ← back · Enter toggle · Esc close".into(),
            ),
            pending_action: None,
            focus: SettingsFocus::Categories,
            config_path,
            raw_scroll: 0,
        }
    }

    /// Open focused on the Provider category (first-run / missing LLM key).
    pub fn open_provider(config: OscarConfig, catalog: Vec<ToolCatalogEntry>) -> Self {
        let mut pane = Self::open(config, catalog);
        pane.category_idx = SettingsCategory::ALL
            .iter()
            .position(|c| *c == SettingsCategory::Provider)
            .unwrap_or(0);
        pane.focus = SettingsFocus::Items;
        pane.item_idx = 1; // Provider enum
        pane.flash = Some(
            "Provider setup: ↑↓ choose · Enter auth action · ← back · Esc close".into(),
        );
        pane
    }

    pub fn take_action(&mut self) -> Option<SettingsAction> {
        self.pending_action.take()
    }

    pub fn drill_in(&mut self) {
        self.focus = SettingsFocus::Items;
        self.ensure_item_bounds();
        if self.category() == SettingsCategory::RawConfig {
            self.flash = Some(
                "Raw config — ↑↓/PgUp/PgDn scroll · Home/End · ← back · Esc close".into(),
            );
            return;
        }
        // Skip headers
        let items = self.items();
        if matches!(
            items.get(self.item_idx).map(|i| &i.kind),
            Some(ItemKind::Header)
        ) {
            self.move_item(1);
        }
        self.flash = Some(format!(
            "{} — ↑↓ items · ← back · Enter activate",
            self.category().title()
        ));
    }

    /// Returns true if focus moved to categories (caller may close on second Esc).
    pub fn drill_out(&mut self) -> bool {
        if self.focus == SettingsFocus::Items {
            self.focus = SettingsFocus::Categories;
            self.flash = Some("↑↓ categories · → open · Esc close".into());
            false
        } else {
            true // already on categories — close
        }
    }

    pub fn category(&self) -> SettingsCategory {
        SettingsCategory::ALL[self.category_idx.min(SettingsCategory::ALL.len() - 1)]
    }

    pub fn items(&self) -> Vec<SettingsItem> {
        match self.category() {
            SettingsCategory::Overview => self.items_overview(),
            SettingsCategory::Identities => self.items_identities_hint(),
            SettingsCategory::Clouds => self.items_clouds(),
            SettingsCategory::Tools => self.items_tools(),
            SettingsCategory::Mcp => self.items_mcp(),
            SettingsCategory::Install => self.items_install(),
            SettingsCategory::Agent => self.items_agent(),
            SettingsCategory::Ui => self.items_ui(),
            SettingsCategory::Provider => self.items_provider(),
            SettingsCategory::RawConfig => self.items_raw_config(),
        }
    }

    /// Serialize the **effective in-memory** config as pretty TOML (what Esc will save).
    /// API keys live in the OS keychain and are never written into this TOML.
    pub fn raw_toml(&self) -> String {
        self.config.to_toml_pretty()
    }

    /// On-disk file contents if present (may lag behind unsaved in-memory edits).
    pub fn disk_toml(&self) -> Option<String> {
        std::fs::read_to_string(&self.config_path).ok()
    }

    /// Status line for the raw TOML viewer header.
    pub fn raw_status_line(&self) -> String {
        let raw = self.raw_toml();
        let lines = raw.lines().count();
        let disk_note = if self.disk_toml().as_ref() == Some(&raw) {
            "matches disk"
        } else if self.config_path.exists() {
            "in-memory differs from disk (Esc saves)"
        } else {
            "file not created yet (Esc saves)"
        };
        format!(
            "{} · {lines} lines · {disk_note} · secrets in keychain only",
            self.config_path.display()
        )
    }

    /// Scroll the raw TOML viewer. `visible_rows` is the viewport height in lines.
    pub fn scroll_raw(&mut self, delta: i32, visible_rows: usize) {
        let total = self.raw_toml().lines().count();
        let max_scroll = total.saturating_sub(visible_rows.max(1));
        let next = self.raw_scroll as i32 + delta;
        self.raw_scroll = next.clamp(0, max_scroll as i32) as usize;
    }

    pub fn scroll_raw_home(&mut self) {
        self.raw_scroll = 0;
    }

    pub fn scroll_raw_end(&mut self, visible_rows: usize) {
        let total = self.raw_toml().lines().count();
        self.raw_scroll = total.saturating_sub(visible_rows.max(1));
    }

    /// Meta rows kept for list fallback; the modal draws the full TOML viewer instead.
    fn items_raw_config(&self) -> Vec<SettingsItem> {
        let path = self.config_path.display().to_string();
        let status = self.raw_status_line();
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Raw config (TOML)".into(),
                description: "Effective settings · secrets are NOT stored here (OS keychain only)"
                    .into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "path".into(),
                label: "Path".into(),
                description: path.clone(),
                kind: ItemKind::Info { value: path },
            },
            SettingsItem {
                id: "status".into(),
                label: "Status".into(),
                description: status.clone(),
                kind: ItemKind::Info { value: status },
            },
            SettingsItem {
                id: "hint".into(),
                label: "Viewer".into(),
                description: "→ focus · ↑↓ / PgUp/PgDn scroll · Home/End · keys never in TOML"
                    .into(),
                kind: ItemKind::Info {
                    value: "scrollable TOML body".into(),
                },
            },
        ]
    }

    /// G6 — MCP master switch + per-server enable (Code Mode mount).
    fn items_mcp(&self) -> Vec<SettingsItem> {
        let mut items = vec![
            SettingsItem {
                id: "hdr".into(),
                label: "MCP (Code Mode mount)".into(),
                description: "Servers from [mcp.servers.*] in config.toml · tools_search mcp.* · not dumped into system prompt".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "mcp_master".into(),
                label: "MCP master enabled".into(),
                description: "Off = no MCP servers connect at agent start".into(),
                kind: ItemKind::Toggle {
                    on: self.config.mcp.enabled,
                },
            },
            SettingsItem {
                id: "mcp_hint".into(),
                label: "How tools appear".into(),
                description: "Each remote tool → mcp.<server>.<tool> · discover with tools_search · execute with tools_execute".into(),
                kind: ItemKind::Info {
                    value: "Code Mode".into(),
                },
            },
            SettingsItem {
                id: "mcp_cli".into(),
                label: "CLI".into(),
                description: "oscar mcp list|add|remove|enable|disable|doctor|tools|example".into(),
                kind: ItemKind::Info {
                    value: "also /mcp".into(),
                },
            },
            SettingsItem {
                id: "mcp_project".into(),
                label: "Project overlay".into(),
                description: "Optional .oscar/config.toml merges [mcp.servers.*] into this session (G7)".into(),
                kind: ItemKind::Info {
                    value: "cwd walk-up".into(),
                },
            },
        ];
        if self.config.mcp.servers.is_empty() {
            items.push(SettingsItem {
                id: "mcp_empty".into(),
                label: "No servers configured".into(),
                description: "oscar mcp example  ·  oscar mcp add filesystem -- npx -y @modelcontextprotocol/server-filesystem /tmp".into(),
                kind: ItemKind::Header,
            });
        } else {
            items.push(SettingsItem {
                id: "mcp_servers_hdr".into(),
                label: format!("{} server(s)", self.config.mcp.servers.len()),
                description: "Space toggles enabled · stdio command shown".into(),
                kind: ItemKind::Header,
            });
            for (name, sc) in &self.config.mcp.servers {
                let cmd = sc
                    .command
                    .as_deref()
                    .or(sc.url.as_deref())
                    .unwrap_or("?");
                let args = if sc.args.is_empty() {
                    String::new()
                } else {
                    format!(" {}", sc.args.join(" "))
                };
                items.push(SettingsItem {
                    id: format!("mcp_srv:{name}"),
                    label: name.clone(),
                    description: format!(
                        "{} · {}{args}",
                        sc.transport,
                        if cmd.len() > 48 {
                            format!("{}…", &cmd[..48])
                        } else {
                            cmd.into()
                        }
                    ),
                    kind: ItemKind::Toggle { on: sc.enabled },
                });
            }
        }
        items.push(SettingsItem {
            id: "mcp_max".into(),
            label: "max_output_bytes".into(),
            description: "Truncate MCP tool results returned to the model".into(),
            kind: ItemKind::Info {
                value: self.config.mcp.max_output_bytes.to_string(),
            },
        });
        items
    }

    fn items_identities_hint(&self) -> Vec<SettingsItem> {
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Identities & access".into(),
                description: "What oscar can reach (profiles, short-lived keys, clusters)".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "open".into(),
                label: "Open identities panel".into(),
                description: "Press Esc then Ctrl+I or type /identities — live validity check".into(),
                kind: ItemKind::Info {
                    value: "Ctrl+I".into(),
                },
            },
            SettingsItem {
                id: "cli".into(),
                label: "CLI".into(),
                description: "oscar identities check | list | json".into(),
                kind: ItemKind::Info {
                    value: "no secrets printed".into(),
                },
            },
            SettingsItem {
                id: "shows".into(),
                label: "Shows".into(),
                description: "AWS accounts, GCP projects, Azure subs, EKS/k8s contexts, LLM keys, auth source, expiry, valid/expired/missing".into(),
                kind: ItemKind::Header,
            },
        ]
    }

    fn items_overview(&self) -> Vec<SettingsItem> {
        let t = &self.config.tools;
        let clouds_off = if t.disabled_clouds.is_empty() {
            "none".into()
        } else {
            t.disabled_clouds.join(", ")
        };
        let tools_off = t.disabled.len();
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Active configuration".into(),
                description: "Saved to ~/.config/oscar/config.toml".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "mode".into(),
                label: "Session mode".into(),
                description: "Hard gate for write-capability tools".into(),
                kind: ItemKind::Info {
                    value: self.config.mode.to_string(),
                },
            },
            SettingsItem {
                id: "mcp_ov".into(),
                label: "MCP".into(),
                description: "Code Mode mount · /settings → MCP servers · /mcp list".into(),
                kind: ItemKind::Info {
                    value: format!(
                        "{} · {} server(s)",
                        if self.config.mcp.enabled {
                            "on"
                        } else {
                            "off"
                        },
                        self.config.mcp.servers.len()
                    ),
                },
            },
            SettingsItem {
                id: "provider".into(),
                label: "Provider / model".into(),
                description: "LLM backend for the agent".into(),
                kind: ItemKind::Info {
                    value: format!(
                        "{}/{}",
                        self.config.provider.id,
                        self.config
                            .provider
                            .model
                            .as_deref()
                            .unwrap_or("(default)")
                    ),
                },
            },
            SettingsItem {
                id: "install".into(),
                label: "Install binaries policy".into(),
                description: "Missing CLI handling".into(),
                kind: ItemKind::Info {
                    value: t.install_binaries.as_str().into(),
                },
            },
            SettingsItem {
                id: "clouds".into(),
                label: "Disabled clouds".into(),
                description: "Hidden from tools_search entirely".into(),
                kind: ItemKind::Info { value: clouds_off },
            },
            SettingsItem {
                id: "tools".into(),
                label: "Disabled tools".into(),
                description: "Individual first-class tools turned off".into(),
                kind: ItemKind::Info {
                    value: format!("{tools_off} tool(s)"),
                },
            },
            SettingsItem {
                id: "thinking".into(),
                label: "Show thinking".into(),
                description: "UI + request thinking channel".into(),
                kind: ItemKind::Info {
                    value: if self.config.ui.show_thinking {
                        "on".into()
                    } else {
                        "off".into()
                    },
                },
            },
            SettingsItem {
                id: "raw".into(),
                label: "Raw config.toml".into(),
                description: "Open the Raw config category (last tab) for full effective TOML"
                    .into(),
                kind: ItemKind::Info {
                    value: "no secrets".into(),
                },
            },
            SettingsItem {
                id: "hint".into(),
                label: "Tip".into(),
                description: "Use Clouds / First-class tools tabs to customize search results".into(),
                kind: ItemKind::Header,
            },
        ]
    }

    fn items_clouds(&self) -> Vec<SettingsItem> {
        let clouds = ["aws", "gcp", "azure", "k8s"];
        let mut items = vec![SettingsItem {
            id: "hdr".into(),
            label: "Cloud providers".into(),
            description: "Off = omit that CSP from tools_search / execute".into(),
            kind: ItemKind::Header,
        }];
        for c in clouds {
            let on = self.config.tools.is_cloud_enabled(c);
            items.push(SettingsItem {
                id: format!("cloud:{c}"),
                label: c.to_ascii_uppercase(),
                description: match c {
                    "aws" => "Amazon Web Services IAM, DNS, network, path tools",
                    "gcp" => "Google Cloud DNS, IAM, connectivity",
                    "azure" => "Azure DNS, RBAC, Network Watcher",
                    "k8s" => "Kubernetes contexts and resource pattern search",
                    _ => "",
                }
                .into(),
                kind: ItemKind::Toggle { on },
            });
        }
        items.push(SettingsItem {
            id: "preset_aws".into(),
            label: "Preset: AWS only".into(),
            description: "Disable gcp, azure, k8s — typical single-cloud shop".into(),
            kind: ItemKind::Toggle {
                on: self.config.tools.is_cloud_enabled("aws")
                    && !self.config.tools.is_cloud_enabled("gcp")
                    && !self.config.tools.is_cloud_enabled("azure")
                    && !self.config.tools.is_cloud_enabled("k8s"),
            },
        });
        items
    }

    fn items_tools(&self) -> Vec<SettingsItem> {
        let mut items = vec![
            SettingsItem {
                id: "hdr".into(),
                label: "First-class tools".into(),
                description: "Space toggles · off tools never appear in tools_search".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "clear_disabled".into(),
                label: "Re-enable all tools".into(),
                description: format!(
                    "Currently {} disabled",
                    self.config.tools.disabled.len()
                ),
                kind: ItemKind::Toggle {
                    on: self.config.tools.disabled.is_empty(),
                },
            },
        ];
        let filter = self.tool_filter.to_ascii_lowercase();
        for t in &self.catalog {
            if !filter.is_empty()
                && !t.id.to_ascii_lowercase().contains(&filter)
                && !t.name.to_ascii_lowercase().contains(&filter)
                && !t.domain.to_ascii_lowercase().contains(&filter)
            {
                continue;
            }
            let on = self.config.tools.is_tool_enabled(&t.id);
            items.push(SettingsItem {
                id: format!("tool:{}", t.id),
                label: t.id.clone(),
                description: format!("{} · {} · {}", t.domain, t.cloud, t.name),
                kind: ItemKind::Toggle { on },
            });
        }
        if items.len() <= 2 {
            items.push(SettingsItem {
                id: "empty".into(),
                label: "(no tools in catalog)".into(),
                description: "Registry empty or filter matched nothing".into(),
                kind: ItemKind::Info {
                    value: String::new(),
                },
            });
        }
        items
    }

    fn items_install(&self) -> Vec<SettingsItem> {
        let policy = self.config.tools.install_binaries;
        let idx = match policy {
            InstallBinariesPolicy::Off => 0,
            InstallBinariesPolicy::Recommend => 1,
            InstallBinariesPolicy::AskAdmin => 2,
            InstallBinariesPolicy::InstallAll => 3,
        };
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Missing binary policy".into(),
                description: "What the agent does when aws/gcloud/az/kubectl are missing".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "policy".into(),
                label: "install_binaries".into(),
                description: "off · recommend · ask-admin · install-all  (←→ cycle)".into(),
                kind: ItemKind::Enum {
                    options: vec!["off", "recommend", "ask-admin", "install-all"],
                    index: idx,
                },
            },
            SettingsItem {
                id: "allow_admin".into(),
                label: "Allow admin install prompt".into(),
                description: "Agent may emit InstallApprovalRequired (user still types approve install)".into(),
                kind: ItemKind::Toggle {
                    on: self.config.tools.allow_admin_install_prompt,
                },
            },
            SettingsItem {
                id: "explain".into(),
                label: "How it works".into(),
                description: "off=report only · recommend=suggest cmds · ask-admin/install-all=request elevation after approval".into(),
                kind: ItemKind::Header,
            },
        ]
    }

    fn items_agent(&self) -> Vec<SettingsItem> {
        let mode_idx = match self.config.mode {
            ExecutionMode::ReadOnly => 0,
            ExecutionMode::ReadWrite => 1,
        };
        let think_on = !matches!(self.config.thinking, ThinkingConfig::Off);
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Agent controls".into(),
                description: "Runtime gates and context behavior".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "mode".into(),
                label: "Execution mode".into(),
                description: "readonly blocks write tools even if cloud creds allow writes".into(),
                kind: ItemKind::Enum {
                    options: vec!["readonly", "readwrite"],
                    index: mode_idx,
                },
            },
            SettingsItem {
                id: "thinking_req".into(),
                label: "Request model thinking".into(),
                description: "Ask the model for a reasoning channel when supported".into(),
                kind: ItemKind::Toggle { on: think_on },
            },
            SettingsItem {
                id: "auto_compact".into(),
                label: "Auto-compact context".into(),
                description: "Fold old tool results when usage crosses threshold (default on)".into(),
                kind: ItemKind::Toggle {
                    on: self.config.context.auto,
                },
            },
            SettingsItem {
                id: "threshold".into(),
                label: "Compact threshold".into(),
                description: "Fraction of full context_window (Grok default 0.85 = 85%)".into(),
                kind: ItemKind::Enum {
                    options: vec!["0.50", "0.65", "0.75", "0.80", "0.85", "0.90"],
                    index: threshold_index(self.config.context.threshold),
                },
            },
            SettingsItem {
                id: "keep_thinking".into(),
                label: "Keep latest thinking on compact".into(),
                description: "Preserve the most recent assistant thinking block".into(),
                kind: ItemKind::Toggle {
                    on: self.config.context.keep_latest_thinking,
                },
            },
        ]
    }

    fn items_ui(&self) -> Vec<SettingsItem> {
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "Appearance".into(),
                description: "Chat UI preferences".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "show_thinking".into(),
                label: "Show thinking in chat".into(),
                description: "Render thinking deltas (Ctrl+T also toggles live)".into(),
                kind: ItemKind::Toggle {
                    on: self.config.ui.show_thinking,
                },
            },
        ]
    }

    fn items_provider(&self) -> Vec<SettingsItem> {
        let providers = ["xai", "openai", "anthropic", "opencode-zen", "opencode-go"];
        let idx = providers
            .iter()
            .position(|p| *p == self.config.provider.id)
            .unwrap_or(0);
        let pid = self.config.provider.id.as_str();
        let auth_mode = ProviderAuthMode::for_provider(pid);
        let key_present = oscar_identity::load_provider_api_key(pid)
            .ok()
            .flatten()
            .map(|k| !k.is_empty())
            .unwrap_or(false);
        let mut items = vec![
            SettingsItem {
                id: "hdr".into(),
                label: "LLM provider".into(),
                description: "xAI/OpenCode: sign in with account · OpenAI/Claude: API key. Secrets never enter chat.".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "provider_id".into(),
                label: "Provider".into(),
                description: "↑↓ focus · Enter/→ open actions · cycle with [/] when selected".into(),
                kind: ItemKind::Enum {
                    options: providers.to_vec(),
                    index: idx,
                },
            },
            SettingsItem {
                id: "auth_mode".into(),
                label: "Auth method".into(),
                description: "How this provider expects you to connect".into(),
                kind: ItemKind::Info {
                    value: auth_mode.label().into(),
                },
            },
        ];
        match auth_mode {
            ProviderAuthMode::AccountSignIn => {
                items.push(SettingsItem {
                    id: "signin_provider".into(),
                    label: if key_present {
                        "Sign in again (browser)".into()
                    } else {
                        "Sign in with account (browser)".into()
                    },
                    description: format!(
                        "Opens {} — sign in, create/copy key, then paste below",
                        provider_auth_url(pid)
                    ),
                    kind: ItemKind::Toggle { on: key_present },
                });
                items.push(SettingsItem {
                    id: "paste_provider_key".into(),
                    label: if key_present {
                        "Paste / replace API key from console".into()
                    } else {
                        "Paste API key (after sign-in)".into()
                    },
                    description: "Secure bar — agent never sees the value".into(),
                    kind: ItemKind::Toggle { on: key_present },
                });
            }
            ProviderAuthMode::ApiKey => {
                items.push(SettingsItem {
                    id: "paste_provider_key".into(),
                    label: if key_present {
                        "Paste / replace API key".into()
                    } else {
                        "Paste API key (required)".into()
                    },
                    description: "OpenAI / Claude use API keys only — secure bar, never chat".into(),
                    kind: ItemKind::Toggle { on: key_present },
                });
            }
        }
        items.push(SettingsItem {
            id: "key_status".into(),
            label: "Keychain status".into(),
            description: "Whether a key is stored for the selected provider".into(),
            kind: ItemKind::Info {
                value: if key_present {
                    format!("ready — key present for `{pid}`")
                } else {
                    format!("NOT READY — auth required for `{pid}`")
                },
            },
        });
        items.push(SettingsItem {
            id: "model".into(),
            label: "Model".into(),
            description: "Configured model id (edit config.toml for custom ids)".into(),
            kind: ItemKind::Info {
                value: self
                    .config
                    .provider
                    .model
                    .clone()
                    .unwrap_or_else(|| "(provider default)".into()),
            },
        });
        items.push(SettingsItem {
            id: "base".into(),
            label: "Base URL".into(),
            description: "Optional custom OpenAI-compatible endpoint".into(),
            kind: ItemKind::Info {
                value: self
                    .config
                    .provider
                    .base_url
                    .clone()
                    .unwrap_or_else(|| "(default)".into()),
            },
        });
        items
    }

    pub fn ensure_item_bounds(&mut self) {
        let n = self.items().len().max(1);
        if self.item_idx >= n {
            self.item_idx = n - 1;
        }
    }

    pub fn move_category(&mut self, delta: i32) {
        let n = SettingsCategory::ALL.len() as i32;
        let mut i = self.category_idx as i32 + delta;
        if i < 0 {
            i = n - 1;
        } else if i >= n {
            i = 0;
        }
        self.category_idx = i as usize;
        self.item_idx = 0;
        self.item_scroll = 0;
        self.raw_scroll = 0;
        self.focus = SettingsFocus::Categories;
        self.flash = Some(self.category().hint().into());
    }

    pub fn move_item(&mut self, delta: i32) {
        let items = self.items();
        let n = items.len() as i32;
        if n == 0 {
            return;
        }
        let mut i = self.item_idx as i32 + delta;
        // skip headers when moving
        for _ in 0..n {
            if i < 0 {
                i = n - 1;
            } else if i >= n {
                i = 0;
            }
            if !matches!(items[i as usize].kind, ItemKind::Header) {
                break;
            }
            i += if delta >= 0 { 1 } else { -1 };
        }
        if i < 0 {
            i = 0;
        }
        self.item_idx = i as usize;
    }

    /// Activate selected item (toggle / cycle forward / action).
    pub fn activate(&mut self) {
        if self.focus == SettingsFocus::Categories {
            self.drill_in();
            return;
        }
        let items = self.items();
        if let Some(item) = items.get(self.item_idx) {
            if item.id == "paste_provider_key" {
                self.pending_action = Some(SettingsAction::PasteProviderApiKey {
                    provider_id: self.config.provider.id.clone(),
                });
                self.flash = Some(format!(
                    "Opening secure paste for provider `{}`…",
                    self.config.provider.id
                ));
                return;
            }
            if item.id == "signin_provider" {
                self.pending_action = Some(SettingsAction::SignInProvider {
                    provider_id: self.config.provider.id.clone(),
                });
                self.flash = Some(format!(
                    "Opening browser sign-in for `{}`…",
                    self.config.provider.id
                ));
                return;
            }
        }
        // Enums: cycle on Enter when focused on items
        self.apply_delta(1);
    }

    /// Cycle enum backward or toggle.
    pub fn activate_back(&mut self) {
        self.apply_delta(-1);
    }

    fn apply_delta(&mut self, delta: i32) {
        let items = self.items();
        let Some(item) = items.get(self.item_idx) else {
            return;
        };
        let id = item.id.clone();
        match item.kind.clone() {
            ItemKind::Header | ItemKind::Info { .. } => {}
            ItemKind::Toggle { on } => {
                self.apply_toggle(&id, !on);
                self.dirty = true;
                self.flash = Some(format!("{} → {}", item.label, if !on { "on" } else { "off" }));
            }
            ItemKind::Enum { options, index } => {
                let n = options.len() as i32;
                if n == 0 {
                    return;
                }
                let mut ni = index as i32 + delta;
                if ni < 0 {
                    ni = n - 1;
                } else if ni >= n {
                    ni = 0;
                }
                let val = options[ni as usize];
                self.apply_enum(&id, val);
                self.dirty = true;
                self.flash = Some(format!("{} → {val}", item.label));
            }
        }
    }

    fn apply_toggle(&mut self, id: &str, on: bool) {
        if let Some(cloud) = id.strip_prefix("cloud:") {
            if on {
                self.config.tools.enable_cloud(cloud);
            } else {
                self.config.tools.disable_cloud(cloud);
            }
            return;
        }
        if let Some(tool) = id.strip_prefix("tool:") {
            if on {
                self.config.tools.enable_tool(tool);
            } else {
                self.config.tools.disable_tool(tool);
            }
            return;
        }
        if let Some(name) = id.strip_prefix("mcp_srv:") {
            if let Some(sc) = self.config.mcp.servers.get_mut(name) {
                sc.enabled = on;
            }
            return;
        }
        match id {
            "mcp_master" => self.config.mcp.enabled = on,
            "allow_admin" => self.config.tools.allow_admin_install_prompt = on,
            "show_thinking" => self.config.ui.show_thinking = on,
            "thinking_req" => {
                self.config.thinking = if on {
                    ThinkingConfig::On {
                        budget_tokens: None,
                    }
                } else {
                    ThinkingConfig::Off
                };
            }
            "auto_compact" => self.config.context.auto = on,
            "keep_thinking" => self.config.context.keep_latest_thinking = on,
            "clear_disabled" => {
                if on {
                    self.config.tools.disabled.clear();
                }
            }
            "preset_aws" => {
                if on {
                    // AWS only
                    self.config.tools.enable_cloud("aws");
                    for c in ["gcp", "azure", "k8s"] {
                        self.config.tools.disable_cloud(c);
                    }
                } else {
                    for c in ["aws", "gcp", "azure", "k8s"] {
                        self.config.tools.enable_cloud(c);
                    }
                }
            }
            _ => {}
        }
    }

    fn apply_enum(&mut self, id: &str, value: &str) {
        match id {
            "policy" => {
                if let Some(p) = InstallBinariesPolicy::parse(value) {
                    self.config.tools.install_binaries = p;
                }
            }
            "mode" => {
                if let Some(m) = ExecutionMode::parse(value) {
                    self.config.mode = m;
                }
            }
            "threshold" => {
                if let Ok(f) = value.parse::<f32>() {
                    self.config.context.threshold = f;
                }
            }
            "provider_id" => {
                self.config.provider.id = value.to_string();
            }
            _ => {}
        }
    }

    pub fn tools_settings(&self) -> &ToolsSettings {
        &self.config.tools
    }
}

fn threshold_index(t: f32) -> usize {
    let opts = [0.50_f32, 0.65, 0.75, 0.80, 0.85, 0.90];
    opts.iter()
        .enumerate()
        .min_by(|(_, a), (_, b)| {
            (*a - t)
                .abs()
                .partial_cmp(&(*b - t).abs())
                .unwrap_or(std::cmp::Ordering::Equal)
        })
        .map(|(i, _)| i)
        .unwrap_or(2)
}

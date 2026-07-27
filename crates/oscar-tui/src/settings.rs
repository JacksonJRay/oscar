//! Interactive settings pane inspired by Grok Build `/settings`.
//!
//! Left: categories · Right: items · Enter/Space toggle · ←→ cycle enums · Esc save & close

use oscar_core::config::{InstallBinariesPolicy, OscarConfig, ToolsSettings};
use oscar_core::{ExecutionMode, ThinkingConfig};

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
}

impl SettingsCategory {
    pub const ALL: [SettingsCategory; 9] = [
        SettingsCategory::Overview,
        SettingsCategory::Identities,
        SettingsCategory::Clouds,
        SettingsCategory::Tools,
        SettingsCategory::Mcp,
        SettingsCategory::Install,
        SettingsCategory::Agent,
        SettingsCategory::Ui,
        SettingsCategory::Provider,
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
            Self::Provider => "LLM provider and model",
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
}

impl SettingsPane {
    pub fn open(config: OscarConfig, catalog: Vec<ToolCatalogEntry>) -> Self {
        Self {
            config,
            catalog,
            category_idx: 0,
            item_idx: 0,
            dirty: false,
            tool_filter: String::new(),
            item_scroll: 0,
            flash: Some("↑↓ navigate · ←→ category · Enter/Space toggle · Esc save & close".into()),
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
        }
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
        vec![
            SettingsItem {
                id: "hdr".into(),
                label: "LLM provider".into(),
                description: "Keys via oscar auth provider-key (keychain)".into(),
                kind: ItemKind::Header,
            },
            SettingsItem {
                id: "provider_id".into(),
                label: "Provider".into(),
                description: "←→ cycle · store key: oscar auth provider-key --provider …".into(),
                kind: ItemKind::Enum {
                    options: providers.to_vec(),
                    index: idx,
                },
            },
            SettingsItem {
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
            },
            SettingsItem {
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
            },
        ]
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

    /// Activate selected item (toggle / cycle forward).
    pub fn activate(&mut self) {
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

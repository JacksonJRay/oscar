use crate::context::ContextManager;
use crate::prompt::system_prompt;
use crate::session::Session;
use futures::StreamExt;
use oscar_core::events::{AgentEvent, CompactReason};
use oscar_core::{
    discover_skills, find_skill, redact_json, redact_text, skills_catalog_prompt, AuthRequest,
    Cloud, ExecutionMode, Message, MessageRole, Skill, SkillsSettings, ThinkingConfig, TokenUsage,
    ToolCall, ToolsSettings,
};
use oscar_identity::{run_install_commands, BinaryInventory, ProfileStore};
use oscar_providers::{
    ChatRequest, LlmProvider, ProviderStreamEvent, ToolSpec,
};
use oscar_tools::{
    agent_tools_primer, parse_capability, parse_cloud, parse_domain, ToolContext, ToolRegistry,
    ToolResult,
};
use serde_json::{json, Value};
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, warn};
use uuid::Uuid;

pub struct AgentOptions {
    pub mode: ExecutionMode,
    pub thinking: ThinkingConfig,
    pub model: String,
    pub max_tool_rounds: u32,
}

/// Tool call paused because credentials were missing or expired.
#[derive(Debug, Clone)]
pub struct PendingToolRetry {
    pub tool_id: String,
    pub tool_call_id: String,
    pub args: Value,
    pub auth: AuthRequest,
}

pub struct Agent {
    provider: Arc<dyn LlmProvider>,
    tools: Arc<ToolRegistry>,
    profiles: Arc<ProfileStore>,
    /// Built once at session start; gates CLI-backed tools.
    pub binaries: Arc<BinaryInventory>,
    /// User settings (disabled tools/clouds, install policy).
    pub settings: Arc<ToolsSettings>,
    /// Skills discovery settings (disabled names, extra paths).
    pub skills_settings: Arc<SkillsSettings>,
    /// Cached skill catalog for the session.
    pub skills: Vec<Skill>,
    /// Skill names pinned by user (`/skill`) or agent activate — full body in system prompt.
    pub active_skills: Vec<String>,
    pub session: Session,
    options: AgentOptions,
    /// When set, the agent is waiting for credentials before retrying this tool.
    pub pending_retry: Option<PendingToolRetry>,
    /// Pending package install awaiting user admin approval.
    pub pending_install: Option<PendingInstall>,
    /// Provider/model labels for session metadata.
    pub provider_id: String,
    pub model_id: String,
}

#[derive(Debug, Clone)]
pub struct PendingInstall {
    pub packages: Vec<String>,
    pub commands: Vec<String>,
    pub reason: String,
    pub install_all: bool,
}

impl Agent {
    pub fn new(
        provider: Arc<dyn LlmProvider>,
        tools: Arc<ToolRegistry>,
        profiles: Arc<ProfileStore>,
        context: ContextManager,
        options: AgentOptions,
        settings: ToolsSettings,
    ) -> Self {
        Self::new_with_skills(
            provider,
            tools,
            profiles,
            context,
            options,
            settings,
            SkillsSettings::default(),
        )
    }

    pub fn new_with_skills(
        provider: Arc<dyn LlmProvider>,
        tools: Arc<ToolRegistry>,
        profiles: Arc<ProfileStore>,
        mut context: ContextManager,
        options: AgentOptions,
        settings: ToolsSettings,
        skills_settings: SkillsSettings,
    ) -> Self {
        if let Some(info) = provider.model_info(&options.model) {
            context.set_model(&options.model, info.context_window);
        } else {
            context.set_model(&options.model, context.context_window.max(128_000));
        }

        let binaries = Arc::new(BinaryInventory::detect());
        let settings = Arc::new(settings);
        let skills_settings = Arc::new(skills_settings);
        let skills = discover_skills(&skills_settings);
        let model_id = options.model.clone();
        let provider_id = provider.id().to_string();
        let mut agent = Self {
            provider,
            tools,
            profiles,
            binaries,
            settings,
            skills_settings,
            skills,
            active_skills: vec![],
            session: Session::new(
                options.mode,
                options.thinking.clone(),
                context,
                Message::system(String::new()),
            ),
            options,
            pending_retry: None,
            pending_install: None,
            provider_id,
            model_id,
        };
        agent.refresh_system();
        agent
    }

    /// Restore conversation from a saved session (E1 persistence).
    pub fn load_chat_history(&mut self, stored: &oscar_core::StoredChatSession) {
        self.session.id = stored.id.clone();
        self.session.title = stored.title.clone();
        if !stored.messages.is_empty() {
            self.session.messages = stored.messages.clone();
        }
        self.active_skills = stored.active_skills.clone();
        // Rebuild system prompt with current binaries/settings; keep non-system history.
        self.refresh_system();
        self.session
            .context
            .observe_messages(&self.session.messages);
    }

    /// Snapshot for disk (messages + metadata). Transcript filled by host/TUI.
    pub fn to_stored_session(
        &self,
        transcript: Vec<oscar_core::TranscriptLine>,
    ) -> oscar_core::StoredChatSession {
        use chrono::Utc;
        let now = Utc::now();
        oscar_core::StoredChatSession {
            id: self.session.id.clone(),
            title: self.session.title.clone(),
            created_at: now, // host may preserve original
            updated_at: now,
            provider: self.provider_id.clone(),
            model: self.model_id.clone(),
            mode: self.session.mode.to_string(),
            messages: self.session.messages.clone(),
            transcript,
            active_skills: self.active_skills.clone(),
        }
    }

    /// Start a brand-new empty chat (keeps provider/tools).
    pub fn new_chat(&mut self) {
        self.session.id = uuid::Uuid::new_v4().to_string();
        self.session.title = "New chat".into();
        self.session.messages = vec![Message::system(String::new())];
        self.active_skills.clear();
        self.pending_retry = None;
        self.pending_install = None;
        self.refresh_system();
    }

    /// Pin a skill into the session system prompt (user `/skill` or agent).
    pub fn activate_skill(&mut self, name: &str) -> Result<String, String> {
        let skill = find_skill(name, &self.skills_settings)
            .ok_or_else(|| format!("unknown skill `{name}` — try system.skills.list or oscar skills list"))?;
        if !self.active_skills.iter().any(|s| s == &skill.name) {
            self.active_skills.push(skill.name.clone());
        }
        self.refresh_system();
        Ok(format!(
            "Activated skill `{}` ({})\n\n{}",
            skill.name, skill.source, skill.body
        ))
    }

    pub fn deactivate_skill(&mut self, name: &str) -> String {
        let before = self.active_skills.len();
        self.active_skills
            .retain(|s| !s.eq_ignore_ascii_case(name));
        self.refresh_system();
        if self.active_skills.len() < before {
            format!("Deactivated skill `{name}`")
        } else {
            format!("Skill `{name}` was not active")
        }
    }

    pub fn reload_skills(&mut self) {
        self.skills = discover_skills(&self.skills_settings);
        self.refresh_system();
    }

    /// Refresh profile store after keychain/auth changes (host rebuilds or reloads).
    pub fn reload_profiles(&mut self, profiles: Arc<ProfileStore>) {
        self.profiles = profiles;
        self.refresh_system();
    }

    /// Rebuild binary inventory (e.g. after user installs a CLI mid-session).
    pub fn refresh_binaries(&mut self) {
        self.binaries = Arc::new(BinaryInventory::detect());
        self.refresh_system();
    }

    /// Reload user settings (disabled tools/clouds, install policy) from host.
    pub fn reload_settings(&mut self, settings: ToolsSettings) {
        self.settings = Arc::new(settings);
        self.refresh_system();
    }

    /// Replace the tool registry (e.g. after MCP remount in TUI without full agent rebuild).
    pub fn replace_tools(&mut self, tools: Arc<ToolRegistry>) {
        self.tools = tools;
    }

    /// Count mounted MCP tools (`mcp.*`).
    pub fn mcp_tool_count(&self) -> usize {
        self.tools
            .list()
            .iter()
            .filter(|m| m.id.starts_with("mcp."))
            .count()
    }

    /// After user types `approve install`, run pending elevated package commands.
    pub fn run_pending_install(&mut self) -> (bool, String) {
        let Some(pending) = self.pending_install.take() else {
            return (
                false,
                "No pending install approval. Agent requests this via system.binaries.install_plan when policy is ask-admin/install-all."
                    .into(),
            );
        };
        if pending.commands.is_empty() {
            self.refresh_binaries();
            return (
                false,
                format!(
                    "Pending install for [{}] had no runnable commands (see notes / manual install)",
                    pending.packages.join(", ")
                ),
            );
        }
        let (ok, out) = run_install_commands(&pending.commands);
        self.refresh_binaries();
        let summary = format!(
            "install packages=[{}] ok={ok}\n{out}\nbinary inventory refreshed\n{}",
            pending.packages.join(", "),
            self.binaries.agent_summary()
        );
        (ok, summary)
    }

    /// User declined admin install.
    pub fn deny_pending_install(&mut self) -> String {
        match self.pending_install.take() {
            Some(p) => format!(
                "Install denied for packages: {}. Agent will recommend manual install only.",
                p.packages.join(", ")
            ),
            None => "No pending install to deny.".into(),
        }
    }

    fn tool_specs(&self) -> Vec<ToolSpec> {
        self.tools
            .code_mode_tool_specs_json()
            .into_iter()
            .map(|(name, description, parameters)| ToolSpec {
                name,
                description,
                parameters,
            })
            .collect()
    }

    pub fn refresh_system(&mut self) {
        self.session
            .context
            .observe_messages(&self.session.messages);
        let snap = self.session.context.snapshot(self.session.messages.len() as u32);
        let thr = (self.session.context.config.threshold * 100.0).round() as u32;
        let auto = if self.session.context.config.auto {
            "on"
        } else {
            "off"
        };
        // Grok: trip % is of full context_window (not window−reserved)
        let context_line = format!(
            "Context: current={} max={} used={:.1}% · auto_compact={auto} at {thr}% of window · compacted={} (count={})",
            snap.used_tokens,
            snap.context_window,
            snap.percent,
            snap.compacted,
            self.session.context.compact_count
        );
        let primer = format!(
            "{}\n\n{}\n\n{}",
            agent_tools_primer(),
            self.binaries.agent_summary(),
            self.settings.agent_summary()
        );
        let skills_cat = skills_catalog_prompt(&self.skills);
        let active_body = self.active_skills_body();
        let sys = system_prompt(
            self.session.mode,
            &self.profiles.agent_summary(),
            &context_line,
            &primer,
            &skills_cat,
            &active_body,
        );
        if let Some(first) = self.session.messages.first_mut() {
            if first.role == MessageRole::System {
                first.content = sys;
                return;
            }
        }
        self.session.messages.insert(0, Message::system(sys));
    }

    fn active_skills_body(&self) -> String {
        let mut parts = Vec::new();
        for name in &self.active_skills {
            if let Some(s) = self.skills.iter().find(|sk| &sk.name == name).cloned().or_else(|| {
                find_skill(name, &self.skills_settings)
            }) {
                parts.push(format!("#### skill: {}\n{}\n", s.name, s.body));
            }
        }
        parts.join("\n")
    }

    pub fn maybe_compact(&mut self, tx: &mpsc::Sender<AgentEvent>, reason: CompactReason) {
        let should = matches!(
            reason,
            CompactReason::Manual | CompactReason::PreFlight | CompactReason::ModelSwitch
        ) || self.session.context.should_compact();
        if !should {
            return;
        }
        let _ = tx.blocking_send(AgentEvent::CompactionStarted { reason });
        self.save_compaction_checkpoint_best_effort(reason);
        let (before, after) = self
            .session
            .context
            .compact(&mut self.session.messages, reason);
        let _ = tx.blocking_send(AgentEvent::CompactionFinished {
            before,
            after: after.clone(),
        });
        let _ = tx.blocking_send(AgentEvent::ContextUsage(after));
    }

    /// Async auto-compact when usage ≥ threshold % of **full** context window
    /// (Grok Build default **85%**). Soft-folds tool dumps slightly earlier.
    async fn auto_compact_if_needed(
        &mut self,
        tx: &mpsc::Sender<AgentEvent>,
        reason: CompactReason,
    ) {
        self.session
            .context
            .observe_messages(&self.session.messages);

        // Soft zone (Grok soft flush analogue): fold fat tool results only
        if self.session.context.should_soft_fold() {
            let n = self
                .session
                .context
                .soft_fold_tools(&mut self.session.messages);
            if n > 0 {
                let _ = tx
                    .send(AgentEvent::ContentDelta {
                        text: format!(
                            "\n[soft-fold] head+tail trimmed {n} large tool result(s) approaching {}% context\n",
                            (self.session.context.config.threshold * 100.0).round() as u32
                        ),
                    })
                    .await;
            }
        }

        let force = matches!(
            reason,
            CompactReason::Manual | CompactReason::ModelSwitch
        );
        if !force && !self.session.context.should_compact() {
            let snap = self
                .session
                .context
                .snapshot(self.session.messages.len() as u32);
            let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
            return;
        }
        let reason = if force {
            reason
        } else {
            CompactReason::Threshold
        };
        let thr = (self.session.context.config.threshold * 100.0).round() as u32;
        let _ = tx.send(AgentEvent::CompactionStarted { reason }).await;
        // User-visible notice (Grok: "You will see a notification when auto-compact triggers")
        if matches!(reason, CompactReason::Threshold | CompactReason::PreFlight) {
            let _ = tx
                .send(AgentEvent::ContentDelta {
                    text: format!(
                        "\n[auto-compact] context ≥ {thr}% of window — compressing history…\n"
                    ),
                })
                .await;
        }
        // Grok: save pre-compact state under sessions/compaction_checkpoints/ (best-effort)
        self.save_compaction_checkpoint_best_effort(reason);
        let (before, after) = self.session.context.compact_with(
            &mut self.session.messages,
            crate::context::CompactRequest {
                reason,
                keep_note: None,
            },
        );
        self.refresh_system();
        let _ = tx
            .send(AgentEvent::CompactionFinished {
                before,
                after: after.clone(),
            })
            .await;
        let _ = tx.send(AgentEvent::ContextUsage(after)).await;
    }

    /// Run one user turn; stream events on `tx`.
    pub async fn run_turn(
        &mut self,
        user_text: String,
        tx: mpsc::Sender<AgentEvent>,
        cancel: CancellationToken,
    ) {
        self.session.push_user(user_text);
        self.refresh_system();

        // Pre-flight: compact if already ≥ threshold (Grok default 85% of window)
        self.auto_compact_if_needed(&tx, CompactReason::PreFlight)
            .await;

        let mut rounds = 0u32;
        loop {
            if cancel.is_cancelled() {
                let _ = tx
                    .send(AgentEvent::Done {
                        usage: self.session.context.last_usage.clone(),
                    })
                    .await;
                return;
            }

            // Before each model call: re-check fill level (tool dumps grow context fast)
            self.auto_compact_if_needed(&tx, CompactReason::Threshold)
                .await;

            let req = ChatRequest {
                messages: self.session.messages.clone(),
                tools: self.tool_specs(),
                model: self.options.model.clone(),
                temperature: Some(0.2),
                max_tokens: Some(4096),
                thinking: self.session.thinking.clone(),
            };

            let stream = match self.provider.chat_stream(req).await {
                Ok(s) => s,
                Err(e) => {
                    // Fallback to non-streaming chat.
                    warn!("chat_stream failed, falling back to chat: {e}");
                    match self
                        .provider
                        .chat(ChatRequest {
                            messages: self.session.messages.clone(),
                            tools: self.tool_specs(),
                            model: self.options.model.clone(),
                            temperature: Some(0.2),
                            max_tokens: Some(4096),
                            thinking: self.session.thinking.clone(),
                        })
                        .await
                    {
                        Ok(resp) => {
                            if let Some(t) = &resp.thinking {
                                let _ = tx
                                    .send(AgentEvent::ThinkingDelta { text: t.clone() })
                                    .await;
                                let _ = tx
                                    .send(AgentEvent::ThinkingDone { chars: t.len() })
                                    .await;
                            }
                            if let Some(c) = &resp.content {
                                let _ = tx
                                    .send(AgentEvent::ContentDelta { text: c.clone() })
                                    .await;
                            }
                            if let Some(u) = resp.usage.clone() {
                                self.session.context.observe_usage(u.clone());
                            }
                            let assistant = Message {
                                role: MessageRole::Assistant,
                                content: resp.content.clone().unwrap_or_default(),
                                thinking: resp.thinking.clone(),
                                tool_call_id: None,
                                name: None,
                                tool_calls: resp.tool_calls.clone(),
                            };
                            self.session.messages.push(assistant);
                            if resp.tool_calls.is_empty() {
                                let snap = self
                                    .session
                                    .context
                                    .snapshot(self.session.messages.len() as u32);
                                let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                                let _ = tx
                                    .send(AgentEvent::Done {
                                        usage: resp.usage,
                                    })
                                    .await;
                                return;
                            }
                            self.handle_tool_calls(resp.tool_calls, &tx, &cancel).await;
                            if self.pending_retry.is_some() {
                                let snap = self
                                    .session
                                    .context
                                    .snapshot(self.session.messages.len() as u32);
                                let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                                let _ = tx
                                    .send(AgentEvent::Done {
                                        usage: self.session.context.last_usage.clone(),
                                    })
                                    .await;
                                return;
                            }
                            rounds += 1;
                            if rounds >= self.options.max_tool_rounds {
                                let _ = tx
                                    .send(AgentEvent::Error {
                                        message: "max tool rounds reached".into(),
                                    })
                                    .await;
                                let _ = tx
                                    .send(AgentEvent::Done {
                                        usage: self.session.context.last_usage.clone(),
                                    })
                                    .await;
                                return;
                            }
                            continue;
                        }
                        Err(e2) => {
                            let _ = tx
                                .send(AgentEvent::Error {
                                    message: e2.to_string(),
                                })
                                .await;
                            let _ = tx
                                .send(AgentEvent::Done {
                                    usage: self.session.context.last_usage.clone(),
                                })
                                .await;
                            return;
                        }
                    }
                }
            };

            let mut content = String::new();
            let mut thinking = String::new();
            let mut tool_calls: Vec<ToolCall> = Vec::new();
            let mut usage: Option<TokenUsage> = None;
            let mut finish = oscar_core::FinishReason::Stop;

            tokio::pin!(stream);
            while let Some(ev) = stream.next().await {
                if cancel.is_cancelled() {
                    finish = oscar_core::FinishReason::Cancelled;
                    break;
                }
                match ev {
                    ProviderStreamEvent::ContentDelta(t) => {
                        content.push_str(&t);
                        let _ = tx.send(AgentEvent::ContentDelta { text: t }).await;
                    }
                    ProviderStreamEvent::ThinkingDelta(t) => {
                        thinking.push_str(&t);
                        let _ = tx.send(AgentEvent::ThinkingDelta { text: t }).await;
                    }
                    ProviderStreamEvent::ToolCallDelta { .. } => {}
                    ProviderStreamEvent::ToolCallDone(tc) => {
                        tool_calls.push(tc);
                    }
                    ProviderStreamEvent::Usage(u) => {
                        usage = Some(u.clone());
                        self.session.context.observe_usage(u);
                    }
                    ProviderStreamEvent::MessageStop { finish_reason } => {
                        finish = finish_reason;
                    }
                    ProviderStreamEvent::Error(e) => {
                        let _ = tx.send(AgentEvent::Error { message: e }).await;
                    }
                }
            }

            if !thinking.is_empty() {
                let _ = tx
                    .send(AgentEvent::ThinkingDone {
                        chars: thinking.len(),
                    })
                    .await;
            }

            let assistant = Message {
                role: MessageRole::Assistant,
                content: content.clone(),
                thinking: if thinking.is_empty() {
                    None
                } else {
                    Some(thinking)
                },
                tool_call_id: None,
                name: None,
                tool_calls: tool_calls.clone(),
            };
            self.session.messages.push(assistant);

            if tool_calls.is_empty()
                || matches!(
                    finish,
                    oscar_core::FinishReason::Stop
                        | oscar_core::FinishReason::Length
                        | oscar_core::FinishReason::Cancelled
                        | oscar_core::FinishReason::Error
                ) && !matches!(finish, oscar_core::FinishReason::ToolCalls)
                    && tool_calls.is_empty()
            {
                // If finish says tool_calls but empty, still end.
                if !matches!(finish, oscar_core::FinishReason::ToolCalls) || tool_calls.is_empty() {
                    let snap = self
                        .session
                        .context
                        .snapshot(self.session.messages.len() as u32);
                    let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                    let _ = tx.send(AgentEvent::Done { usage }).await;
                    return;
                }
            }

            if matches!(finish, oscar_core::FinishReason::ToolCalls) || !tool_calls.is_empty() {
                self.handle_tool_calls(tool_calls, &tx, &cancel).await;
                if self.pending_retry.is_some() {
                    let snap = self
                        .session
                        .context
                        .snapshot(self.session.messages.len() as u32);
                    let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                    let _ = tx.send(AgentEvent::Done { usage }).await;
                    return;
                }
                rounds += 1;
                if rounds >= self.options.max_tool_rounds {
                    let _ = tx
                        .send(AgentEvent::Error {
                            message: "max tool rounds reached".into(),
                        })
                        .await;
                    let _ = tx.send(AgentEvent::Done { usage }).await;
                    return;
                }
                continue;
            }

            let snap = self
                .session
                .context
                .snapshot(self.session.messages.len() as u32);
            let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
            let _ = tx.send(AgentEvent::Done { usage }).await;
            return;
        }
    }

    async fn handle_tool_calls(
        &mut self,
        tool_calls: Vec<ToolCall>,
        tx: &mpsc::Sender<AgentEvent>,
        cancel: &CancellationToken,
    ) {
        for tc in tool_calls {
            if cancel.is_cancelled() {
                break;
            }
            debug!(name = %tc.name, id = %tc.id, "tool call");
            match tc.name.as_str() {
                "tools_search" => {
                    let query = tc
                        .arguments
                        .get("query")
                        .or_else(|| tc.arguments.get("q"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("");
                    let domain = tc
                        .arguments
                        .get("domain")
                        .and_then(|v| v.as_str())
                        .and_then(parse_domain);
                    let cloud = tc
                        .arguments
                        .get("cloud")
                        .and_then(|v| v.as_str())
                        .and_then(parse_cloud);
                    let capability = tc
                        .arguments
                        .get("capability")
                        .and_then(|v| v.as_str())
                        .and_then(parse_capability);
                    let limit = tc
                        .arguments
                        .get("limit")
                        .and_then(|v| v.as_u64())
                        .unwrap_or(15)
                        .clamp(1, 50) as usize;
                    let result = self.tools.search_as_json_gated_limited(
                        query,
                        domain,
                        cloud,
                        capability,
                        Some(&self.binaries),
                        Some(&self.settings),
                        limit,
                    );
                    let hits = result.get("count").and_then(|c| c.as_u64()).unwrap_or(0) as usize;
                    let _ = tx
                        .send(AgentEvent::ToolSearch {
                            query: query.to_string(),
                            hits,
                        })
                        .await;
                    let content = result.to_string();
                    self.session.messages.push(Message::tool_result(
                        tc.id,
                        "tools_search",
                        content,
                    ));
                }
                "tools_execute" => {
                    let tool_id = tc
                        .arguments
                        .get("tool_id")
                        .or_else(|| tc.arguments.get("id"))
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string();
                    // Models sometimes nest args wrong or stringify JSON — normalize.
                    let args = normalize_execute_arguments(&tc.arguments);
                    let redacted = redact_args(&args);
                    let _ = tx
                        .send(AgentEvent::ToolStart {
                            tool_id: tool_id.clone(),
                            args_redacted: redacted,
                        })
                        .await;

                    let config_dir = oscar_core::Paths::discover()
                        .map(|p| p.config_dir)
                        .unwrap_or_else(|_| std::path::PathBuf::from("."));
                    let ctx = ToolContext {
                        mode: self.session.mode,
                        profiles: Arc::clone(&self.profiles),
                        cancel: cancel.clone(),
                        config_dir,
                        binaries: Arc::clone(&self.binaries),
                        settings: Arc::clone(&self.settings),
                        skills_settings: Arc::clone(&self.skills_settings),
                    };
                    let mut result = self.tools.execute(&tool_id, args.clone(), &ctx).await;

                    // Phase 6: local tool audit log (redacted args only)
                    {
                        let preview = redact_args(&args).to_string();
                        oscar_core::audit_tool_execute(
                            &tool_id,
                            result.ok,
                            &result.summary,
                            Some(&self.session.mode.to_string()),
                            Some(&self.session.id),
                            Some(&preview),
                        );
                    }

                    // Promote install approval from install_plan tool
                    if tool_id == "system.binaries.install_plan" {
                        if result
                            .data
                            .get("needs_user_admin_approval")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false)
                        {
                            let packages = result
                                .data
                                .pointer("/plan/packages")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let commands = result
                                .data
                                .pointer("/plan/commands")
                                .and_then(|v| v.as_array())
                                .map(|a| {
                                    a.iter()
                                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                        .collect::<Vec<_>>()
                                })
                                .unwrap_or_default();
                            let install_all = result
                                .data
                                .get("install_all_intent")
                                .and_then(|v| v.as_bool())
                                .unwrap_or(false);
                            self.pending_install = Some(PendingInstall {
                                packages: packages.clone(),
                                commands: commands.clone(),
                                reason: result.summary.clone(),
                                install_all,
                            });
                            let _ = tx
                                .send(AgentEvent::InstallApprovalRequired {
                                    packages,
                                    commands,
                                    reason: result.summary.clone(),
                                    install_all,
                                })
                                .await;
                        }
                    }

                    // Promote auth-ish failures from summary when tools returned plain errors.
                    if result.auth_required.is_none() && !result.ok {
                        let cloud = cloud_from_tool_id(&tool_id);
                        if let Some(mut auth) = oscar_identity::auth_request_from_error(
                            cloud,
                            None,
                            &format!("{} {}", result.summary, result.data),
                        ) {
                            auth.cloud = cloud;
                            // Enrich with full education payload
                            result = ToolResult::needs_auth(auth);
                        }
                    }

                    // system.access.prepare (etc.) may have written profiles.toml — reload in-session.
                    if result
                        .data
                        .get("reload_profiles")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(false)
                    {
                        if let Ok(paths) = oscar_core::Paths::discover() {
                            if let Ok(store) = ProfileStore::load(&paths) {
                                self.reload_profiles(Arc::new(store));
                            }
                        }
                    }

                    if let Some(auth) = result.auth_required.clone() {
                        self.pending_retry = Some(PendingToolRetry {
                            tool_id: tool_id.clone(),
                            tool_call_id: tc.id.clone(),
                            args: args.clone(),
                            auth: auth.clone(),
                        });
                        let _ = tx.send(AgentEvent::AuthRequired(auth.clone())).await;
                        let _ = tx
                            .send(AgentEvent::AuthPendingRetry {
                                tool_id: tool_id.clone(),
                                tool_call_id: tc.id.clone(),
                                args: args.clone(),
                                auth,
                            })
                            .await;
                    }
                    if result.summary.contains("read-only") || result.summary.contains("ModeDenied") {
                        let _ = tx
                            .send(AgentEvent::ModeDenied {
                                tool_id: tool_id.clone(),
                                reason: result.summary.clone(),
                            })
                            .await;
                    }

                    let _ = tx
                        .send(AgentEvent::ToolEnd {
                            tool_id: tool_id.clone(),
                            summary: result.summary.clone(),
                        })
                        .await;

                    // Side-store large payloads.
                    let artifact_id = Uuid::new_v4().to_string();
                    if result.data.to_string().len() > 2000 {
                        self.session
                            .context
                            .store_artifact(&artifact_id, result.data.clone());
                    }

                    let content = model_safe_tool_payload(&result);
                    self.session
                        .messages
                        .push(Message::tool_result(tc.id, "tools_execute", content));
                }
                other => {
                    let msg = format!("unknown agent tool: {other}");
                    let _ = tx
                        .send(AgentEvent::Error {
                            message: msg.clone(),
                        })
                        .await;
                    self.session
                        .messages
                        .push(Message::tool_result(tc.id, other, msg));
                }
            }
        }
        self.session.context.observe_messages(&self.session.messages);
    }

    /// After user provides credentials (TUI secure bar or `oscar auth`), retry paused tool and continue.
    pub async fn resume_after_auth(
        &mut self,
        tx: mpsc::Sender<AgentEvent>,
        cancel: CancellationToken,
    ) {
        let Some(pending) = self.pending_retry.take() else {
            let _ = tx
                .send(AgentEvent::Error {
                    message: "No pending tool awaiting authentication".into(),
                })
                .await;
            let _ = tx.send(AgentEvent::Done { usage: None }).await;
            return;
        };

        self.refresh_system();
        let _ = tx
            .send(AgentEvent::AuthResumed {
                tool_id: pending.tool_id.clone(),
                profile_id: pending.auth.profile_hint.clone(),
            })
            .await;
        let _ = tx
            .send(AgentEvent::ContentDelta {
                text: format!(
                    "\n[auth resumed — retrying `{}`{}]\n",
                    pending.tool_id,
                    if pending.auth.reauth {
                        " after re-auth/expiry"
                    } else {
                        ""
                    }
                ),
            })
            .await;

        let config_dir = oscar_core::Paths::discover()
            .map(|p| p.config_dir)
            .unwrap_or_else(|_| std::path::PathBuf::from("."));
        let ctx = ToolContext {
            mode: self.session.mode,
            profiles: Arc::clone(&self.profiles),
            cancel: cancel.clone(),
            config_dir,
            binaries: Arc::clone(&self.binaries),
            settings: Arc::clone(&self.settings),
            skills_settings: Arc::clone(&self.skills_settings),
        };
        let _ = tx
            .send(AgentEvent::ToolStart {
                tool_id: pending.tool_id.clone(),
                args_redacted: redact_args(&pending.args),
            })
            .await;

        let mut result = self
            .tools
            .execute(&pending.tool_id, pending.args.clone(), &ctx)
            .await;
        if result.auth_required.is_none() && !result.ok {
            let cloud = cloud_from_tool_id(&pending.tool_id);
            if let Some(mut auth) =
                oscar_identity::auth_request_from_error(cloud, None, &result.summary)
            {
                auth.cloud = cloud;
                result = ToolResult::needs_auth(auth);
            }
        }

        if let Some(auth) = result.auth_required.clone() {
            self.pending_retry = Some(PendingToolRetry {
                tool_id: pending.tool_id.clone(),
                tool_call_id: pending.tool_call_id.clone(),
                args: pending.args.clone(),
                auth: auth.clone(),
            });
            let _ = tx.send(AgentEvent::AuthRequired(auth.clone())).await;
            let _ = tx
                .send(AgentEvent::AuthPendingRetry {
                    tool_id: pending.tool_id.clone(),
                    tool_call_id: pending.tool_call_id.clone(),
                    args: pending.args,
                    auth,
                })
                .await;
            let _ = tx
                .send(AgentEvent::ToolEnd {
                    tool_id: pending.tool_id,
                    summary: result.summary.clone(),
                })
                .await;
            let content = model_safe_tool_payload(&result);
            self.session.messages.push(Message::tool_result(
                pending.tool_call_id,
                "tools_execute",
                content,
            ));
            let _ = tx
                .send(AgentEvent::Done {
                    usage: self.session.context.last_usage.clone(),
                })
                .await;
            return;
        }

        let _ = tx
            .send(AgentEvent::ToolEnd {
                tool_id: pending.tool_id.clone(),
                summary: redact_text(&result.summary),
            })
            .await;
        let mut result = result;
        result.summary = format!("{} (retried_after_auth)", result.summary);
        let content = model_safe_tool_payload(&result);
        self.session.messages.push(Message::tool_result(
            pending.tool_call_id,
            "tools_execute",
            content,
        ));
        self.session.messages.push(Message::user(format!(
            "[system] Credentials were updated and tool `{}` was retried successfully (or finished). Continue the investigation using the latest tool results.",
            pending.tool_id
        )));

        // Continue agent loop without another human prompt.
        self.run_turn_continue(tx, cancel).await;
    }

    /// Continue model/tool loop without pushing a new user-visible message (after auth retry).
    async fn run_turn_continue(
        &mut self,
        tx: mpsc::Sender<AgentEvent>,
        cancel: CancellationToken,
    ) {
        // Reuse run_turn with empty user by only running model loop:
        // push was already done; call internal loop via a minimal path.
        self.refresh_system();
        let mut rounds = 0u32;
        loop {
            if cancel.is_cancelled() {
                let _ = tx
                    .send(AgentEvent::Done {
                        usage: self.session.context.last_usage.clone(),
                    })
                    .await;
                return;
            }
            let req = ChatRequest {
                messages: self.session.messages.clone(),
                tools: self.tool_specs(),
                model: self.options.model.clone(),
                temperature: Some(0.2),
                max_tokens: Some(4096),
                thinking: self.session.thinking.clone(),
            };
            let stream = match self.provider.chat_stream(req).await {
                Ok(s) => s,
                Err(e) => {
                    let _ = tx
                        .send(AgentEvent::Error {
                            message: e.to_string(),
                        })
                        .await;
                    let _ = tx
                        .send(AgentEvent::Done {
                            usage: self.session.context.last_usage.clone(),
                        })
                        .await;
                    return;
                }
            };
            let mut content = String::new();
            let mut thinking = String::new();
            let mut tool_calls: Vec<ToolCall> = Vec::new();
            let mut usage: Option<TokenUsage> = None;
            let mut finish = oscar_core::FinishReason::Stop;
            tokio::pin!(stream);
            while let Some(ev) = stream.next().await {
                if cancel.is_cancelled() {
                    break;
                }
                match ev {
                    ProviderStreamEvent::ContentDelta(t) => {
                        content.push_str(&t);
                        let _ = tx.send(AgentEvent::ContentDelta { text: t }).await;
                    }
                    ProviderStreamEvent::ThinkingDelta(t) => {
                        thinking.push_str(&t);
                        let _ = tx.send(AgentEvent::ThinkingDelta { text: t }).await;
                    }
                    ProviderStreamEvent::ToolCallDelta { .. } => {}
                    ProviderStreamEvent::ToolCallDone(tc) => tool_calls.push(tc),
                    ProviderStreamEvent::Usage(u) => {
                        usage = Some(u.clone());
                        self.session.context.observe_usage(u);
                    }
                    ProviderStreamEvent::MessageStop { finish_reason } => {
                        finish = finish_reason;
                    }
                    ProviderStreamEvent::Error(e) => {
                        let _ = tx.send(AgentEvent::Error { message: e }).await;
                    }
                }
            }
            if !thinking.is_empty() {
                let _ = tx
                    .send(AgentEvent::ThinkingDone {
                        chars: thinking.len(),
                    })
                    .await;
            }
            self.session.messages.push(Message {
                role: MessageRole::Assistant,
                content: content.clone(),
                thinking: if thinking.is_empty() {
                    None
                } else {
                    Some(thinking)
                },
                tool_call_id: None,
                name: None,
                tool_calls: tool_calls.clone(),
            });
            if tool_calls.is_empty() {
                let snap = self
                    .session
                    .context
                    .snapshot(self.session.messages.len() as u32);
                let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                let _ = tx.send(AgentEvent::Done { usage }).await;
                return;
            }
            self.handle_tool_calls(tool_calls, &tx, &cancel).await;
            if self.pending_retry.is_some() {
                let snap = self
                    .session
                    .context
                    .snapshot(self.session.messages.len() as u32);
                let _ = tx.send(AgentEvent::ContextUsage(snap)).await;
                let _ = tx.send(AgentEvent::Done { usage }).await;
                return;
            }
            rounds += 1;
            if rounds >= self.options.max_tool_rounds {
                let _ = tx
                    .send(AgentEvent::Error {
                        message: "max tool rounds reached".into(),
                    })
                    .await;
                let _ = tx.send(AgentEvent::Done { usage }).await;
                return;
            }
            let _ = finish;
        }
    }

    pub fn compact_manual(&mut self) -> (oscar_core::events::ContextSnapshot, oscar_core::events::ContextSnapshot) {
        self.compact_manual_with(None)
    }

    /// Manual compact with optional Grok-style preserve note: `/compact keep auth details`.
    pub fn compact_manual_with(
        &mut self,
        keep_note: Option<String>,
    ) -> (oscar_core::events::ContextSnapshot, oscar_core::events::ContextSnapshot) {
        self.save_compaction_checkpoint_best_effort(CompactReason::Manual);
        let out = self.session.context.compact_with(
            &mut self.session.messages,
            crate::context::CompactRequest {
                reason: CompactReason::Manual,
                keep_note,
            },
        );
        self.refresh_system();
        out
    }

    /// Best-effort pre-compact snapshot (Grok `compaction_checkpoints`).
    fn save_compaction_checkpoint_best_effort(&self, reason: CompactReason) {
        let reason_s = match reason {
            CompactReason::Threshold => "auto",
            CompactReason::PreFlight => "preflight",
            CompactReason::Manual => "manual",
            CompactReason::ModelSwitch => "model_switch",
        };
        if let Ok(paths) = oscar_core::Paths::discover() {
            if let Err(e) = oscar_core::save_compaction_checkpoint(
                &paths,
                &self.session.id,
                reason_s,
                &self.session.messages,
            ) {
                warn!(error = %e, "compaction checkpoint save failed (continuing)");
            }
        }
    }
}

fn cloud_from_tool_id(tool_id: &str) -> Cloud {
    if tool_id.starts_with("aws.") {
        Cloud::Aws
    } else if tool_id.starts_with("gcp.") {
        Cloud::Gcp
    } else if tool_id.starts_with("azure.") {
        Cloud::Azure
    } else if tool_id.starts_with("k8s.") {
        Cloud::K8s
    } else {
        Cloud::Multi
    }
}

/// Tool results for the model: deep redaction so keys/tokens never enter the LLM context.
/// Normalize tools_execute arguments from various model shapes.
fn normalize_execute_arguments(call_args: &Value) -> Value {
    // Prefer explicit "arguments" object
    if let Some(v) = call_args.get("arguments") {
        return match v {
            Value::String(s) => serde_json::from_str(s).unwrap_or_else(|_| json!({})),
            Value::Object(_) => v.clone(),
            Value::Null => json!({}),
            other => json!({ "value": other }),
        };
    }
    // Some models put tool fields at top level (excluding tool_id)
    if let Some(obj) = call_args.as_object() {
        let mut cleaned = serde_json::Map::new();
        for (k, v) in obj {
            if k == "tool_id" || k == "id" || k == "name" {
                continue;
            }
            cleaned.insert(k.clone(), v.clone());
        }
        if !cleaned.is_empty() {
            return Value::Object(cleaned);
        }
    }
    json!({})
}

fn model_safe_tool_payload(result: &ToolResult) -> String {
    let auth = result.auth_required.as_ref().map(|a| {
        json!({
            "reauth": a.reauth,
            "cloud": a.cloud.to_string(),
            "profile_hint": a.profile_hint,
            "kinds": a.kinds,
            "reason": redact_text(&a.reason),
            "guidance": a.guidance.as_ref().map(|g| redact_text(g)),
            "hint_commands": a.hint_commands,
            // Never include any secret material — only how to re-auth
            "secrets_never_in_chat": true,
        })
    });
    let payload = json!({
        "ok": result.ok,
        "summary": redact_text(&result.summary),
        "data": redact_json(&result.data),
        "diagnostics": result.diagnostics,
        "auth_required": auth,
    });
    let s = payload.to_string();
    // Second pass: scrub any residual patterns in the serialized form
    redact_text(&s)
}

fn redact_args(v: &Value) -> Value {
    redact_json(v)
}

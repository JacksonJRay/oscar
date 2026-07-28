use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use oscar_core::{Capability, Cloud, ExecutionMode, ToolDomain};
use oscar_identity::{feasibility_for_tool, required_binaries_for_tool, BinaryInventory, ToolFeasibility};
use oscar_mode::check_capability;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

/// Inventory of first-class tools.
///
/// Agent-facing surface:
/// - Always: `tools_search` + `tools_execute` (Code Mode for cloud/infra)
/// - Native (no search): account/access tools — see [`NATIVE_ACCOUNT_TOOL_IDS`]
pub struct ToolRegistry {
    tools: HashMap<String, Arc<dyn Tool>>,
}

/// Account / profile / identity / skills tools mounted as **native** LLM tools (no tools_search).
pub const NATIVE_ACCOUNT_TOOL_IDS: &[&str] = &[
    "system.access.review",
    "system.access.prepare",
    "system.access.select",
    "system.profiles.list",
    "system.identities.list",
    // Playbooks: create + progressive load without tools_search
    "system.skills.search",
    "system.skills.get",
    "system.skills.create",
    "system.skills.list",
];

impl ToolRegistry {
    pub fn is_native_account_tool(id: &str) -> bool {
        NATIVE_ACCOUNT_TOOL_IDS.contains(&id)
    }

    pub fn new() -> Self {
        Self {
            tools: HashMap::new(),
        }
    }

    pub fn register(&mut self, tool: Arc<dyn Tool>) {
        let id = tool.meta().id.clone();
        debug!(%id, "registered tool");
        self.tools.insert(id, tool);
    }

    /// Drop tools whose id starts with `prefix` (e.g. `"mcp."` for MCP remount / M9).
    pub fn unregister_prefix(&mut self, prefix: &str) -> usize {
        let before = self.tools.len();
        self.tools.retain(|id, _| !id.starts_with(prefix));
        before.saturating_sub(self.tools.len())
    }

    pub fn get(&self, id: &str) -> Option<Arc<dyn Tool>> {
        if let Some(t) = self.tools.get(id) {
            return Some(t.clone());
        }
        // skill.<name> → load via system.skills.get (progressive disclosure)
        if id.starts_with("skill.") {
            return self.tools.get("system.skills.get").cloned();
        }
        // Narrative / older docs used alternate ids — map to canonical tools.
        if let Some(canon) = resolve_tool_alias(id) {
            if let Some(t) = self.tools.get(canon) {
                return Some(t.clone());
            }
        }
        // Grok Build names MCP tools `server__tool`; oscar uses `mcp.server.tool`.
        // Accept both so models/scripts can use either form.
        if let Some(canonical) = resolve_mcp_tool_id(id) {
            return self.tools.get(&canonical).cloned();
        }
        None
    }

    pub fn list(&self) -> Vec<ToolMeta> {
        let mut metas: Vec<_> = self.tools.values().map(|t| t.meta().clone()).collect();
        metas.sort_by(|a, b| a.id.cmp(&b.id));
        metas
    }

    /// Code Mode search: filter inventory by free text + optional facets.
    pub fn search(
        &self,
        query: &str,
        domain: Option<ToolDomain>,
        cloud: Option<Cloud>,
        capability: Option<Capability>,
    ) -> Vec<ToolMeta> {
        self.search_filtered(query, domain, cloud, capability, None)
    }

    /// Search with user settings (disabled tools/clouds omitted from results).
    pub fn search_filtered(
        &self,
        query: &str,
        domain: Option<ToolDomain>,
        cloud: Option<Cloud>,
        capability: Option<Capability>,
        settings: Option<&oscar_core::ToolsSettings>,
    ) -> Vec<ToolMeta> {
        let q = query.to_ascii_lowercase();
        let tokens: Vec<&str> = q.split_whitespace().filter(|t| !t.is_empty()).collect();

        let mut scored: Vec<(i32, ToolMeta)> = self
            .tools
            .values()
            .filter_map(|t| {
                let m = t.meta();
                if let Some(s) = settings {
                    if !s.is_tool_enabled(&m.id) {
                        return None;
                    }
                    // Hide tools solely for disabled clouds (keep Multi/meta tools)
                    let cloud_blocked = m.clouds.iter().all(|c| {
                        let cs = c.to_string();
                        cs != "multi" && !s.is_cloud_enabled(&cs)
                    });
                    if cloud_blocked && !m.clouds.is_empty() {
                        // if any cloud still enabled, keep
                        let any_ok = m.clouds.iter().any(|c| {
                            let cs = c.to_string();
                            cs == "multi" || s.is_cloud_enabled(&cs)
                        });
                        if !any_ok {
                            return None;
                        }
                    }
                }
                if let Some(d) = domain {
                    if m.domain != d {
                        return None;
                    }
                }
                if let Some(c) = cloud {
                    if !m.clouds.contains(&c) && !m.clouds.contains(&Cloud::Multi) {
                        return None;
                    }
                }
                if let Some(cap) = capability {
                    if m.capability != cap {
                        return None;
                    }
                }

                let hay = format!(
                    "{} {} {} {} {}",
                    m.id,
                    m.name,
                    m.description,
                    m.tags.join(" "),
                    m.domain
                )
                .to_ascii_lowercase();

                if tokens.is_empty() {
                    return Some((0, m.clone()));
                }

                // Soft multi-token scoring: long queries like
                // "hosted zones list inventory sync aws dns" used to AND-fail
                // every token and return 0 hits (zones.list vs inventory.sync).
                let mut score = 0i32;
                let mut matched = 0usize;
                for tok in &tokens {
                    // Skip ultra-common noise that over-constrains long queries.
                    if matches!(*tok, "the" | "a" | "an" | "for" | "with" | "and" | "or" | "to") {
                        continue;
                    }
                    let mut hit = false;
                    if m.id.to_ascii_lowercase().contains(tok) {
                        score += 10;
                        hit = true;
                    }
                    if hay.contains(tok) {
                        score += 3;
                        hit = true;
                    }
                    if hit {
                        matched += 1;
                    }
                }
                let meaningful = tokens
                    .iter()
                    .filter(|t| {
                        !matches!(**t, "the" | "a" | "an" | "for" | "with" | "and" | "or" | "to")
                    })
                    .count()
                    .max(1);
                // Require at least one meaningful token; prefer ≥40% match so
                // multi-intent queries still surface relevant tools.
                let min_matched = ((meaningful + 2) / 3).max(1); // ~33%+ ceil
                if matched < min_matched {
                    return None;
                }
                // Boost denser matches
                score += (matched as i32) * 2;
                Some((score, m.clone()))
            })
            .collect();

        scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
        let mut out: Vec<ToolMeta> = scored.into_iter().map(|(_, m)| m).collect();

        // Progressive skills in the same search channel (Grok/OpenCode): name+description only.
        // Exec via tools_execute tool_id=skill.<name> → system.skills.get.
        // Inject when the query looks playbook-related OR matches skill names strongly —
        // avoid polluting pure infra queries (e.g. "dns pattern") with skill noise.
        let skill_query = q.contains("skill")
            || q.contains("playbook")
            || q.contains("runbook")
            || q.contains("when i say")
            || q.contains("procedure")
            || q.starts_with("skill.");
        if !q.is_empty() && (skill_query || out.is_empty()) {
            let skill_settings = oscar_core::SkillsSettings::default();
            // Prefer config skills if available
            let skill_settings = oscar_core::Paths::discover()
                .ok()
                .and_then(|p| oscar_core::OscarConfig::load(&p).ok())
                .map(|c| c.skills)
                .unwrap_or(skill_settings);
            let skill_hits = oscar_core::search_skills(&q, &skill_settings, 8);
            for s in skill_hits {
                if s.disable_model_invocation {
                    continue;
                }
                let id = format!("skill.{}", s.name);
                if out.iter().any(|m| m.id == id) {
                    continue;
                }
                out.push(ToolMeta {
                    id,
                    name: format!("Skill: {}", s.name),
                    description: format!(
                        "[PLAYBOOK] {} — tools_execute this id to load full instructions (progressive disclosure).",
                        s.description
                    ),
                    domain: ToolDomain::Meta,
                    clouds: vec![Cloud::Multi],
                    capability: Capability::Read,
                    tags: vec![
                        "skill".into(),
                        "playbook".into(),
                        s.name.clone(),
                        s.when_to_use.clone().unwrap_or_default(),
                    ],
                    input_schema: json!({
                        "type": "object",
                        "properties": {
                            "name": { "type": "string", "description": "optional; defaults from skill.* id" }
                        }
                    }),
                    output_schema: None,
                });
            }
        }

        out
    }

    pub async fn execute(
        &self,
        tool_id: &str,
        args: serde_json::Value,
        ctx: &ToolContext,
    ) -> ToolResult {
        // skill.<name> → system.skills.get with name extracted (Code Mode exec path)
        let (tool_id, args) = if let Some(skill_name) = tool_id.strip_prefix("skill.") {
            let mut a = args;
            if a.get("name").and_then(|v| v.as_str()).is_none() {
                if let Some(obj) = a.as_object_mut() {
                    obj.insert("name".into(), json!(skill_name));
                } else {
                    a = json!({ "name": skill_name });
                }
            }
            ("system.skills.get", a)
        } else {
            (tool_id, args)
        };

        let Some(tool) = self.get(tool_id) else {
            // Help agent recover: suggest search
            let suggestions = self.search_filtered(tool_id, None, None, None, Some(&ctx.settings));
            let hint = if suggestions.is_empty() {
                format!(
                    "unknown tool: `{tool_id}`. Call tools_search with a short query (e.g. \"dns pattern\", \"path analyze\") to discover valid tool_ids."
                )
            } else {
                let ids: Vec<_> = suggestions.iter().take(5).map(|m| m.id.as_str()).collect();
                format!(
                    "unknown tool: `{tool_id}`. Did you mean one of: {}? Or tools_search for more.",
                    ids.join(", ")
                )
            };
            return ToolResult::error(hint);
        };
        let meta = tool.meta();
        // skill.* aliases are always allowed when system.skills.get is enabled
        let enable_id = if tool_id == "system.skills.get" {
            "system.skills.get"
        } else {
            tool_id
        };
        if !ctx.settings.is_tool_enabled(enable_id) {
            return ToolResult::error(format!(
                "tool_disabled: `{tool_id}` is turned off in user settings (oscar settings enable-tool {tool_id})"
            ));
        }
        // Cloud filter: block if all of tool's clouds are disabled
        {
            let any_ok = meta.clouds.iter().any(|c| {
                let cs = c.to_string();
                cs == "multi" || ctx.settings.is_cloud_enabled(&cs)
            });
            if !any_ok && !meta.clouds.is_empty() {
                return ToolResult::error(format!(
                    "cloud_disabled: `{tool_id}` belongs to disabled cloud(s); enable in oscar settings enable-cloud …"
                ));
            }
        }
        if let Err(e) = check_capability(ctx.mode, meta.capability, &meta.id) {
            return ToolResult::error(e.to_string());
        }
        // Schema gate: ensure agent has the info to fill required fields
        if let Err(msg) = Self::validate_execute_args(tool_id, &meta.input_schema, &args) {
            return ToolResult::error(msg);
        }
        // Binary gate: refuse CLI-backed tools when required binaries are missing.
        match feasibility_for_tool(tool_id, &ctx.binaries) {
            ToolFeasibility::Unavailable { missing, fallback } => {
                let policy = ctx.settings.install_binaries.as_str();
                let install_hint = match ctx.settings.install_binaries {
                    oscar_core::InstallBinariesPolicy::Off => {
                        "install_binaries=off — report missing only; user installs manually"
                    }
                    oscar_core::InstallBinariesPolicy::Recommend => {
                        "call system.binaries.install_plan to recommend packages (no elevation)"
                    }
                    oscar_core::InstallBinariesPolicy::AskAdmin
                    | oscar_core::InstallBinariesPolicy::InstallAll => {
                        "call system.binaries.install_plan (request_admin) so user can approve elevated install"
                    }
                };
                return ToolResult::error(format!(
                    "binary_gate: cannot run `{tool_id}` — missing binaries: {}. {fallback}. Available: {}. policy={policy}; {install_hint}",
                    missing.join(", "),
                    ctx.binaries.available.join(", ")
                ));
            }
            ToolFeasibility::Degraded { missing, note } => {
                // Allow execute; tool may partial-fail. Prepend diagnostic after.
                let mut result = tool.execute(args, ctx).await;
                result.diagnostics.push(oscar_core::Diagnostic {
                    code: Some("binary_degraded".into()),
                    message: format!("missing optional CLIs {}: {note}", missing.join(", ")),
                    severity: oscar_core::DiagnosticSeverity::Warning,
                });
                return result;
            }
            ToolFeasibility::Available => {}
        }
        tool.execute(args, ctx).await
    }

    /// JSON schemas exposed to the model:
    /// Code Mode (`tools_search` / `tools_execute`) **plus** native account tools.
    pub fn agent_tool_specs() -> Vec<oscar_providers_stub::ToolSpecLite> {
        let mut specs = vec![
            oscar_providers_stub::ToolSpecLite {
                name: "tools_search".into(),
                description: crate::catalog::tools_search_description(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Free-text search across tool id, name, description, tags. Prefer short 2–4 word queries (e.g. \"aws dns zones\", \"dns pattern\"). Pass an exact tool_id to refresh that tool's full schema. Do NOT search for account tools — call system.access.* / system.profiles.list / system.identities.list directly."
                        },
                        "domain": {
                            "type": "string",
                            "description": "Optional filter: dns | network | access | account | cluster | infra | meta"
                        },
                        "cloud": {
                            "type": "string",
                            "description": "Optional filter: aws | gcp | azure | k8s | multi"
                        },
                        "capability": {
                            "type": "string",
                            "description": "Optional filter: read | write (default session is read-only)"
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Max tools to return (default 15, max 50). Results include input_schema + example_arguments for execute."
                        }
                    },
                    "required": ["query"]
                }),
            },
            oscar_providers_stub::ToolSpecLite {
                name: "tools_execute".into(),
                description: crate::catalog::tools_execute_description(),
                parameters: json!({
                    "type": "object",
                    "properties": {
                        "tool_id": {
                            "type": "string",
                            "description": "Stable tool id from tools_search results (e.g. aws.dns.zones.list, aws.dns.pattern.search). Use the `id` field, not the name. Account tools may also be called as native functions without tools_execute."
                        },
                        "arguments": {
                            "type": "object",
                            "description": "JSON object matching the tool's input_schema from tools_search. Include all required_args. Copy/adapt example_arguments when unsure. Never include secrets/tokens/keys."
                        }
                    },
                    "required": ["tool_id", "arguments"]
                }),
            },
        ];
        // Native account tools — schemas come from registered ToolMeta when available
        // via code_mode_tool_specs_json; static fallbacks keep compile-time safety.
        for id in NATIVE_ACCOUNT_TOOL_IDS {
            if let Some(spec) = native_account_tool_spec_static(id) {
                specs.push(spec);
            }
        }
        specs
    }

    /// Build full agent tool specs including live meta from the registry (preferred).
    pub fn agent_tool_specs_with_registry(&self) -> Vec<oscar_providers_stub::ToolSpecLite> {
        let mut specs = Self::agent_tool_specs();
        // Replace static native stubs with live ToolMeta schemas when registered.
        for id in NATIVE_ACCOUNT_TOOL_IDS {
            if let Some(tool) = self.get(id) {
                let m = tool.meta();
                let live = oscar_providers_stub::ToolSpecLite {
                    name: m.id.clone(),
                    description: format!(
                        "[NATIVE — call directly, no tools_search] {}",
                        m.description
                    ),
                    parameters: m.input_schema.clone(),
                };
                if let Some(slot) = specs.iter_mut().find(|s| s.name == *id) {
                    *slot = live;
                } else {
                    specs.push(live);
                }
            }
        }
        specs
    }

    pub fn search_as_json(
        &self,
        query: &str,
        domain: Option<ToolDomain>,
        cloud: Option<Cloud>,
        capability: Option<Capability>,
    ) -> serde_json::Value {
        self.search_as_json_gated(query, domain, cloud, capability, None, None)
    }

    /// Search with optional binary inventory + user settings for gating.
    ///
    /// Caps results (default 15) so agent context stays small; each hit includes
    /// full `input_schema`, `example_arguments`, and feasibility so the model can
    /// call `tools_execute` without guessing.
    pub fn search_as_json_gated(
        &self,
        query: &str,
        domain: Option<ToolDomain>,
        cloud: Option<Cloud>,
        capability: Option<Capability>,
        binaries: Option<&BinaryInventory>,
        settings: Option<&oscar_core::ToolsSettings>,
    ) -> serde_json::Value {
        self.search_as_json_gated_limited(query, domain, cloud, capability, binaries, settings, 15)
    }

    pub fn search_as_json_gated_limited(
        &self,
        query: &str,
        domain: Option<ToolDomain>,
        cloud: Option<Cloud>,
        capability: Option<Capability>,
        binaries: Option<&BinaryInventory>,
        settings: Option<&oscar_core::ToolsSettings>,
        limit: usize,
    ) -> serde_json::Value {
        // Exact id lookup: query matches a registered tool id (or Grok-style server__tool) → one hit
        let qtrim = query.trim();
        let mut hits = if !qtrim.is_empty() {
            if let Some(t) = self.get(qtrim) {
                vec![t.meta().clone()]
            } else {
                self.search_filtered(query, domain, cloud, capability, settings)
            }
        } else {
            self.search_filtered(query, domain, cloud, capability, settings)
        };
        let total_matched = hits.len();
        let limit = limit.clamp(1, 50);
        let truncated = total_matched > limit;
        hits.truncate(limit);
        let inv = binaries.cloned().unwrap_or_default();
        json!({
            "count": hits.len(),
            "total_matched": total_matched,
            "truncated": truncated,
            "limit": limit,
            "query": query,
            "settings": {
                "disabled_tools": settings.map(|s| s.disabled.clone()).unwrap_or_default(),
                "disabled_clouds": settings.map(|s| s.disabled_clouds.clone()).unwrap_or_default(),
                "install_binaries": settings.map(|s| s.install_binaries.as_str()).unwrap_or("recommend"),
            },
            "binary_inventory": {
                "available": inv.available,
                "missing_critical": inv.missing_critical,
            },
            "how_to_use": {
                "next_step": "Pick a tool with feasibility=available. Call tools_execute with tool_id=id and arguments matching input_schema (see example_arguments). Prefer inventory.sync then pattern.search for discovery.",
                "if_truncated": "Narrow query or pass domain/cloud filters; re-search with exact tool id for full schema refresh",
                "auth_note": "If execute returns auth_required, show hint_commands; never paste secrets into chat; host auto-retries after auth",
                "mode_note": "Write tools require readwrite mode",
                "binary_note": "feasibility unavailable means required CLI missing — call system.binaries.install_plan or pick a cache/first_class tool",
                "settings_note": "Disabled tools/clouds are omitted from search results entirely",
                "backend_note": "execution_backend: first_class_or_cache | cli_binary",
                "info_sufficiency": "Each hit includes input_schema.required + properties + example_arguments so you can execute without extra discovery"
            },
            "tools": hits.iter().map(|m| {
                let req = required_binaries_for_tool(&m.id);
                let feas = feasibility_for_tool(&m.id, &inv);
                let (feas_s, missing, fallback) = match &feas {
                    ToolFeasibility::Available => ("available", Vec::<String>::new(), None),
                    ToolFeasibility::Degraded { missing, note } => {
                        ("degraded", missing.clone(), Some(note.clone()))
                    }
                    ToolFeasibility::Unavailable { missing, fallback } => {
                        ("unavailable", missing.clone(), Some(fallback.clone()))
                    }
                };
                let backend = if req.is_empty() {
                    "first_class_or_cache"
                } else {
                    "cli_binary"
                };
                let required_args = schema_required_fields(&m.input_schema);
                let example = example_arguments_from_schema(&m.id, &m.input_schema);
                json!({
                    "id": m.id,
                    "name": m.name,
                    "description": m.description,
                    "agent_notes": agent_notes_for_tool(&m.id, &m.description, m.capability),
                    "domain": m.domain.to_string(),
                    "clouds": m.clouds.iter().map(|c| c.to_string()).collect::<Vec<_>>(),
                    "capability": m.capability.to_string(),
                    "tags": m.tags,
                    "input_schema": m.input_schema,
                    "required_args": required_args,
                    "example_arguments": example,
                    "when_to_use": when_to_use_for(&m.id),
                    "required_binaries": req,
                    "execution_backend": backend,
                    "feasibility": feas_s,
                    "missing_binaries": missing,
                    "fallback": fallback,
                    "can_execute_now": feas_s == "available" || feas_s == "degraded",
                })
            }).collect::<Vec<_>>()
        })
    }

    /// Validate that `args` supplies schema-required properties. Returns Ok(()) or error message.
    pub fn validate_execute_args(tool_id: &str, schema: &serde_json::Value, args: &serde_json::Value) -> Result<(), String> {
        let required = schema_required_fields(schema);
        if required.is_empty() {
            return Ok(());
        }
        let obj = args.as_object();
        let mut missing = Vec::new();
        for key in &required {
            let present = obj
                .map(|o| {
                    o.get(key)
                        .map(|v| !v.is_null() && v.as_str().map(|s| !s.is_empty()).unwrap_or(true))
                        .unwrap_or(false)
                })
                .unwrap_or(false);
            if !present {
                missing.push(key.clone());
            }
        }
        if missing.is_empty() {
            Ok(())
        } else {
            let example = example_arguments_from_schema(tool_id, schema);
            Err(format!(
                "missing_required_args for `{tool_id}`: {}. Provide them in tools_execute.arguments. Example: {}",
                missing.join(", "),
                example
            ))
        }
    }
}

fn schema_required_fields(schema: &serde_json::Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(|r| r.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

/// Build a minimal example args object from JSON Schema (for agent guidance).
fn example_arguments_from_schema(tool_id: &str, schema: &serde_json::Value) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    let props = schema
        .get("properties")
        .and_then(|p| p.as_object())
        .cloned()
        .unwrap_or_default();
    let required = schema_required_fields(schema);

    // Prefer required fields; fill a few useful optionals for pattern tools
    let mut keys: Vec<String> = required.clone();
    for opt in ["pattern", "query", "name", "profile_id", "region", "limit", "source", "destination"] {
        if props.contains_key(opt) && !keys.iter().any(|k| k == opt) {
            keys.push(opt.into());
        }
        if keys.len() >= 6 {
            break;
        }
    }
    if keys.is_empty() {
        for k in props.keys().take(4) {
            keys.push(k.clone());
        }
    }

    for key in keys {
        let Some(prop) = props.get(&key) else { continue };
        let ty = prop.get("type").and_then(|t| t.as_str()).unwrap_or("string");
        let val = match (key.as_str(), ty) {
            ("pattern" | "query" | "name", _) => {
                if tool_id.contains("ip") || tool_id.contains("network") {
                    json!("10.0.4")
                } else if tool_id.contains("dns") {
                    json!("api.internal")
                } else {
                    json!("prod")
                }
            }
            ("source", _) => json!("10.0.1.10"),
            ("destination", _) => json!("10.0.2.20"),
            ("destination_port" | "to_port", _) | (_, "integer") => {
                if key.contains("port") {
                    json!(443)
                } else if key == "limit" {
                    json!(20)
                } else {
                    json!(1)
                }
            }
            ("limit", _) => json!(20),
            ("mode", _) => json!("partial"),
            ("protocol", _) => json!("TCP"),
            ("refresh", _) | (_, "boolean") => json!(false),
            ("profile_id", _) => json!("default"),
            ("region", _) => json!("us-east-1"),
            ("context", _) => json!(""),
            ("tool_id", _) => json!("…"),
            (_, "array") => json!([]),
            (_, "object") => json!({}),
            _ => json!("…"),
        };
        // Skip empty optional context
        if key == "context" {
            continue;
        }
        obj.insert(key, val);
    }
    serde_json::Value::Object(obj)
}

fn agent_notes_for_tool(id: &str, description: &str, cap: Capability) -> String {
    let mut notes = vec![description.to_string()];
    if matches!(cap, Capability::Write) {
        notes.push("WRITE tool: blocked unless oscar mode is readwrite.".into());
    }
    if id.contains("inventory.sync") {
        notes.push("Fills unified inventory cache used by pattern.search tools. Prefer sync before first pattern search in a session if cache empty.".into());
    }
    if id.contains("pattern") || id == "dns.where" || id == "dns.pattern.find" || id == "dns.resolve.public"
    {
        notes.push("High-accuracy discovery: partial/glob/IP fragment search. Prefer over multi-step list+filter.".into());
    }
    if id.contains("path.analyze") || id.contains("connectivity") || id.contains("troubleshoot") {
        notes.push("Live path analysis via CSP native tooling; returns PathTraceResult-shaped data. Needs working cloud auth/binary session.".into());
    }
    notes.push("Secrets are never returned; credentials flow through keychain/binary sessions only.".into());
    notes.join(" ")
}

fn when_to_use_for(id: &str) -> &'static str {
    if id.contains("inventory.sync") {
        "Before pattern search when inventory cache is empty or stale"
    } else if id.contains("forwarding.map") {
        "Cross-CSP private DNS forwarding narrative after resolver inventory sync"
    } else if id.contains("resolver") || id.contains("firewall") || id.contains("querylog") || id.contains("vnet_link") || id.contains("private_resolver") || id.contains("dns.policy") || id.contains("dns.profile") {
        "Hybrid/private DNS: Resolver endpoints/rules, firewall, policies, VNet links, Private Resolver"
    } else if id.contains("pattern") || id == "dns.where" {
        "User asks where a name/IP/CIDR fragment lives or wants discovery without long exploratory queries"
    } else if id.contains("path.analyze") || id.contains("connectivity") || id.contains("troubleshoot") || id.contains("next_hop") {
        "User asks why A cannot reach B / path reachability between endpoints"
    } else if id.contains("ip.locate") {
        "Locate which VPC/subnet/ENI owns an IP or partial IP"
    } else if id.contains("cni") || id.contains("hubble") || id.contains("calico") || id.contains("cilium") || id.contains("networkpolicy") {
        "Kubernetes CNI / policy drops (detect CNI first, then Hubble or Calico tools)"
    } else if id.contains("coredns") {
        "Cluster DNS path: CoreDNS pods, kube-dns Service, EndpointSlices, Corefile"
    } else if id.starts_with("k8s.") {
        "Kubernetes resource discovery or cluster context questions"
    } else if id.starts_with("mcp.") {
        "External MCP capability via tools_search → tools_execute (Grok analogue: search_tool → use_tool). Write MCP tools need readwrite mode."
    } else if id.starts_with("system.binaries") {
        "Missing CLI for a first-class tool; plan/recommend install per user install_binaries policy"
    } else if id.contains("iam") || id.starts_with("access.") {
        "IAM / access troubleshooting, simulate, or manage (write needs readwrite mode)"
    } else {
        "See description and tags"
    }
}

/// Map Grok-style `server__tool` or bare `server.tool` to oscar `mcp.server.tool`.
/// Older narrative / interconnect docs used these ids — resolve to live tools.
fn resolve_tool_alias(id: &str) -> Option<&'static str> {
    match id {
        "aws.network.path.reachability" | "aws.network.reachability" => {
            Some("aws.network.path.analyze")
        }
        "aws.network.path.access" => Some("aws.network.access.analyze"),
        "gcp.network.path.connectivity_test" | "gcp.network.path.analyze" => {
            Some("gcp.network.connectivity.test")
        }
        "azure.network.path.test_connectivity" | "azure.network.connectivity.test" => {
            Some("azure.network.path.troubleshoot")
        }
        "azure.network.path.next_hop" => Some("azure.network.next_hop"),
        "network.troubleshoot" | "network.playbook" => Some("network.troubleshoot.playbook"),
        "network.locate" | "ip.locate" => Some("network.ip.locate"),
        "envoy.diagnose" | "mesh.diagnose" => Some("mesh.envoy.diagnose"),
        "node.status" | "node.network.status" => Some("node.net.status"),
        _ => None,
    }
}

fn resolve_mcp_tool_id(id: &str) -> Option<String> {
    let id = id.trim();
    if id.starts_with("mcp.") {
        return None;
    }
    // Grok: server__tool  (double underscore)
    if let Some((server, tool)) = id.split_once("__") {
        if !server.is_empty() && !tool.is_empty() {
            return Some(oscar_core::mcp_tool_id(server, tool));
        }
    }
    None
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

// Avoid circular dep on oscar-providers for specs used by agent; keep a local lite type.
mod oscar_providers_stub {
    use serde_json::Value;
    pub struct ToolSpecLite {
        pub name: String,
        pub description: String,
        pub parameters: Value,
    }
}

impl ToolRegistry {
    pub fn code_mode_tool_specs_json(&self) -> Vec<(String, String, serde_json::Value)> {
        self.agent_tool_specs_with_registry()
            .into_iter()
            .map(|t| (t.name, t.description, t.parameters))
            .collect()
    }
}

fn native_account_tool_spec_static(id: &str) -> Option<oscar_providers_stub::ToolSpecLite> {
    let (description, parameters) = match id {
        "system.access.review" => (
            "[NATIVE] List oscar cloud profiles and validity (no secrets). Filter by cloud/account/label. Call directly — do not tools_search for this.".into(),
            json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string", "description": "aws|gcp|azure|k8s" },
                    "account": { "type": "string", "description": "Account id or label filter (e.g. vdms)" },
                    "live": { "type": "boolean", "default": true }
                }
            }),
        ),
        "system.access.prepare" => (
            "[NATIVE] Create/update a local profile and request secure-bar / SSO auth for a named account (e.g. vdms). Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string", "enum": ["aws", "gcp", "azure", "k8s"] },
                    "label": { "type": "string" },
                    "account": { "type": "string" },
                    "region": { "type": "string" },
                    "profile_id": { "type": "string" },
                    "prefer": { "type": "string", "enum": ["sso", "session", "keys"] },
                    "request_auth": { "type": "boolean", "default": true }
                },
                "required": ["cloud"]
            }),
        ),
        "system.access.select" => (
            "[NATIVE] Set or clear session preferred profile so domain tools target that account. Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "clear": { "type": "boolean", "default": false }
                }
            }),
        ),
        "system.profiles.list" => (
            "[NATIVE] List local oscar profiles grouped by CSP. No secrets. Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string" }
                }
            }),
        ),
        "system.identities.list" => (
            "[NATIVE] Show configured cloud/LLM identities and validity. Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "live": { "type": "boolean", "default": true }
                }
            }),
        ),
        "system.skills.search" => (
            "[NATIVE] Search playbooks by trigger phrase (short hits only). Then system.skills.get or skill.<name>. Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "query": { "type": "string" },
                    "limit": { "type": "integer", "default": 10 }
                },
                "required": ["query"]
            }),
        ),
        "system.skills.get" => (
            "[NATIVE] Load full playbook body into the tool result. Call directly (or tools_execute skill.<name>).".into(),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string" }
                },
                "required": ["name"]
            }),
        ),
        "system.skills.create" => (
            "[NATIVE] Create a user playbook/skill from guidance (when user says X, do Y). Local SKILL.md only — works in readonly. Call directly.".into(),
            json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "kebab-case id; optional if guidance given (auto-slug)" },
                    "description": { "type": "string" },
                    "when_to_use": { "type": "string" },
                    "guidance": { "type": "string", "description": "User's natural-language procedure; used to build body if body omitted" },
                    "body": { "type": "string", "description": "Markdown steps; optional if guidance provided" },
                    "scope": { "type": "string", "enum": ["user", "project"], "default": "user" },
                    "allowed_tools": { "type": "array", "items": { "type": "string" } }
                },
                "required": []
            }),
        ),
        "system.skills.list" => (
            "[NATIVE] List skill names/descriptions (no bodies). Call directly.".into(),
            json!({ "type": "object", "properties": {} }),
        ),
        _ => return None,
    };
    Some(oscar_providers_stub::ToolSpecLite {
        name: id.into(),
        description,
        parameters,
    })
}

/// Parse optional domain string.
pub fn parse_domain(s: &str) -> Option<ToolDomain> {
    match s.to_ascii_lowercase().as_str() {
        "dns" => Some(ToolDomain::Dns),
        "network" | "net" | "path" => Some(ToolDomain::Network),
        "access" | "iam" => Some(ToolDomain::Access),
        "account" => Some(ToolDomain::Account),
        "cluster" | "k8s" => Some(ToolDomain::Cluster),
        "infra" | "infrastructure" => Some(ToolDomain::Infra),
        "meta" => Some(ToolDomain::Meta),
        _ => None,
    }
}

pub fn parse_capability(s: &str) -> Option<Capability> {
    match s.to_ascii_lowercase().as_str() {
        "read" | "ro" => Some(Capability::Read),
        "write" | "rw" => Some(Capability::Write),
        _ => None,
    }
}

pub fn parse_cloud(s: &str) -> Option<Cloud> {
    Cloud::parse(s)
}

/// Helper used when session is read-only and a write was attempted (for AgentEvent).
pub fn mode_denied_message(tool_id: &str, mode: ExecutionMode) -> String {
    format!("tool `{tool_id}` requires write capability but session mode is {mode}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::{Capability, Cloud, ToolDomain, ToolsSettings};
    use oscar_identity::BinaryInventory;
    use serde_json::json;

    struct DummyTool {
        meta: ToolMeta,
    }

    #[async_trait::async_trait]
    impl Tool for DummyTool {
        fn meta(&self) -> &ToolMeta {
            &self.meta
        }
        async fn execute(&self, _args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
            ToolResult::success("ok", json!({}))
        }
    }

    fn dummy(id: &str, clouds: Vec<Cloud>) -> Arc<dyn Tool> {
        Arc::new(DummyTool {
            meta: ToolMeta {
                id: id.into(),
                name: id.into(),
                description: format!("tool {id}"),
                domain: ToolDomain::Dns,
                clouds,
                capability: Capability::Read,
                tags: vec!["test".into()],
                input_schema: json!({}),
                output_schema: None,
            },
        })
    }

    #[test]
    fn search_omits_disabled_tools_and_clouds() {
        let mut reg = ToolRegistry::new();
        reg.register(dummy("aws.dns.x", vec![Cloud::Aws]));
        reg.register(dummy("gcp.dns.x", vec![Cloud::Gcp]));
        reg.register(dummy("system.settings.get", vec![Cloud::Multi]));

        let mut settings = ToolsSettings::default();
        settings.disable_cloud("gcp");
        settings.disable_tool("aws.dns.x");

        let hits = reg.search_filtered("dns", None, None, None, Some(&settings));
        let ids: Vec<_> = hits.iter().map(|m| m.id.as_str()).collect();
        assert!(!ids.contains(&"aws.dns.x"));
        assert!(!ids.contains(&"gcp.dns.x"));

        // Multi tools still searchable when not disabled
        let all = reg.search_filtered("settings", None, None, None, Some(&settings));
        assert!(all.iter().any(|m| m.id == "system.settings.get"));
    }

    #[test]
    fn search_soft_match_long_hosted_zones_query() {
        let mut reg = ToolRegistry::new();
        reg.register(dummy("aws.dns.zones.list", vec![Cloud::Aws]));
        // Enrich dummy name/desc via a second realistic tool
        reg.register(Arc::new(DummyTool {
            meta: ToolMeta {
                id: "aws.dns.inventory.sync".into(),
                name: "Sync Route 53 inventory".into(),
                description: "Live-fetch AWS Route 53 public/private hosted zones and records"
                    .into(),
                domain: ToolDomain::Dns,
                clouds: vec![Cloud::Aws],
                capability: Capability::Read,
                tags: vec![
                    "dns".into(),
                    "sync".into(),
                    "inventory".into(),
                    "route53".into(),
                ],
                input_schema: json!({}),
                output_schema: None,
            },
        }));
        reg.register(Arc::new(DummyTool {
            meta: ToolMeta {
                id: "aws.dns.zones.list".into(),
                name: "List Route 53 hosted zones".into(),
                description: "List public and private Route 53 hosted zones".into(),
                domain: ToolDomain::Dns,
                clouds: vec![Cloud::Aws],
                capability: Capability::Read,
                tags: vec!["dns".into(), "zones".into(), "list".into(), "hosted".into()],
                input_schema: json!({}),
                output_schema: None,
            },
        }));
        let hits = reg.search(
            "hosted zones list inventory sync aws dns",
            None,
            None,
            None,
        );
        let ids: Vec<_> = hits.iter().map(|m| m.id.as_str()).collect();
        assert!(
            !ids.is_empty(),
            "long multi-token query must not return 0 hits"
        );
        assert!(
            ids.contains(&"aws.dns.zones.list") || ids.contains(&"aws.dns.inventory.sync"),
            "expected zone list or inventory sync, got {ids:?}"
        );
    }

    #[test]
    fn search_json_includes_schema_and_examples_for_execute() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(DummyTool {
            meta: ToolMeta {
                id: "aws.dns.pattern.search".into(),
                name: "Pattern search".into(),
                description: "Find DNS fragments".into(),
                domain: ToolDomain::Dns,
                clouds: vec![Cloud::Aws],
                capability: Capability::Read,
                tags: vec!["dns".into(), "pattern".into()],
                input_schema: json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string" },
                        "limit": { "type": "integer" }
                    },
                    "required": ["pattern"]
                }),
                output_schema: None,
            },
        }));
        let mut inv = BinaryInventory::default();
        inv.available = vec!["aws".into()];
        let out = reg.search_as_json_gated(
            "dns pattern",
            None,
            None,
            None,
            Some(&inv),
            None,
        );
        assert_eq!(out["count"], 1);
        let tool = &out["tools"][0];
        assert_eq!(tool["id"], "aws.dns.pattern.search");
        assert!(tool["input_schema"]["required"]
            .as_array()
            .unwrap()
            .iter()
            .any(|v| v == "pattern"));
        assert!(tool["example_arguments"].get("pattern").is_some());
        assert_eq!(tool["required_args"][0], "pattern");
        assert_eq!(tool["can_execute_now"], true);
        assert_eq!(tool["feasibility"], "available");
        assert!(out["how_to_use"]["info_sufficiency"]
            .as_str()
            .unwrap()
            .contains("example_arguments"));
    }

    #[test]
    fn validate_execute_args_reports_missing_required() {
        let schema = json!({
            "type": "object",
            "properties": { "pattern": { "type": "string" } },
            "required": ["pattern"]
        });
        let err = ToolRegistry::validate_execute_args("t", &schema, &json!({}))
            .unwrap_err();
        assert!(err.contains("pattern"));
        assert!(ToolRegistry::validate_execute_args("t", &schema, &json!({"pattern": "x"})).is_ok());
    }

    #[test]
    fn exact_tool_id_query_returns_that_tool() {
        let mut reg = ToolRegistry::new();
        reg.register(dummy("aws.dns.pattern.search", vec![Cloud::Aws]));
        reg.register(dummy("aws.network.pattern.search", vec![Cloud::Aws]));
        let out = reg.search_as_json_gated("aws.dns.pattern.search", None, None, None, None, None);
        assert_eq!(out["count"], 1);
        assert_eq!(out["tools"][0]["id"], "aws.dns.pattern.search");
    }

    #[test]
    fn grok_style_mcp_id_resolves_to_canonical() {
        assert_eq!(
            resolve_mcp_tool_id("filesystem__read_file").as_deref(),
            Some("mcp.filesystem.read_file")
        );
        assert_eq!(resolve_mcp_tool_id("mcp.filesystem.read_file"), None);
        assert_eq!(resolve_mcp_tool_id("plain"), None);

        let mut reg = ToolRegistry::new();
        reg.register(dummy("mcp.filesystem.read_file", vec![Cloud::Multi]));
        assert!(reg.get("filesystem__read_file").is_some());
        assert!(reg.get("mcp.filesystem.read_file").is_some());
        let out = reg.search_as_json_gated("filesystem__read_file", None, None, None, None, None);
        assert_eq!(out["count"], 1);
        assert_eq!(out["tools"][0]["id"], "mcp.filesystem.read_file");
    }

    #[test]
    fn tool_aliases_resolve_path_and_playbook() {
        assert_eq!(
            resolve_tool_alias("aws.network.path.reachability"),
            Some("aws.network.path.analyze")
        );
        assert_eq!(
            resolve_tool_alias("gcp.network.path.connectivity_test"),
            Some("gcp.network.connectivity.test")
        );
        assert_eq!(
            resolve_tool_alias("azure.network.path.next_hop"),
            Some("azure.network.next_hop")
        );
        let mut reg = ToolRegistry::new();
        reg.register(dummy("aws.network.path.analyze", vec![Cloud::Aws]));
        assert!(reg.get("aws.network.path.reachability").is_some());
        assert_eq!(
            reg.get("aws.network.path.reachability").unwrap().meta().id,
            "aws.network.path.analyze"
        );
    }

    #[test]
    fn write_tool_blocked_in_readonly_mode() {
        use oscar_core::ExecutionMode;
        use oscar_mode::check_capability;

        // Same gate as ToolRegistry::execute
        assert!(
            check_capability(ExecutionMode::ReadOnly, Capability::Write, "aws.network.vpc.create")
                .is_err()
        );
        assert!(
            check_capability(
                ExecutionMode::ReadWrite,
                Capability::Write,
                "aws.network.vpc.create"
            )
            .is_ok()
        );
        assert!(
            check_capability(
                ExecutionMode::ReadOnly,
                Capability::Read,
                "aws.network.vpc.pattern"
            )
            .is_ok()
        );
        // DNS + network write ids
        for id in [
            "aws.network.subnet.delete",
            "gcp.network.firewall.create",
            "azure.network.peering.delete",
            "aws.dns.record.create",
        ] {
            assert!(
                check_capability(ExecutionMode::ReadOnly, Capability::Write, id).is_err(),
                "{id} must be blocked in readonly"
            );
        }
    }

    #[test]
    fn soft_search_connectivity_and_envoy_tags() {
        let mut reg = ToolRegistry::new();
        reg.register(Arc::new(DummyTool {
            meta: ToolMeta {
                id: "aws.network.path.analyze".into(),
                name: "path".into(),
                description: "reachability".into(),
                domain: ToolDomain::Network,
                clouds: vec![Cloud::Aws],
                capability: Capability::Read,
                tags: vec![
                    "connectivity".into(),
                    "analyze".into(),
                    "troubleshoot".into(),
                ],
                input_schema: json!({}),
                output_schema: None,
            },
        }));
        reg.register(Arc::new(DummyTool {
            meta: ToolMeta {
                id: "mesh.envoy.diagnose".into(),
                name: "envoy diagnose".into(),
                description: "mesh".into(),
                domain: ToolDomain::Network,
                clouds: vec![Cloud::Multi],
                capability: Capability::Read,
                tags: vec!["envoy".into(), "mesh".into(), "status".into()],
                input_schema: json!({}),
                output_schema: None,
            },
        }));
        let conn = reg.search("connectivity test", Some(ToolDomain::Network), None, None);
        assert!(
            conn.iter().any(|m| m.id.contains("path.analyze")),
            "connectivity should hit path analyze"
        );
        let env = reg.search("envoy clusters", None, None, None);
        assert!(
            env.iter().any(|m| m.id.contains("envoy")),
            "envoy query should find mesh tools"
        );
    }
}

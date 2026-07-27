//! Multi-cloud discovery tools — find where a domain/IP lives across CSPs.

use crate::helpers::{load_dns_cache, load_dns_resolver_cache, load_network_cache};
use crate::pattern_schema::{discovery_blurb, discovery_tool_result, pattern_properties, to_tool_result};
use crate::scan::{
    scan_dns_inventory, scan_dns_resolver_inventory, scan_network_inventory, PublicDnsProbe,
};
use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use crate::ToolRegistry;
use async_trait::async_trait;
use oscar_core::{
    discover_skills, find_skill, Capability, Cloud, InstallBinariesPolicy, PatternQuery,
    SkillsSettings, ToolDomain,
};
use oscar_identity::{binaries_for_tools, critical_csp_binaries, plan_install};
use serde_json::json;
use std::sync::Arc;

pub fn register_multi(registry: &mut ToolRegistry) {
    registry.register(Arc::new(DnsPatternFind));
    registry.register(Arc::new(NetworkPatternFind));
    registry.register(Arc::new(DnsWhere));
    registry.register(Arc::new(DnsResolvePublic));
    registry.register(Arc::new(DnsInventorySyncMulti));
    registry.register(Arc::new(DnsForwardingMap));
    registry.register(Arc::new(DnsQuerylogHints));
    registry.register(Arc::new(MulticloudInterconnectAwareness));
    registry.register(Arc::new(MulticloudPathNarrative));
    registry.register(Arc::new(MulticloudPathOrchestrate));
    registry.register(Arc::new(SystemBinariesList));
    registry.register(Arc::new(SystemBinariesInstallPlan));
    registry.register(Arc::new(SystemSettingsGet));
    registry.register(Arc::new(SystemSkillsList));
    registry.register(Arc::new(SystemSkillsGet));
    registry.register(Arc::new(SystemIdentitiesList));
    registry.register(Arc::new(AccessTroubleshootGuide));
    registry.register(Arc::new(AccessPatternFind));
}

struct SystemIdentitiesList;

struct SystemSkillsList;
struct SystemSkillsGet;

#[async_trait]
impl Tool for SystemIdentitiesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.identities.list".into(),
            name: "List oscar identities / access".into(),
            description: "Show what cloud/LLM/k8s identities oscar currently has configured and whether they validate (keychain short-lived keys, binary sessions, profiles). Never returns secret values. User UI: /identities or oscar identities check.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "identity".into(),
                "identities".into(),
                "access".into(),
                "auth".into(),
                "profile".into(),
                "credentials".into(),
                "whoami".into(),
                "valid".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "live": {
                        "type": "boolean",
                        "default": true,
                        "description": "If true, live-probe STS/gcloud/az/kubectl (slower). If false, keychain presence only."
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{
            build_identity_inventory, build_identity_inventory_quick, ProfileStore,
        };
        let live = args
            .get("live")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let store = oscar_core::Paths::discover()
            .and_then(|p| ProfileStore::load(&p))
            .unwrap_or_else(|_| {
                ProfileStore::load_path(std::path::Path::new(
                    "/var/empty/oscar-no-profiles.toml",
                ))
                .expect("empty profile store")
            });
        let inv = if live {
            build_identity_inventory(&store, &ctx.binaries)
        } else {
            build_identity_inventory_quick(&store)
        };
        ToolResult::success(
            inv.summary_line(),
            json!({
                "inventory": inv,
                "ui": "User can open /identities or Ctrl+I in TUI; CLI: oscar identities check",
            }),
        )
    }
}

fn skills_settings_from_ctx(ctx: &ToolContext) -> SkillsSettings {
    (*ctx.skills_settings).clone()
}

#[async_trait]
impl Tool for SystemSkillsList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.skills.list".into(),
            name: "List available skills".into(),
            description: "List user/project/builtin skills that steer the agent outside the fixed harness prompt. Use before system.skills.get when choosing a playbook (IAM least-privilege, k8s CNI, VLSM network, discovery intent, permission test plan).".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "skills".into(),
                "skill".into(),
                "playbook".into(),
                "prompt".into(),
                "steer".into(),
                "system".into(),
            ],
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: None,
        })
    }

    async fn execute(&self, _args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let settings = skills_settings_from_ctx(ctx);
        let skills = discover_skills(&settings);
        let list: Vec<_> = skills
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "description": s.description,
                    "when_to_use": s.when_to_use,
                    "source": s.source,
                    "user_invocable": s.user_invocable,
                    "disable_model_invocation": s.disable_model_invocation,
                })
            })
            .collect();
        ToolResult::success(
            format!("{} skill(s) available", list.len()),
            json!({
                "skills": list,
                "how_to_use": "Call system.skills.get with name to load full instructions. User can /skill <name> to pin into the session harness.",
                "locations": [
                    "./.oscar/skills/<name>/SKILL.md",
                    "~/.config/oscar/skills/<name>/SKILL.md",
                    "builtin (shipped with oscar)",
                ]
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemSkillsGet {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.skills.get".into(),
            name: "Load skill instructions".into(),
            description: "Load the full markdown body of a skill playbook. Follow it for the current task while still obeying harness safety (least privilege, no secrets in chat, first-class tools first).".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "skills".into(),
                "skill".into(),
                "playbook".into(),
                "load".into(),
                "system".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Skill name e.g. least-privilege-iam, k8s-cni-connectivity, network-vlsm-path"
                    }
                },
                "required": ["name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let name = match args.get("name").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return ToolResult::error("missing name"),
        };
        let settings = skills_settings_from_ctx(ctx);
        match find_skill(name, &settings) {
            Some(s) => ToolResult::success(
                format!("loaded skill `{}` ({})", s.name, s.source),
                json!({
                    "name": s.name,
                    "description": s.description,
                    "when_to_use": s.when_to_use,
                    "source": s.source,
                    "path": s.path,
                    "body": s.body,
                    "instruction": "Follow this skill for the current task. Harness safety still applies.",
                }),
            ),
            None => ToolResult::error(format!(
                "unknown skill `{name}` — call system.skills.list"
            )),
        }
    }
}

struct AccessTroubleshootGuide;
struct AccessPatternFind;

#[async_trait]
impl Tool for AccessTroubleshootGuide {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "access.troubleshoot".into(),
            name: "Multi-cloud access/IAM troubleshoot guide".into(),
            description: "Route IAM permission issues to the right CSP tools: simulate/test, get user/role, attach/detach policies, bindings, RBAC assignments. Use when user asks why access is denied or who can do X.".into(),
            domain: ToolDomain::Access,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "iam".into(),
                "access".into(),
                "permission".into(),
                "troubleshoot".into(),
                "role".into(),
                "user".into(),
                "policy".into(),
                "rbac".into(),
                "denied".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string", "enum": ["aws", "gcp", "azure", "auto"] },
                    "symptom": { "type": "string", "description": "e.g. AccessDenied, 403, permission denied" },
                    "principal": { "type": "string" },
                    "action": { "type": "string" },
                    "resource": { "type": "string" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let cloud = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .unwrap_or("auto");
        let playbooks = json!({
            "aws": {
                "whoami": "aws.iam.caller.identity",
                "test": "aws.iam.access.test / aws.iam.simulate",
                "inspect_user": "aws.iam.user.get",
                "inspect_role": "aws.iam.role.get",
                "search": "aws.iam.pattern.search",
                "manage": [
                    "aws.iam.user.create/delete",
                    "aws.iam.role.create/delete",
                    "aws.iam.group.create/delete",
                    "aws.iam.policy.create/delete",
                    "aws.iam.policy.attach/detach",
                    "aws.iam.group.add_user/remove_user",
                    "aws.iam.inline_policy.put/delete"
                ],
                "notes": [
                    "Permission denied with valid session → wrong IAM policy, not re-auth",
                    "simulate-principal-policy needs user/role ARN (not assumed-role session ARN)",
                    "Mutations require oscar mode readwrite"
                ]
            },
            "gcp": {
                "test": "gcp.iam.test_permissions / gcp.iam.access.test",
                "inspect_policy": "gcp.iam.policy.get",
                "search": "gcp.iam.pattern.search",
                "manage": [
                    "gcp.iam.service_account.create/delete",
                    "gcp.iam.binding.add/remove"
                ],
                "notes": ["Project IAM bindings are roles→members", "Mutations require readwrite"]
            },
            "azure": {
                "test": "azure.iam.access.test / azure.iam.check_access",
                "list_assignments": "azure.iam.role_assignments.list",
                "search": "azure.iam.pattern.search / azure.iam.principals.search",
                "manage": [
                    "azure.iam.role_assignment.create/delete",
                    "azure.iam.users.list"
                ],
                "notes": ["RBAC is role assignment at scope", "Mutations require readwrite"]
            }
        });
        let selected = match cloud {
            "aws" => json!({ "aws": playbooks["aws"].clone() }),
            "gcp" => json!({ "gcp": playbooks["gcp"].clone() }),
            "azure" => json!({ "azure": playbooks["azure"].clone() }),
            _ => playbooks,
        };
        ToolResult::success(
            format!("access troubleshoot playbook (cloud={cloud})"),
            json!({
                "symptom": args.get("symptom"),
                "principal": args.get("principal"),
                "action": args.get("action"),
                "resource": args.get("resource"),
                "playbooks": selected,
                "operator_steps": [
                    "1. Identify cloud + principal (whoami / caller.identity)",
                    "2. Run access.test or simulate with action+resource",
                    "3. Inspect attached policies/bindings",
                    "4. If change needed: switch to readwrite and create/attach/bind",
                    "5. Re-test"
                ]
            }),
        )
    }
}

#[async_trait]
impl Tool for AccessPatternFind {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "access.pattern.find".into(),
            name: "Multi-cloud IAM pattern find".into(),
            description: "Hint tool: use per-CSP aws.iam.pattern.search / gcp.iam.pattern.search / azure.iam.pattern.search to find users, roles, policies, bindings by name.".into(),
            domain: ToolDomain::Access,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "iam".into(),
                "access".into(),
                "pattern".into(),
                "search".into(),
                "user".into(),
                "role".into(),
                "multi".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string" },
                    "clouds": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let pattern = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        ToolResult::success(
            format!("route pattern `{pattern}` to per-CSP IAM search tools"),
            json!({
                "pattern": pattern,
                "tools": {
                    "aws": "aws.iam.pattern.search",
                    "gcp": "gcp.iam.pattern.search",
                    "azure": "azure.iam.pattern.search"
                },
                "troubleshoot": "access.troubleshoot",
                "note": "Call tools_execute on the CSP-specific search tool for live results"
            }),
        )
    }
}

struct SystemBinariesList;
struct SystemBinariesInstallPlan;
struct SystemSettingsGet;

#[async_trait]
impl Tool for SystemSettingsGet {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.settings.get".into(),
            name: "Get user tool settings".into(),
            description: "Return user settings: disabled first-class tools, disabled clouds, install_binaries policy (off|recommend|ask-admin|install-all). Disabled tools never appear in tools_search.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec!["settings".into(), "menu".into(), "disable".into(), "install".into()],
            input_schema: json!({ "type": "object", "properties": {} }),
            output_schema: None,
        })
    }

    async fn execute(&self, _args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let s = &*ctx.settings;
        ToolResult::success(
            format!(
                "install_policy={} disabled_tools={} disabled_clouds={}",
                s.install_binaries.as_str(),
                s.disabled.len(),
                s.disabled_clouds.len()
            ),
            json!({
                "disabled_tools": s.disabled,
                "disabled_clouds": s.disabled_clouds,
                "install_binaries": s.install_binaries.as_str(),
                "allow_admin_install_prompt": s.allow_admin_install_prompt,
                "user_menu": "oscar settings menu | oscar settings disable-tool <id> | enable-tool | disable-cloud aws | install-policy recommend|ask-admin|install-all|off",
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemBinariesInstallPlan {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.binaries.install_plan".into(),
            name: "Plan or request binary installs".into(),
            description: "Based on install_binaries policy: recommend missing CLIs, or request admin-elevated install approval for packages needed by enabled first-class tools. Never runs sudo without user approval (InstallApprovalRequired). Policy off → only report missing.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "binary".into(),
                "install".into(),
                "admin".into(),
                "sudo".into(),
                "packages".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "scope": {
                        "type": "string",
                        "enum": ["missing_critical", "enabled_tools", "explicit"],
                        "default": "missing_critical",
                        "description": "missing_critical=aws/gcloud/az/kubectl gaps; enabled_tools=binaries for all non-disabled first-class tools; explicit=use binaries list"
                    },
                    "binaries": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "When scope=explicit, binaries to install (e.g. aws, kubectl)"
                    },
                    "request_admin": {
                        "type": "boolean",
                        "default": false,
                        "description": "If true and policy allows, mark plan as needing user admin approval"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let policy = ctx.settings.install_binaries;
        if matches!(policy, InstallBinariesPolicy::Off) {
            return ToolResult::success(
                "install_binaries policy is off — will not plan installs; report missing binaries only",
                json!({
                    "policy": "off",
                    "available": ctx.binaries.available,
                    "missing_critical": ctx.binaries.missing_critical,
                    "action": "recommend_manual_only",
                }),
            );
        }

        // install-all defaults to full enabled-tool / cloud-aware critical set
        let default_scope = if matches!(policy, InstallBinariesPolicy::InstallAll) {
            "enabled_tools"
        } else {
            "missing_critical"
        };
        let scope = args
            .get("scope")
            .and_then(|v| v.as_str())
            .unwrap_or(default_scope);
        let wanted: Vec<String> = match scope {
            "explicit" => args
                .get("binaries")
                .and_then(|v| v.as_array())
                .map(|a| {
                    a.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default(),
            "enabled_tools" => {
                // Caller may pass tool ids; else critical set for install-all (respect disabled clouds)
                if let Some(ids) = args.get("tool_ids").and_then(|v| v.as_array()) {
                    let tids: Vec<String> = ids
                        .iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .filter(|id| ctx.settings.is_tool_enabled(id))
                        .collect();
                    binaries_for_tools(&tids)
                        .into_iter()
                        .filter(|b| binary_allowed_for_settings(b, &ctx.settings))
                        .collect()
                } else {
                    critical_csp_binaries()
                        .into_iter()
                        .filter(|b| binary_allowed_for_settings(b, &ctx.settings))
                        .collect()
                }
            }
            _ => critical_csp_binaries()
                .into_iter()
                .filter(|b| binary_allowed_for_settings(b, &ctx.settings))
                .collect(),
        };

        let plan = plan_install(&wanted, &ctx.binaries);
        if plan.binaries.is_empty() {
            return ToolResult::success(
                "all requested binaries already available",
                json!({ "policy": policy.as_str(), "plan": plan }),
            );
        }

        let request_admin = args
            .get("request_admin")
            .and_then(|v| v.as_bool())
            .unwrap_or(false)
            || matches!(
                policy,
                InstallBinariesPolicy::AskAdmin | InstallBinariesPolicy::InstallAll
            );

        let needs_approval = request_admin
            && ctx.settings.allow_admin_install_prompt
            && !matches!(policy, InstallBinariesPolicy::Recommend);

        let summary = if needs_approval {
            format!(
                "ADMIN APPROVAL NEEDED to install missing binaries: {} via {} — user must approve elevated install",
                plan.binaries.join(", "),
                plan.package_manager.as_str()
            )
        } else {
            format!(
                "Recommend installing missing binaries: {} (policy={})",
                plan.binaries.join(", "),
                policy.as_str()
            )
        };

        ToolResult::success(
            summary,
            json!({
                "policy": policy.as_str(),
                "needs_user_admin_approval": needs_approval,
                "install_all_intent": matches!(policy, InstallBinariesPolicy::InstallAll),
                "plan": plan,
                "operator_steps": if needs_approval {
                    vec![
                        "Show the install commands to the user",
                        "User approves with: approve install  (or oscar binaries install --yes)",
                        "After install, agent refreshes binary inventory and retries tools",
                    ]
                } else {
                    vec![
                        "Show recommended install commands",
                        "Do not run sudo yourself unless policy is ask-admin/install-all and user approved",
                    ]
                },
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemBinariesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.binaries.list".into(),
            name: "List available system binaries".into(),
            description: "Return the session binary inventory (CLIs on PATH the agent may use). Use to decide first-class tools vs CLI vs API fallbacks. Does not expose secrets.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "binary".into(),
                "inventory".into(),
                "system".into(),
                "path".into(),
                "feasibility".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "refresh": {
                        "type": "boolean",
                        "default": false,
                        "description": "If true, re-scan PATH (default uses session inventory when available)"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let refresh = args
            .get("refresh")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let inv = if refresh {
            oscar_identity::BinaryInventory::detect()
        } else {
            (*ctx.binaries).clone()
        };
        ToolResult::success(
            format!(
                "{} binaries available; missing critical: {}",
                inv.available.len(),
                if inv.missing_critical.is_empty() {
                    "none".into()
                } else {
                    inv.missing_critical.join(", ")
                }
            ),
            inv.feasibility_json(),
        )
    }
}

/// Map binary → cloud so install-all / missing_critical skip disabled clouds (e.g. AWS-only).
fn binary_allowed_for_settings(binary: &str, settings: &oscar_core::ToolsSettings) -> bool {
    match binary {
        "aws" => settings.is_cloud_enabled("aws"),
        "gcloud" => settings.is_cloud_enabled("gcp"),
        "az" => settings.is_cloud_enabled("azure"),
        "kubectl" | "helm" => settings.is_cloud_enabled("k8s"),
        _ => true,
    }
}

struct DnsInventorySyncMulti;

struct DnsPatternFind;
struct NetworkPatternFind;
struct DnsWhere;
struct DnsForwardingMap;

/// C9 — narrative + ranked edges for private DNS forwarding across CSPs.
#[async_trait]
impl Tool for DnsForwardingMap {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.forwarding.map".into(),
            name: "Cross-CSP private DNS forwarding map".into(),
            description: "Map private DNS forwarding across AWS Route 53 Resolver, GCP Cloud DNS policies/forwarding zones, and Azure Private DNS links / Private Resolver from unified DnsResolverInventory caches. Prefer after per-CSP *.dns.resolver.inventory.sync. Optional pattern filters the narrative.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "forwarding".into(),
                "private".into(),
                "resolver".into(),
                "multi".into(),
                "map".into(),
                "narrative".into(),
                "hybrid".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "Optional domain/name/IP fragment filter" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "limit": { "type": "integer", "default": 50 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let pattern = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("*")
            .to_string();
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(50)
            .clamp(1, 200) as usize;
        let profile_id = args.get("profile_id").and_then(|v| v.as_str());
        let region = args.get("region").and_then(|v| v.as_str());

        let mut edges = Vec::new();
        let mut notes = Vec::new();
        let mut hits_total = 0usize;

        for p in ctx.profiles.list() {
            if !matches!(p.cloud, Cloud::Aws | Cloud::Gcp | Cloud::Azure) {
                continue;
            }
            if let Some(pid) = profile_id {
                if p.id != pid {
                    continue;
                }
            }
            let r = region.or(p.default_region.as_deref());
            let Some(inv) = load_dns_resolver_cache(&ctx.config_dir, &p.id, r) else {
                notes.push(format!(
                    "no DnsResolverInventory for {} (`{}`) — run {}.dns.resolver.inventory.sync",
                    p.cloud,
                    p.id,
                    p.cloud.to_string().to_ascii_lowercase()
                ));
                continue;
            };

            if pattern != "*" && !pattern.is_empty() {
                if let Ok(q) = PatternQuery::from_args(&json!({
                    "pattern": pattern,
                    "limit": limit,
                    "profile_id": p.id,
                    "region": r,
                })) {
                    let part = scan_dns_resolver_inventory(&inv, &q);
                    hits_total += part.hits.len();
                }
            }

            for ep in &inv.endpoints {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": "resolver_endpoint",
                    "direction": ep.direction,
                    "name": ep.name,
                    "id": ep.id,
                    "vpc_id": ep.vpc_id,
                    "ips": ep.ip_addresses,
                    "narrative": format!(
                        "{} {} endpoint `{}` in VPC {:?} ips={:?}",
                        inv.cloud, ep.direction, ep.name.as_deref().unwrap_or(&ep.id), ep.vpc_id, ep.ip_addresses
                    ),
                }));
            }
            for rule in &inv.rules {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": "resolver_rule",
                    "domain": rule.domain_name,
                    "name": rule.name,
                    "id": rule.id,
                    "target_ips": rule.target_ips,
                    "endpoint_id": rule.resolver_endpoint_id,
                    "narrative": format!(
                        "{} FORWARD `{}` → targets {:?} via endpoint {:?}",
                        inv.cloud, rule.domain_name, rule.target_ips, rule.resolver_endpoint_id
                    ),
                }));
            }
            for pol in &inv.policies {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": pol.policy_type.clone().unwrap_or_else(|| "policy".into()),
                    "name": pol.name,
                    "id": pol.id,
                    "networks": pol.networks,
                    "name_servers": pol.alternative_name_servers,
                    "domains": pol.domains,
                    "narrative": format!(
                        "{} {:?} `{}` networks={:?} ns={:?} domains={:?}",
                        inv.cloud,
                        pol.policy_type,
                        pol.name.as_deref().unwrap_or(&pol.id),
                        pol.networks,
                        pol.alternative_name_servers,
                        pol.domains
                    ),
                }));
            }
            for link in &inv.vnet_links {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": "vnet_link",
                    "zone": link.zone_name,
                    "name": link.name,
                    "vnet_id": link.vnet_id,
                    "registration_enabled": link.registration_enabled,
                    "narrative": format!(
                        "{} Private DNS zone `{}` linked to VNet {:?} (registration={:?})",
                        inv.cloud, link.zone_name, link.vnet_id, link.registration_enabled
                    ),
                }));
            }
            for pr in &inv.private_resolvers {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": "private_resolver",
                    "name": pr.name,
                    "id": pr.id,
                    "vnet_id": pr.vnet_id,
                    "endpoints": pr.endpoints,
                    "rulesets": pr.rulesets,
                    "narrative": format!(
                        "{} Private Resolver `{}` vnet={:?} endpoints={:?} rulesets={:?}",
                        inv.cloud,
                        pr.name.as_deref().unwrap_or(&pr.id),
                        pr.vnet_id,
                        pr.endpoints,
                        pr.rulesets
                    ),
                }));
            }
            for pr in &inv.profiles {
                edges.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "kind": "r53_profile",
                    "name": pr.name,
                    "id": pr.id,
                    "share_status": pr.share_status,
                    "narrative": format!(
                        "{} Route 53 Profile `{}` share={:?}",
                        inv.cloud,
                        pr.name.as_deref().unwrap_or(&pr.id),
                        pr.share_status
                    ),
                }));
            }
        }

        if pattern != "*" && !pattern.is_empty() {
            let pat = pattern.to_ascii_lowercase();
            edges.retain(|e| e.to_string().to_ascii_lowercase().contains(&pat));
        }
        edges.truncate(limit);

        let summary = if edges.is_empty() {
            format!(
                "No forwarding edges (pattern=`{pattern}`). Sync with aws|gcp|azure.dns.resolver.inventory.sync first."
            )
        } else {
            format!(
                "{} private DNS forwarding edge(s) across profiles (pattern=`{pattern}`)",
                edges.len()
            )
        };

        ToolResult::success(
            summary,
            json!({
                "format": "DnsForwardingMap",
                "pattern": pattern,
                "edges": edges,
                "edge_count": edges.len(),
                "scan_hits": hits_total,
                "notes": notes,
            }),
        )
    }
}

#[async_trait]
impl Tool for DnsPatternFind {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.pattern.find".into(),
            name: "Multi-cloud DNS pattern find".into(),
            description: format!(
                "{} Scans AWS+GCP+Azure DNS inventories and optional public resolver. Use to answer: where does this domain/name fragment live?",
                discovery_blurb("DNS zones and records across all configured cloud profiles")
            ),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "pattern".into(),
                "search".into(),
                "discover".into(),
                "multi".into(),
                "where".into(),
                "partial".into(),
                "glob".into(),
                "private".into(),
                "public".into(),
                "zone".into(),
                "record".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": pattern_properties()["pattern"].clone(),
                    "query": pattern_properties()["query"].clone(),
                    "mode": pattern_properties()["mode"].clone(),
                    "profile_id": pattern_properties()["profile_id"].clone(),
                    "limit": pattern_properties()["limit"].clone(),
                    "include_public": {
                        "type": "boolean",
                        "default": true,
                        "description": "Also probe public system resolver when pattern looks like a FQDN"
                    },
                    "clouds": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional filter: aws, gcp, azure"
                    }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let q = match PatternQuery::from_args(&args) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(e),
        };
        let include_public = args
            .get("include_public")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let cloud_filter: Option<Vec<Cloud>> = args.get("clouds").and_then(|v| v.as_array()).map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().and_then(Cloud::parse))
                .collect()
        });

        let mut merged = oscar_core::DiscoveryResult::empty(&q.pattern, q.mode, "dns.pattern.find:multi");
        let mut any = false;

        for p in ctx.profiles.list() {
            if !matches!(p.cloud, Cloud::Aws | Cloud::Gcp | Cloud::Azure) {
                continue;
            }
            if let Some(ref cf) = cloud_filter {
                if !cf.contains(&p.cloud) {
                    continue;
                }
            }
            if let Some(pid) = &q.profile_id {
                if &p.id != pid {
                    continue;
                }
            }
            if let Some(inv) = load_dns_cache(&ctx.config_dir, &p.id) {
                any = true;
                let mut part = scan_dns_inventory(&inv, &q);
                merged.hits.append(&mut part.hits);
            } else {
                merged.partial = true;
                merged.notes.push(format!("no DNS cache for {} (`{}`)", p.cloud, p.id));
            }
        }

        if ctx.profiles.list().is_empty() {
            merged.partial = true;
            merged.notes.push("No cloud profiles configured.".into());
        }

        if include_public && looks_like_hostname(&q.pattern) {
            let public_hits = PublicDnsProbe::resolve_name(&q.pattern).await;
            if !public_hits.is_empty() {
                any = true;
                merged.hits.extend(public_hits);
            } else {
                merged.notes.push(format!(
                    "public resolver: no A/AAAA for `{}`",
                    q.pattern.trim_end_matches('.')
                ));
            }
        }

        if !any {
            merged.partial = true;
            merged.notes.push(
                "No DNS inventory hits yet. Populate cache files under ~/.config/oscar/cache/<profile>/dns.json or configure profiles.".into(),
            );
        }

        merged.hits.truncate(q.limit);
        to_tool_result(discovery_tool_result(merged.finalize()))
    }
}

fn looks_like_hostname(s: &str) -> bool {
    let s = s.trim().trim_end_matches('.');
    s.contains('.')
        && !s.contains(' ')
        && !s.contains('/')
        && s.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '*')
        && !s.contains('*') // globs aren't resolvable publicly as-is
}

#[async_trait]
impl Tool for DnsWhere {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.where".into(),
            name: "Where does this domain live?".into(),
            description: "Convenience alias for dns.pattern.find — locate zones/records hosting a domain name across clouds + public DNS.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "where".into(),
                "discover".into(),
                "pattern".into(),
                "multi".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": { "type": "string", "description": "Domain or name fragment" },
                    "pattern": { "type": "string" },
                    "include_public": { "type": "boolean", "default": true },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Some(obj) = args.as_object_mut() {
            if !obj.contains_key("pattern") {
                if let Some(n) = obj.get("name").cloned() {
                    obj.insert("pattern".into(), n);
                }
            }
            obj.entry("include_public".to_string())
                .or_insert(json!(true));
        }
        DnsPatternFind.execute(args, ctx).await
    }
}

struct DnsResolvePublic;

/// Plan tool `dns.resolve.public` — system resolver A/AAAA (no CSP inventory).
#[async_trait]
impl Tool for DnsResolvePublic {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.resolve.public".into(),
            name: "Public DNS resolve".into(),
            description: "Resolve a FQDN via the host system resolver (public Internet A/AAAA). Does not query private CSP zones — use dns.where / dns.pattern.find for inventory. Fast check for public reachability of a name.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "public".into(),
                "resolve".into(),
                "a".into(),
                "aaaa".into(),
                "lookup".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "Fully-qualified domain name (e.g. api.example.com)"
                    },
                    "query": { "type": "string", "description": "Alias for name" }
                },
                "required": ["name"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let name = args
            .get("name")
            .or_else(|| args.get("query"))
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .trim_end_matches('.');
        if name.is_empty() {
            return ToolResult::error("name is required (FQDN)");
        }
        if name.contains('*') || name.contains(' ') {
            return ToolResult::error("name must be a concrete FQDN (no wildcards/spaces)");
        }
        let hits = PublicDnsProbe::resolve_name(name).await;
        if hits.is_empty() {
            return ToolResult::success(
                format!("public resolve: no A/AAAA for `{name}`"),
                json!({
                    "query": name,
                    "scope": "public_system_resolver",
                    "records": [],
                    "ok": false,
                }),
            );
        }
        let ips: Vec<String> = hits
            .iter()
            .filter_map(|h| h.attrs.get("values"))
            .filter_map(|v| v.as_array())
            .flat_map(|a| a.iter().filter_map(|x| x.as_str().map(|s| s.to_string())))
            .collect();
        ToolResult::success(
            format!("public resolve `{name}` → {}", ips.join(", ")),
            json!({
                "query": name,
                "scope": "public_system_resolver",
                "records": hits,
                "values": ips,
                "ok": true,
                "format": "DnsLookupResult-ish",
            }),
        )
    }
}

#[async_trait]
impl Tool for DnsInventorySyncMulti {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.inventory.sync".into(),
            name: "Sync DNS inventory (all clouds)".into(),
            description: "Hint tool: prefer per-CSP aws.dns.inventory.sync / gcp.dns.inventory.sync / azure.dns.inventory.sync. Returns which profiles need sync and unified format contract.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec!["dns".into(), "sync".into(), "inventory".into(), "multi".into()],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "clouds": {
                        "type": "array",
                        "items": { "type": "string" }
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, _args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let mut profiles = Vec::new();
        for p in ctx.profiles.list() {
            let cached = load_dns_cache(&ctx.config_dir, &p.id).is_some();
            profiles.push(json!({
                "profile_id": p.id,
                "cloud": p.cloud.to_string(),
                "account_ref": p.account_ref,
                "dns_cache_present": cached,
                "sync_tool": match p.cloud {
                    Cloud::Aws => "aws.dns.inventory.sync",
                    Cloud::Gcp => "gcp.dns.inventory.sync",
                    Cloud::Azure => "azure.dns.inventory.sync",
                    _ => "n/a",
                }
            }));
        }
        ToolResult::success(
            format!(
                "{} profile(s) — use per-CSP *.dns.inventory.sync to fill unified DnsInventory cache",
                profiles.len()
            ),
            json!({
                "format": "DnsInventory",
                "cache_root": ctx.config_dir.join("cache").display().to_string(),
                "profiles": profiles
            }),
        )
    }
}

#[async_trait]
impl Tool for NetworkPatternFind {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "network.pattern.find".into(),
            name: "Multi-cloud network pattern find".into(),
            description: format!(
                "{} Answers: which VPC/subnet/IP inventory matches this fragment across AWS, GCP, Azure, and k8s cluster IPs.",
                discovery_blurb("VPCs/VNets, subnets, IPs, and k8s pod/svc/node addresses")
            ),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "pattern".into(),
                "search".into(),
                "discover".into(),
                "multi".into(),
                "subnet".into(),
                "vpc".into(),
                "ip".into(),
                "cidr".into(),
                "partial".into(),
                "k8s".into(),
                "pod".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": pattern_properties(),
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let q = match PatternQuery::from_args(&args) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(e),
        };

        let mut merged =
            oscar_core::DiscoveryResult::empty(&q.pattern, q.mode, "network.pattern.find:multi");

        for p in ctx.profiles.list() {
            if !matches!(
                p.cloud,
                Cloud::Aws | Cloud::Gcp | Cloud::Azure | Cloud::K8s
            ) {
                continue;
            }
            if let Some(pid) = &q.profile_id {
                if &p.id != pid {
                    continue;
                }
            }
            // CSP network caches use region; k8s F9 writes region=cluster
            let region = if p.cloud == Cloud::K8s {
                Some("cluster")
            } else {
                q.region.as_deref()
            };
            if let Some(inv) = load_network_cache(&ctx.config_dir, &p.id, region) {
                let mut part = scan_network_inventory(&inv, &q);
                merged.hits.append(&mut part.hits);
            } else if p.cloud != Cloud::K8s {
                merged.partial = true;
                merged.notes.push(format!("no network cache for {} (`{}`)", p.cloud, p.id));
            }
        }

        // Ambient k8s network cache written by k8s.inventory.sync (F9)
        for key in ["k8s-default", "default"] {
            if let Some(inv) = load_network_cache(&ctx.config_dir, key, Some("cluster")) {
                let mut part = scan_network_inventory(&inv, &q);
                merged.hits.append(&mut part.hits);
            }
        }

        if merged.hits.is_empty() {
            merged.partial = true;
            merged.notes.push(
                "No network inventory hits. Populate via oscar inventory sync --kind network|k8s".into(),
            );
        }

        merged.hits.truncate(q.limit);
        to_tool_result(discovery_tool_result(merged.finalize()))
    }
}

// ─── D4: DNS query log aggregation hints ───────────────────────────────────

struct DnsQuerylogHints;

/// D4 — where each CSP sends DNS query logs and how to pivot from inventory.
#[async_trait]
impl Tool for DnsQuerylogHints {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "dns.querylog.hints".into(),
            name: "DNS query log aggregation hints".into(),
            description: "Track D4: map where DNS query logs land per CSP (AWS Route 53 Resolver → CloudWatch/S3/Kinesis, GCP Cloud DNS → Cloud Logging, Azure DNS → Monitor diagnostic settings) and list any query-log configs already in DnsResolverInventory caches. Use after *.dns.resolver.inventory.sync or aws.dns.querylog.pattern.search.".into(),
            domain: ToolDomain::Dns,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "dns".into(),
                "query-log".into(),
                "querylog".into(),
                "logging".into(),
                "cloudwatch".into(),
                "aggregation".into(),
                "hints".into(),
                "multi".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "cloud": {
                        "type": "string",
                        "description": "Optional filter: aws | gcp | azure | multi"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let profile_id = args.get("profile_id").and_then(|v| v.as_str());
        let region = args.get("region").and_then(|v| v.as_str());
        let cloud_f = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .unwrap_or("multi")
            .to_ascii_lowercase();

        let playbook = json!([
            {
                "cloud": "aws",
                "service": "Route 53 Resolver query logging",
                "destination": ["CloudWatch Logs", "S3", "Kinesis Data Firehose"],
                "inventory_tools": [
                    "aws.dns.resolver.inventory.sync",
                    "aws.dns.querylog.pattern.search"
                ],
                "cli_hints": [
                    "aws route53resolver list-resolver-query-log-configs",
                    "aws logs filter-log-events --log-group-name <from dest ARN>",
                    "aws s3 ls s3://<bucket-from-config>/"
                ],
                "note": "Query-log configs appear in DnsResolverInventory.query_log_configs with destination_arn."
            },
            {
                "cloud": "gcp",
                "service": "Cloud DNS query logging (DNS policies / public zone logging)",
                "destination": ["Cloud Logging"],
                "inventory_tools": [
                    "gcp.dns.resolver.inventory.sync",
                    "gcp.dns.policy.pattern.search"
                ],
                "cli_hints": [
                    "gcloud dns policies list",
                    "gcloud logging read 'resource.type=\"dns_query\"' --limit=20",
                    "gcloud logging read 'protoPayload.serviceName=\"dns.googleapis.com\"' --limit=20"
                ],
                "note": "Enable query logging on DNS policy or public zone; logs land in Cloud Logging under dns_query."
            },
            {
                "cloud": "azure",
                "service": "Azure DNS / Private DNS diagnostic settings",
                "destination": ["Log Analytics", "Storage", "Event Hub"],
                "inventory_tools": [
                    "azure.dns.private_resolver.pattern.search",
                    "azure.dns.vnet_link.pattern.search"
                ],
                "cli_hints": [
                    "az monitor diagnostic-settings list --resource <dns-zone-id>",
                    "az network private-dns zone show -g <rg> -n <zone>",
                    "az monitor log-analytics query -w <workspace-id> --analytics-query \"AzureDiagnostics | where Category == 'DnsQuery'\""
                ],
                "note": "Wire diagnostic settings on the DNS zone or Private Resolver; query AzureDiagnostics / DNS tables."
            }
        ]);

        let mut discovered = Vec::new();
        let mut notes = Vec::new();
        for p in ctx.profiles.list() {
            if !matches!(p.cloud, Cloud::Aws | Cloud::Gcp | Cloud::Azure) {
                continue;
            }
            if cloud_f != "multi" && cloud_f != "all" {
                let want = match p.cloud {
                    Cloud::Aws => "aws",
                    Cloud::Gcp => "gcp",
                    Cloud::Azure => "azure",
                    _ => continue,
                };
                if cloud_f != want {
                    continue;
                }
            }
            if let Some(pid) = profile_id {
                if p.id != pid {
                    continue;
                }
            }
            let r = region.or(p.default_region.as_deref());
            let Some(inv) = load_dns_resolver_cache(&ctx.config_dir, &p.id, r) else {
                notes.push(format!(
                    "no DnsResolverInventory for {} (`{}`) — run {}.dns.resolver.inventory.sync",
                    p.cloud,
                    p.id,
                    p.cloud.to_string().to_ascii_lowercase()
                ));
                continue;
            };
            for ql in &inv.query_log_configs {
                discovered.push(json!({
                    "cloud": inv.cloud.to_string(),
                    "profile_id": inv.profile_id,
                    "id": ql.id,
                    "name": ql.name,
                    "destination_arn": ql.destination_arn,
                    "status": ql.status,
                    "association_count": ql.association_count,
                    "narrative": format!(
                        "{} query-log `{}` → dest {:?} (status={:?}, associations={:?})",
                        inv.cloud,
                        ql.name.as_deref().unwrap_or(&ql.id),
                        ql.destination_arn,
                        ql.status,
                        ql.association_count
                    ),
                }));
            }
            if inv.query_log_configs.is_empty() {
                notes.push(format!(
                    "{} `{}`: inventory present but zero query_log_configs (logging may be off or not applicable)",
                    inv.cloud, inv.profile_id
                ));
            }
        }

        let summary = if discovered.is_empty() {
            format!(
                "DNS query-log playbook ready (AWS→CW/S3, GCP→Logging, Azure→Monitor); {} inventory notes, 0 configs discovered",
                notes.len()
            )
        } else {
            format!(
                "DNS query-log: {} config(s) in inventory + aggregation playbook",
                discovered.len()
            )
        };

        ToolResult::success(
            summary,
            json!({
                "playbook": playbook,
                "discovered_query_logs": discovered,
                "notes": notes,
                "next": [
                    "Sync resolver inventory per cloud, then re-run dns.querylog.hints",
                    "Use destination ARN / workspace to open logs in the CSP console or CLI",
                    "For name-based search of configs: aws.dns.querylog.pattern.search"
                ],
            }),
        )
    }
}

// ─── D1-lite: Multicloud interconnect awareness ────────────────────────────

struct MulticloudInterconnectAwareness;

/// D1/D2 research-backed awareness (not full live inventory until GA tooling stabilizes).
#[async_trait]
impl Tool for MulticloudInterconnectAwareness {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "multicloud.interconnect.awareness".into(),
            name: "Multicloud interconnect awareness".into(),
            description: "Track D1/D2: research-backed map of AWS Interconnect – multicloud (preview), Google Cross-Cloud Interconnect, and Azure ExpressRoute/interconnect posture for cross-CSP path planning. Returns status, CLI discovery hints, and how to wire into PathTrace / network inventory — not a full live catalog until GA APIs stabilize.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "multicloud".into(),
                "interconnect".into(),
                "cross-cloud".into(),
                "expressroute".into(),
                "path".into(),
                "hybrid".into(),
                "awareness".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cloud": {
                        "type": "string",
                        "description": "Optional filter: aws | gcp | azure | multi"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let cloud_f = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .unwrap_or("multi")
            .to_ascii_lowercase();

        let mut products = vec![
            json!({
                "cloud": "aws",
                "product": "AWS Interconnect – multicloud",
                "status": "preview (announced ~Nov 2025; GCP pairing first, Azure later)",
                "role": "Dedicated multicloud pipe into AWS VPCs",
                "cli_discovery": [
                    "aws help | rg -i interconnect || true",
                    "aws ec2 describe-transit-gateways",
                    "aws directconnect describe-connections",
                    "aws directconnect describe-virtual-interfaces"
                ],
                "path_tools": [
                    "aws.network.path.reachability",
                    "aws.network.access.analyzer"
                ],
                "oscar_gap": "Full inventory mapper deferred until stable describe APIs; use DX/TGW + path analyzers today."
            }),
            json!({
                "cloud": "gcp",
                "product": "Cross-Cloud Interconnect",
                "status": "GA for several partner/CSP pairs; pairs with AWS Interconnect multicloud when available",
                "role": "Dedicated interconnect from other CSPs into Google Cloud",
                "cli_discovery": [
                    "gcloud compute interconnects list",
                    "gcloud compute interconnects attachments list",
                    "gcloud compute routers list"
                ],
                "path_tools": ["gcp.network.path.connectivity_test"],
                "oscar_gap": "Use gcloud interconnect list + Connectivity Tests; dedicated unified inventory mapper backlog."
            }),
            json!({
                "cloud": "azure",
                "product": "ExpressRoute / future multicloud interconnect pairing",
                "status": "ExpressRoute GA; AWS Interconnect Azure pairing later (2026 track)",
                "role": "Private connectivity into Azure VNets",
                "cli_discovery": [
                    "az network express-route list",
                    "az network express-route list-service-providers",
                    "az network vnet-gateway list"
                ],
                "path_tools": [
                    "azure.network.path.test_connectivity",
                    "azure.network.path.next_hop"
                ],
                "oscar_gap": "ExpressRoute list + NW path tools; agentless Connection Troubleshoot (D3) still backlog."
            }),
        ];

        if cloud_f != "multi" && cloud_f != "all" {
            products.retain(|p| {
                p.get("cloud")
                    .and_then(|c| c.as_str())
                    .map(|c| c == cloud_f)
                    .unwrap_or(false)
            });
        }

        ToolResult::success(
            format!(
                "Multicloud interconnect awareness: {} product note(s) — live full inventory still GA-gated",
                products.len()
            ),
            json!({
                "products": products,
                "recommended_workflow": [
                    "1. Discover existing pipes with CSP CLI (DX / Cross-Cloud Interconnect / ExpressRoute)",
                    "2. Place endpoints in NetworkInventory (VPC/VNet/subnet sync)",
                    "3. Run native path analyzers between endpoint pairs",
                    "4. Revisit multicloud.interconnect.awareness when preview APIs stabilize for auto-inventory"
                ],
                "related_tools": [
                    "network.pattern.find",
                    "dns.forwarding.map",
                    "dns.querylog.hints",
                    "multicloud.path.narrative"
                ],
            }),
        )
    }
}

// ─── Cross-CSP multi-hop path narrative (Phase 6 polish) ───────────────────

struct MulticloudPathNarrative;

/// Ordered playbook for multi-hop / hybrid paths across CSPs + DNS + k8s.
#[async_trait]
impl Tool for MulticloudPathNarrative {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "multicloud.path.narrative".into(),
            name: "Cross-CSP multi-hop path narrative".into(),
            description: "Build a step-by-step troubleshooting narrative for multi-hop paths (on-prem↔cloud, CSP↔CSP, or cluster egress). Combines inventory locate, private DNS forwarding, path analyzers, and interconnect awareness into an ordered playbook with concrete tool ids.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "multicloud".into(),
                "path".into(),
                "hybrid".into(),
                "narrative".into(),
                "playbook".into(),
                "multi-hop".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string", "description": "Source IP, hostname, or resource id" },
                    "destination": { "type": "string", "description": "Destination IP, hostname, or resource id" },
                    "port": { "type": "integer", "default": 443 },
                    "scenario": {
                        "type": "string",
                        "description": "Optional: hybrid | cross_csp | cluster_egress | general",
                        "default": "general"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let source = args
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443);
        let scenario = args
            .get("scenario")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_ascii_lowercase();

        let mut steps = Vec::new();
        steps.push(json!({
            "step": 1,
            "title": "Locate endpoints in inventory",
            "tools": ["network.pattern.find", "dns.where", "dns.pattern.find", "k8s.pods.pattern.search"],
            "hint": if source.is_empty() || dest.is_empty() {
                "Pass source and destination (IP/hostname). Pattern-search each side for VPC/subnet/pod ownership.".to_string()
            } else {
                format!("Search inventory for `{source}` and `{dest}` (partial/IP modes).")
            },
        }));
        steps.push(json!({
            "step": 2,
            "title": "Resolve private DNS / hybrid forwarding",
            "tools": [
                "dns.forwarding.map",
                "aws.dns.resolver.pattern.search",
                "gcp.dns.policy.pattern.search",
                "azure.dns.private_resolver.pattern.search",
                "dns.querylog.hints"
            ],
            "hint": "If either side is a private name, map Resolver/Private DNS links before L4 path analysis.",
        }));
        steps.push(json!({
            "step": 3,
            "title": "Native path analysis per CSP hop",
            "tools": [
                "aws.network.path.analyze",
                "aws.network.access.analyze",
                "gcp.network.connectivity.test",
                "azure.network.path.troubleshoot",
                "azure.network.next_hop"
            ],
            "hint": format!(
                "Run path tools on each hop (port {port}). Prefer resource ids for Azure agentless-style troubleshoot."
            ),
        }));

        if scenario.contains("cluster") || scenario.contains("k8s") || scenario.contains("egress") {
            steps.push(json!({
                "step": 4,
                "title": "Cluster egress / CNI",
                "tools": [
                    "k8s.cni.detect",
                    "k8s.networkpolicy.deny.narrative",
                    "k8s.hubble.observe",
                    "k8s.coredns.discover"
                ],
                "hint": "Detect CNI, validate SNAT/egress identity, check NetworkPolicy and CoreDNS before blaming cloud SG.",
            }));
        } else {
            steps.push(json!({
                "step": 4,
                "title": "Cross-CSP interconnect / pipe",
                "tools": ["multicloud.interconnect.awareness"],
                "hint": "If path crosses CSP boundaries, check DX / Cross-Cloud Interconnect / ExpressRoute with multicloud.interconnect.awareness.",
            }));
        }

        steps.push(json!({
            "step": 5,
            "title": "Authn vs authz vs network",
            "tools": ["access.troubleshoot", "system.identities.list"],
            "hint": "403/401 after connectivity OK → IAM/RBAC. Connection timeout/reset → network/path. Expired creds → re-auth, not path.",
        }));

        // Ambient inventory notes
        let mut inventory_notes = Vec::new();
        for p in ctx.profiles.list() {
            inventory_notes.push(format!(
                "profile `{}` cloud={} — ensure inventory sync before pattern search",
                p.id, p.cloud
            ));
        }
        if inventory_notes.is_empty() {
            inventory_notes.push(
                "No oscar profiles yet — ambient CLIs may still work; add profiles for multi-account scope."
                    .into(),
            );
        }

        let narrative = format!(
            "Multi-hop path playbook ({}): {} → {} :{} — {} steps",
            scenario,
            if source.is_empty() { "?" } else { source },
            if dest.is_empty() { "?" } else { dest },
            port,
            steps.len()
        );

        ToolResult::success(
            narrative,
            json!({
                "source": source,
                "destination": dest,
                "port": port,
                "scenario": scenario,
                "steps": steps,
                "inventory_notes": inventory_notes,
                "next": "Execute tools in step order via tools_search → tools_execute; or call multicloud.path.orchestrate for live inventory locate steps.",
            }),
        )
    }
}

// ─── Multi-hop live orchestration (bounded inventory locate) ───────────────

struct MulticloudPathOrchestrate;

/// Runs live inventory/DNS locate steps for source+destination (no long-running path jobs).
#[async_trait]
impl Tool for MulticloudPathOrchestrate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "multicloud.path.orchestrate".into(),
            name: "Cross-CSP multi-hop live locate".into(),
            description: "Bounded live orchestration: pattern-scan NetworkInventory + DnsInventory for source and destination, then attach a multi-hop narrative of recommended path-analyzer next steps. Does not start long-running Reachability/Connectivity jobs (those stay explicit tools).".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "multicloud".into(),
                "path".into(),
                "orchestrate".into(),
                "live".into(),
                "multi-hop".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "source": { "type": "string" },
                    "destination": { "type": "string" },
                    "port": { "type": "integer", "default": 443 },
                    "limit": { "type": "integer", "default": 8 }
                },
                "required": ["source", "destination"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let source = args
            .get("source")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if source.is_empty() || dest.is_empty() {
            return ToolResult::error("source and destination are required");
        }
        let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443);
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(8)
            .clamp(1, 25) as usize;

        let mut phases = Vec::new();
        let mut notes = Vec::new();

        for (label, pattern) in [("source", source), ("destination", dest)] {
            // Network locate
            let mut net_hits = Vec::new();
            if let Ok(q) = PatternQuery::from_args(&json!({
                "pattern": pattern,
                "limit": limit,
            })) {
                for p in ctx.profiles.list() {
                    if matches!(p.cloud, Cloud::Aws | Cloud::Gcp | Cloud::Azure | Cloud::K8s) {
                        let region = p.default_region.as_deref();
                        if let Some(inv) = load_network_cache(&ctx.config_dir, &p.id, region) {
                            let part = scan_network_inventory(&inv, &q);
                            for h in part.hits.into_iter().take(limit) {
                                net_hits.push(json!({
                                    "profile_id": p.id,
                                    "cloud": p.cloud.to_string(),
                                    "kind": h.kind.to_string(),
                                    "name": h.name,
                                    "id": h.id,
                                    "matched_field": h.matched_field,
                                    "matched_value": h.matched_value,
                                    "score": h.score,
                                }));
                            }
                            notes.extend(part.notes);
                        }
                    }
                }
                // ambient k8s network cache
                for key in ["k8s-default", "default"] {
                    if let Some(inv) = load_network_cache(&ctx.config_dir, key, Some("cluster")) {
                        let part = scan_network_inventory(&inv, &q);
                        for h in part.hits.into_iter().take(limit) {
                            net_hits.push(json!({
                                "profile_id": key,
                                "cloud": "k8s",
                                "kind": h.kind.to_string(),
                                "name": h.name,
                                "id": h.id,
                                "score": h.score,
                            }));
                        }
                    }
                }
            }

            // DNS locate
            let mut dns_hits = Vec::new();
            if let Ok(q) = PatternQuery::from_args(&json!({
                "pattern": pattern,
                "limit": limit,
            })) {
                for p in ctx.profiles.list() {
                    if matches!(p.cloud, Cloud::Aws | Cloud::Gcp | Cloud::Azure) {
                        if let Some(inv) = load_dns_cache(&ctx.config_dir, &p.id) {
                            let part = scan_dns_inventory(&inv, &q);
                            for h in part.hits.into_iter().take(limit) {
                                dns_hits.push(json!({
                                    "profile_id": p.id,
                                    "cloud": p.cloud.to_string(),
                                    "kind": h.kind.to_string(),
                                    "name": h.name,
                                    "id": h.id,
                                    "matched_value": h.matched_value,
                                    "score": h.score,
                                }));
                            }
                        }
                    }
                }
            }

            phases.push(json!({
                "endpoint": label,
                "pattern": pattern,
                "network_hits": net_hits,
                "dns_hits": dns_hits,
            }));
        }

        let next_tools = json!([
            {
                "when": "private DNS hop",
                "tools": ["dns.forwarding.map", "aws.dns.resolver.pattern.search", "azure.dns.private_resolver.pattern.search"]
            },
            {
                "when": "L4 path on AWS",
                "tools": ["aws.network.path.analyze", "aws.network.access.analyze"],
                "args_hint": { "source": source, "destination": dest, "destination_port": port }
            },
            {
                "when": "L4 path on GCP",
                "tools": ["gcp.network.connectivity.test"]
            },
            {
                "when": "L4 path on Azure",
                "tools": ["azure.network.path.troubleshoot", "azure.network.next_hop"]
            },
            {
                "when": "cluster egress",
                "tools": ["k8s.cni.detect", "k8s.networkpolicy.deny.narrative", "k8s.hubble.observe"]
            },
            {
                "when": "cross-CSP pipe",
                "tools": ["multicloud.interconnect.awareness"]
            }
        ]);

        ToolResult::success(
            format!(
                "orchestrated locate for {source} → {dest}:{port} ({} phases)",
                phases.len()
            ),
            json!({
                "source": source,
                "destination": dest,
                "port": port,
                "phases": phases,
                "notes": notes,
                "next_path_tools": next_tools,
                "narrative_tool": "multicloud.path.narrative",
                "limits": "Did not start long-running path analyzers; run next_path_tools explicitly.",
            }),
        )
    }
}

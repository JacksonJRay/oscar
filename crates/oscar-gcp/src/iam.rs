//! GCP IAM — service accounts, project policy bindings, permission tests.
//!
//! Live via `gcloud`. Mutations require readwrite mode.

use async_trait::async_trait;
use oscar_core::{
    AccessBinding, AccessCheckResult, AccessDecision, AccessEntity, AccessObjectKind, Capability,
    Cloud, ToolDomain,
};
use oscar_identity::Profile;
use oscar_tools::sync::{gcloud_project_args, run_json_command, which_ok};
use oscar_tools::{
    auth_for, resolve_profiles, Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn register_iam(registry: &mut ToolRegistry) {
    registry.register(Arc::new(GcpIamServiceAccountsList));
    registry.register(Arc::new(GcpIamServiceAccountCreate));
    registry.register(Arc::new(GcpIamServiceAccountDelete));
    registry.register(Arc::new(GcpIamPolicyGet));
    registry.register(Arc::new(GcpIamBindingAdd));
    registry.register(Arc::new(GcpIamBindingRemove));
    registry.register(Arc::new(GcpIamRolesList));
    registry.register(Arc::new(GcpIamTestPermissions));
    registry.register(Arc::new(GcpIamPatternSearch));
    registry.register(Arc::new(GcpIamAccessTest));
}

fn project_for(profile: &Profile, args: &Value) -> String {
    args.get("project")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if profile.account_ref.is_empty() || profile.account_ref == "ambient" {
                String::new()
            } else {
                profile.account_ref.clone()
            }
        })
}

fn profile_or_auth(
    ctx: &ToolContext,
    profile_id: Option<&str>,
) -> Result<Profile, ToolResult> {
    let profiles = ctx.profiles_for(Cloud::Gcp, profile_id);
    if let Some(p) = profiles.first() {
        return Ok((*p).clone());
    }
    // Ambient gcloud ADC
    Ok(Profile::new(Cloud::Gcp, "ambient", "ambient"))
}

async fn gcloud_json(args: &[&str]) -> Result<Value, ToolResult> {
    if !which_ok("gcloud").await {
        return Err(ToolResult::needs_auth(auth_for(
            Cloud::Gcp,
            "gcloud binary not found on PATH",
        )));
    }
    match run_json_command("gcloud", args).await {
        Ok(v) => Ok(v),
        Err(e) => {
            let text = e.to_string();
            if let Some(auth) = oscar_identity::auth_request_from_error(Cloud::Gcp, None, &text) {
                Err(ToolResult::needs_auth(auth))
            } else {
                Err(ToolResult::error(text))
            }
        }
    }
}

async fn gcloud_ok(args: &[&str]) -> Result<(), ToolResult> {
    if !which_ok("gcloud").await {
        return Err(ToolResult::needs_auth(auth_for(
            Cloud::Gcp,
            "gcloud binary not found on PATH",
        )));
    }
    let mut cmd = tokio::process::Command::new("gcloud");
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = cmd
        .output()
        .await
        .map_err(|e| ToolResult::error(format!("spawn gcloud: {e}")))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let text = err.trim().to_string();
        if let Some(auth) = oscar_identity::auth_request_from_error(Cloud::Gcp, None, &text) {
            return Err(ToolResult::needs_auth(auth));
        }
        return Err(ToolResult::error(text));
    }
    Ok(())
}

fn sa_entity(sa: &Value, profile_id: &str, project: &str) -> AccessEntity {
    AccessEntity {
        cloud: Cloud::Gcp,
        kind: AccessObjectKind::ServiceAccount,
        id: sa
            .get("email")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .into(),
        name: sa
            .get("displayName")
            .and_then(|v| v.as_str())
            .or_else(|| sa.get("email").and_then(|v| v.as_str()))
            .unwrap_or("")
            .into(),
        profile_id: Some(profile_id.into()),
        account_ref: Some(project.into()),
        path: sa
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        attached_policies: vec![],
        groups: vec![],
        tags: vec![],
        description: sa
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        raw: Some(sa.clone()),
    }
}

macro_rules! meta {
    ($id:expr, $name:expr, $desc:expr, $cap:expr, $tags:expr, $schema:expr) => {
        ToolMeta {
            id: $id.into(),
            name: $name.into(),
            description: $desc.into(),
            domain: ToolDomain::Access,
            clouds: vec![Cloud::Gcp],
            capability: $cap,
            tags: $tags.into_iter().map(|s: &str| s.to_string()).collect(),
            input_schema: $schema,
            output_schema: None,
        }
    };
}

struct GcpIamServiceAccountsList;
struct GcpIamServiceAccountCreate;
struct GcpIamServiceAccountDelete;
struct GcpIamPolicyGet;
struct GcpIamBindingAdd;
struct GcpIamBindingRemove;
struct GcpIamRolesList;
struct GcpIamTestPermissions;
struct GcpIamPatternSearch;
struct GcpIamAccessTest;

#[async_trait]
impl Tool for GcpIamServiceAccountsList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.service_accounts.list",
                "List GCP service accounts",
                "List service accounts in a project (gcloud iam service-accounts list).",
                Capability::Read,
                ["iam", "service-account", "list", "user", "identity", "gcp"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let project = project_for(&profile, &args);
        let mut cli = vec![
            "iam".into(),
            "service-accounts".into(),
            "list".into(),
            "--format=json".into(),
        ];
        if !project.is_empty() {
            cli.push(format!("--project={project}"));
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match gcloud_json(&refs).await {
            Ok(v) => {
                let arr = if v.is_array() {
                    v.as_array().cloned().unwrap_or_default()
                } else {
                    vec![]
                };
                let entities: Vec<AccessEntity> = arr
                    .iter()
                    .map(|sa| sa_entity(sa, &profile.id, &project))
                    .collect();
                ToolResult::success(
                    format!("{} service account(s)", entities.len()),
                    json!({ "cloud": "gcp", "kind": "service_account", "project": project, "entities": entities }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamServiceAccountCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.service_account.create",
                "Create GCP service account",
                "Create a service account (readwrite). Does not create keys (keys would leak secrets to the agent).",
                Capability::Write,
                ["iam", "service-account", "create", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "account_id": { "type": "string", "description": "SA id (local part before @)" },
                        "display_name": { "type": "string" },
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["account_id"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let account_id = match args.get("account_id").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing account_id"),
        };
        let project = project_for(&profile, &args);
        let mut cli = vec![
            "iam".into(),
            "service-accounts".into(),
            "create".into(),
            account_id.into(),
            "--format=json".into(),
        ];
        if let Some(d) = args.get("display_name").and_then(|v| v.as_str()) {
            cli.push(format!("--display-name={d}"));
        }
        if !project.is_empty() {
            cli.push(format!("--project={project}"));
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match gcloud_json(&refs).await {
            Ok(v) => ToolResult::success(
                format!("created service account `{account_id}`"),
                json!({ "mutation": "create", "kind": "service_account", "service_account": v }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamServiceAccountDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.service_account.delete",
                "Delete GCP service account",
                "Delete service account by email.",
                Capability::Write,
                ["iam", "service-account", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "email": { "type": "string" },
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["email"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let email = match args.get("email").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing email"),
        };
        let project = project_for(&profile, &args);
        let mut cli = vec![
            "iam".into(),
            "service-accounts".into(),
            "delete".into(),
            email.into(),
            "--quiet".into(),
        ];
        if !project.is_empty() {
            cli.push(format!("--project={project}"));
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match gcloud_ok(&refs).await {
            Ok(()) => ToolResult::success(
                format!("deleted service account `{email}`"),
                json!({ "mutation": "delete", "kind": "service_account", "email": email }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamPolicyGet {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.policy.get",
                "Get project IAM policy",
                "Fetch project IAM policy bindings (roles → members). Primary read for who has what.",
                Capability::Read,
                ["iam", "policy", "binding", "role", "permission", "get"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let project = project_for(&profile, &args);
        if project.is_empty() {
            return ToolResult::error(
                "project required (args.project or oscar profile account_ref / gcloud config)",
            );
        }
        match gcloud_json(&[
            "projects",
            "get-iam-policy",
            &project,
            "--format=json",
        ])
        .await
        {
            Ok(v) => {
                let mut bindings = Vec::new();
                if let Some(arr) = v.get("bindings").and_then(|b| b.as_array()) {
                    for b in arr {
                        let role = b
                            .get("role")
                            .and_then(|r| r.as_str())
                            .unwrap_or("")
                            .to_string();
                        if let Some(members) = b.get("members").and_then(|m| m.as_array()) {
                            for m in members {
                                if let Some(mem) = m.as_str() {
                                    bindings.push(AccessBinding {
                                        cloud: Cloud::Gcp,
                                        principal_id: mem.into(),
                                        principal_type: mem.split(':').next().map(|s| s.into()),
                                        role_or_policy: role.clone(),
                                        scope: Some(format!("projects/{project}")),
                                        binding_id: None,
                                        condition: None,
                                    });
                                }
                            }
                        }
                    }
                }
                ToolResult::success(
                    format!(
                        "project `{project}` IAM: {} binding(s)",
                        bindings.len()
                    ),
                    json!({
                        "cloud": "gcp",
                        "project": project,
                        "bindings": bindings,
                        "policy": v,
                    }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamBindingAdd {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.binding.add",
                "Add IAM policy binding",
                "Add member to a role on a project (gcloud projects add-iam-policy-binding).",
                Capability::Write,
                ["iam", "binding", "add", "role", "permission", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "role": { "type": "string", "description": "e.g. roles/viewer" },
                        "member": {
                            "type": "string",
                            "description": "e.g. user:a@b.com, serviceAccount:…, group:…"
                        },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role", "member"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let project = project_for(&profile, &args);
        if project.is_empty() {
            return ToolResult::error("project required");
        }
        let role = match args.get("role").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing role"),
        };
        let member = match args.get("member").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing member"),
        };
        match gcloud_json(&[
            "projects",
            "add-iam-policy-binding",
            &project,
            "--role",
            role,
            "--member",
            member,
            "--format=json",
        ])
        .await
        {
            Ok(v) => ToolResult::success(
                format!("added {member} → {role} on {project}"),
                json!({ "mutation": "bind", "project": project, "role": role, "member": member, "policy": v }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamBindingRemove {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.binding.remove",
                "Remove IAM policy binding",
                "Remove member from a role on a project.",
                Capability::Write,
                ["iam", "binding", "remove", "role", "permission", "write", "manage", "delete"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "role": { "type": "string" },
                        "member": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role", "member"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let project = project_for(&profile, &args);
        if project.is_empty() {
            return ToolResult::error("project required");
        }
        let role = match args.get("role").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing role"),
        };
        let member = match args.get("member").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing member"),
        };
        match gcloud_json(&[
            "projects",
            "remove-iam-policy-binding",
            &project,
            "--role",
            role,
            "--member",
            member,
            "--format=json",
            "--quiet",
        ])
        .await
        {
            Ok(v) => ToolResult::success(
                format!("removed {member} from {role} on {project}"),
                json!({ "mutation": "unbind", "project": project, "role": role, "member": member, "policy": v }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamRolesList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.roles.list",
                "List GCP IAM roles",
                "List predefined or project custom roles (filter with pattern).",
                Capability::Read,
                ["iam", "role", "list", "roles", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "filter": { "type": "string", "description": "name fragment" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 50 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let filter = args
            .get("filter")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        // Predefined roles list is huge; use list with filter when provided
        match gcloud_json(&["iam", "roles", "list", "--format=json"]).await {
            Ok(v) => {
                let mut entities = Vec::new();
                if let Some(arr) = v.as_array() {
                    for r in arr {
                        let name = r
                            .get("name")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        let title = r
                            .get("title")
                            .and_then(|n| n.as_str())
                            .unwrap_or("")
                            .to_string();
                        if !filter.is_empty()
                            && !name.to_ascii_lowercase().contains(&filter)
                            && !title.to_ascii_lowercase().contains(&filter)
                        {
                            continue;
                        }
                        entities.push(AccessEntity {
                            cloud: Cloud::Gcp,
                            kind: AccessObjectKind::Role,
                            id: name.clone(),
                            name: if title.is_empty() { name } else { title },
                            profile_id: None,
                            account_ref: None,
                            path: r.get("name").and_then(|n| n.as_str()).map(|s| s.into()),
                            attached_policies: vec![],
                            groups: vec![],
                            tags: vec![],
                            description: r
                                .get("description")
                                .and_then(|d| d.as_str())
                                .map(|s| s.into()),
                            raw: Some(r.clone()),
                        });
                        if entities.len() >= limit {
                            break;
                        }
                    }
                }
                ToolResult::success(
                    format!("{} role(s)", entities.len()),
                    json!({ "cloud": "gcp", "kind": "role", "entities": entities }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamTestPermissions {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.test_permissions",
                "Test IAM permissions on project",
                "Call projects testIamPermissions for the current credentials (what can I do?).",
                Capability::Read,
                ["iam", "test", "permission", "troubleshoot", "access"],
                json!({
                    "type": "object",
                    "properties": {
                        "project": { "type": "string" },
                        "permissions": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "e.g. resourcemanager.projects.get, compute.instances.list"
                        },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["permissions"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let project = project_for(&profile, &args);
        if project.is_empty() {
            // try config
            let _ = gcloud_project_args(&profile);
            return ToolResult::error("project required for test_permissions");
        }
        let perms: Vec<String> = args
            .get("permissions")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if perms.is_empty() {
            return ToolResult::error("permissions array required");
        }
        // gcloud projects get-iam-policy doesn't test; use REST via gcloud:
        // gcloud projects get-iam-policy is not the same. Use:
        // gcloud alpha/beta or curl. Standard approach:
        // gcloud projects test-iam-permissions PROJECT --permissions=...
        let joined = perms.join(",");
        match gcloud_json(&[
            "projects",
            "test-iam-permissions",
            &project,
            &format!("--permissions={joined}"),
            "--format=json",
        ])
        .await
        {
            Ok(v) => {
                let granted: Vec<String> = v
                    .get("permissions")
                    .and_then(|p| p.as_array())
                    .map(|a| {
                        a.iter()
                            .filter_map(|x| x.as_str().map(|s| s.to_string()))
                            .collect()
                    })
                    .unwrap_or_default();
                let missing: Vec<String> = perms
                    .iter()
                    .filter(|p| !granted.iter().any(|g| g == *p))
                    .cloned()
                    .collect();
                let checks: Vec<AccessCheckResult> = perms
                    .iter()
                    .map(|p| AccessCheckResult {
                        cloud: Cloud::Gcp,
                        principal: "current_credentials".into(),
                        action: p.clone(),
                        resource: Some(format!("projects/{project}")),
                        decision: if granted.iter().any(|g| g == p) {
                            AccessDecision::Allowed
                        } else {
                            AccessDecision::Denied
                        },
                        matched_statements: vec![],
                        missing_permissions: if granted.iter().any(|g| g == p) {
                            vec![]
                        } else {
                            vec![p.clone()]
                        },
                        notes: vec![],
                        raw: None,
                    })
                    .collect();
                ToolResult::success(
                    format!(
                        "test permissions on {project}: {} granted, {} missing",
                        granted.len(),
                        missing.len()
                    ),
                    json!({
                        "cloud": "gcp",
                        "project": project,
                        "granted": granted,
                        "missing": missing,
                        "checks": checks,
                    }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for GcpIamPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.pattern.search",
                "Search service accounts and IAM members by pattern",
                "Partial-match search for SA emails and project IAM binding members (substring contains). Prefer name fragments over full emails.",
                Capability::Read,
                ["iam", "pattern", "search", "service-account", "binding", "discover", "partial"],
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Name fragment (partial contains)" },
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 50 }
                    },
                    "required": ["pattern"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let pattern = args
            .get("pattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_ascii_lowercase();
        let sa = GcpIamServiceAccountsList.execute(args.clone(), ctx).await;
        let pol = GcpIamPolicyGet.execute(args.clone(), ctx).await;
        let mut entities = Vec::new();
        let mut bindings = Vec::new();
        if sa.ok {
            if let Some(arr) = sa.data.get("entities").and_then(|e| e.as_array()) {
                for e in arr {
                    let name = e
                        .get("name")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let id = e
                        .get("id")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if name.contains(&pattern) || id.contains(&pattern) {
                        if let Ok(ent) = serde_json::from_value::<AccessEntity>(e.clone()) {
                            entities.push(ent);
                        }
                    }
                }
            }
        }
        if pol.ok {
            if let Some(arr) = pol.data.get("bindings").and_then(|e| e.as_array()) {
                for b in arr {
                    let principal = b
                        .get("principal_id")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    let role = b
                        .get("role_or_policy")
                        .and_then(|n| n.as_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    if principal.contains(&pattern) || role.contains(&pattern) {
                        if let Ok(bind) = serde_json::from_value::<AccessBinding>(b.clone()) {
                            bindings.push(bind);
                        }
                    }
                }
            }
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        entities.truncate(limit);
        bindings.truncate(limit);
        ToolResult::success(
            format!(
                "gcp IAM pattern `{}`: {} entities, {} bindings",
                pattern,
                entities.len(),
                bindings.len()
            ),
            json!({ "cloud": "gcp", "pattern": pattern, "entities": entities, "bindings": bindings }),
        )
    }
}

#[async_trait]
impl Tool for GcpIamAccessTest {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "gcp.iam.access.test",
                "Test single GCP permission",
                "Test whether current credentials have one permission on a project.",
                Capability::Read,
                ["iam", "test", "permission", "access", "troubleshoot", "can-i"],
                json!({
                    "type": "object",
                    "properties": {
                        "permission": { "type": "string" },
                        "project": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["permission"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let perm = match args.get("permission").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing permission"),
        };
        let mut a = args.clone();
        if let Some(obj) = a.as_object_mut() {
            obj.insert("permissions".into(), json!([perm]));
        }
        GcpIamTestPermissions.execute(a, ctx).await
    }
}

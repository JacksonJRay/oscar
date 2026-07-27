//! Azure RBAC + Entra — role assignments, definitions, users, access checks.
//!
//! Live via `az`. Mutations require readwrite mode.

use async_trait::async_trait;
use oscar_core::{
    AccessBinding, AccessCheckResult, AccessDecision, AccessEntity, AccessObjectKind, Capability,
    Cloud, ToolDomain,
};
use oscar_identity::Profile;
use oscar_tools::sync::{run_json_command, which_ok};
use oscar_tools::{
    auth_for, resolve_profiles, Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult,
};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn register_iam(registry: &mut ToolRegistry) {
    registry.register(Arc::new(AzureIamRoleAssignmentsList));
    registry.register(Arc::new(AzureIamRoleAssignmentCreate));
    registry.register(Arc::new(AzureIamRoleAssignmentDelete));
    registry.register(Arc::new(AzureIamRoleDefinitionsList));
    registry.register(Arc::new(AzureIamUsersList));
    registry.register(Arc::new(AzureIamPrincipalsSearch));
    registry.register(Arc::new(AzureIamCheckAccess));
    registry.register(Arc::new(AzureIamPatternSearch));
    registry.register(Arc::new(AzureIamAccessTest));
}

fn profile_or_auth(
    ctx: &ToolContext,
    profile_id: Option<&str>,
) -> Result<Profile, ToolResult> {
    let profiles = ctx.profiles_for(Cloud::Azure, profile_id);
    if let Some(p) = profiles.first() {
        return Ok((*p).clone());
    }
    Ok(Profile::new(Cloud::Azure, "ambient", "ambient"))
}

async fn az_json(args: &[&str]) -> Result<Value, ToolResult> {
    if !which_ok("az").await {
        return Err(ToolResult::needs_auth(auth_for(
            Cloud::Azure,
            "az binary not found on PATH",
        )));
    }
    match run_json_command("az", args).await {
        Ok(v) => Ok(v),
        Err(e) => {
            let text = e.to_string();
            if let Some(auth) = oscar_identity::auth_request_from_error(Cloud::Azure, None, &text) {
                Err(ToolResult::needs_auth(auth))
            } else {
                Err(ToolResult::error(text))
            }
        }
    }
}

async fn az_ok(args: &[&str]) -> Result<String, ToolResult> {
    if !which_ok("az").await {
        return Err(ToolResult::needs_auth(auth_for(
            Cloud::Azure,
            "az binary not found on PATH",
        )));
    }
    let mut cmd = tokio::process::Command::new("az");
    cmd.args(args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped());
    let out = cmd
        .output()
        .await
        .map_err(|e| ToolResult::error(format!("spawn az: {e}")))?;
    let stdout = String::from_utf8_lossy(&out.stdout).to_string();
    let stderr = String::from_utf8_lossy(&out.stderr).to_string();
    if !out.status.success() {
        let text = format!("{} {}", stderr.trim(), stdout.trim());
        if let Some(auth) = oscar_identity::auth_request_from_error(Cloud::Azure, None, &text) {
            return Err(ToolResult::needs_auth(auth));
        }
        return Err(ToolResult::error(text));
    }
    Ok(stdout)
}

macro_rules! meta {
    ($id:expr, $name:expr, $desc:expr, $cap:expr, $tags:expr, $schema:expr) => {
        ToolMeta {
            id: $id.into(),
            name: $name.into(),
            description: $desc.into(),
            domain: ToolDomain::Access,
            clouds: vec![Cloud::Azure],
            capability: $cap,
            tags: $tags.into_iter().map(|s: &str| s.to_string()).collect(),
            input_schema: $schema,
            output_schema: None,
        }
    };
}

struct AzureIamRoleAssignmentsList;
struct AzureIamRoleAssignmentCreate;
struct AzureIamRoleAssignmentDelete;
struct AzureIamRoleDefinitionsList;
struct AzureIamUsersList;
struct AzureIamPrincipalsSearch;
struct AzureIamCheckAccess;
struct AzureIamPatternSearch;
struct AzureIamAccessTest;

#[async_trait]
impl Tool for AzureIamRoleAssignmentsList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.role_assignments.list",
                "List Azure RBAC role assignments",
                "List role assignments at subscription or resource group scope.",
                Capability::Read,
                ["iam", "rbac", "role", "assignment", "list", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "scope": { "type": "string", "description": "ARM scope; default subscription" },
                        "assignee": { "type": "string", "description": "Filter by principal object id or UPN" },
                        "role": { "type": "string" },
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _p = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli: Vec<String> = vec![
            "role".into(),
            "assignment".into(),
            "list".into(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(s) = args.get("scope").and_then(|v| v.as_str()) {
            cli.push("--scope".into());
            cli.push(s.into());
        }
        if let Some(a) = args.get("assignee").and_then(|v| v.as_str()) {
            cli.push("--assignee".into());
            cli.push(a.into());
        }
        if let Some(r) = args.get("role").and_then(|v| v.as_str()) {
            cli.push("--role".into());
            cli.push(r.into());
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match az_json(&refs).await {
            Ok(v) => {
                let mut bindings = Vec::new();
                if let Some(arr) = v.as_array() {
                    for a in arr {
                        bindings.push(AccessBinding {
                            cloud: Cloud::Azure,
                            principal_id: a
                                .get("principalId")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .into(),
                            principal_type: a
                                .get("principalType")
                                .and_then(|x| x.as_str())
                                .map(|s| s.into()),
                            role_or_policy: a
                                .get("roleDefinitionName")
                                .and_then(|x| x.as_str())
                                .or_else(|| a.get("roleDefinitionId").and_then(|x| x.as_str()))
                                .unwrap_or("")
                                .into(),
                            scope: a.get("scope").and_then(|x| x.as_str()).map(|s| s.into()),
                            binding_id: a.get("id").and_then(|x| x.as_str()).map(|s| s.into()),
                            condition: None,
                        });
                    }
                }
                ToolResult::success(
                    format!("{} role assignment(s)", bindings.len()),
                    json!({ "cloud": "azure", "kind": "role_assignment", "bindings": bindings, "raw_count": bindings.len() }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AzureIamRoleAssignmentCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.role_assignment.create",
                "Create Azure RBAC role assignment",
                "Assign a role to a principal at a scope (readwrite).",
                Capability::Write,
                ["iam", "rbac", "role", "assignment", "create", "write", "manage", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "assignee": { "type": "string", "description": "Object id, UPN, or app id" },
                        "role": { "type": "string", "description": "Role name or id e.g. Reader" },
                        "scope": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["assignee", "role"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _p = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let assignee = match args.get("assignee").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing assignee"),
        };
        let role = match args.get("role").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing role"),
        };
        let mut cli: Vec<String> = vec![
            "role".into(),
            "assignment".into(),
            "create".into(),
            "--assignee".into(),
            assignee.into(),
            "--role".into(),
            role.into(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(s) = args.get("scope").and_then(|v| v.as_str()) {
            cli.push("--scope".into());
            cli.push(s.into());
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match az_json(&refs).await {
            Ok(v) => ToolResult::success(
                format!("created role assignment {role} → {assignee}"),
                json!({ "mutation": "create", "kind": "role_assignment", "assignment": v }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AzureIamRoleAssignmentDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.role_assignment.delete",
                "Delete Azure RBAC role assignment",
                "Remove role assignment by id, or by assignee+role+scope.",
                Capability::Write,
                ["iam", "rbac", "role", "assignment", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "ids": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Role assignment resource ids"
                        },
                        "assignee": { "type": "string" },
                        "role": { "type": "string" },
                        "scope": { "type": "string" },
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _p = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        if let Some(ids) = args.get("ids").and_then(|v| v.as_array()) {
            let id_list: Vec<&str> = ids.iter().filter_map(|x| x.as_str()).collect();
            if id_list.is_empty() {
                return ToolResult::error("ids empty");
            }
            let mut cli: Vec<String> = vec![
                "role".into(),
                "assignment".into(),
                "delete".into(),
                "--ids".into(),
            ];
            for id in &id_list {
                cli.push((*id).into());
            }
            cli.push("--yes".into());
            let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
            return match az_ok(&refs).await {
                Ok(_) => ToolResult::success(
                    format!("deleted {} assignment(s)", id_list.len()),
                    json!({ "mutation": "delete", "ids": id_list }),
                ),
                Err(e) => e,
            };
        }
        let assignee = match args.get("assignee").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => {
                return ToolResult::error("provide ids[] or assignee+role");
            }
        };
        let role = match args.get("role").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing role"),
        };
        let mut cli: Vec<String> = vec![
            "role".into(),
            "assignment".into(),
            "delete".into(),
            "--assignee".into(),
            assignee.into(),
            "--role".into(),
            role.into(),
            "--yes".into(),
        ];
        if let Some(s) = args.get("scope").and_then(|v| v.as_str()) {
            cli.push("--scope".into());
            cli.push(s.into());
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match az_ok(&refs).await {
            Ok(_) => ToolResult::success(
                format!("deleted assignment {role} for {assignee}"),
                json!({ "mutation": "delete", "assignee": assignee, "role": role }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AzureIamRoleDefinitionsList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.role_definitions.list",
                "List Azure role definitions",
                "List built-in/custom RBAC roles; optional name filter.",
                Capability::Read,
                ["iam", "rbac", "role", "definition", "list", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "name": { "type": "string", "description": "Filter by role name" },
                        "scope": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 50 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _p = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli: Vec<String> = vec![
            "role".into(),
            "definition".into(),
            "list".into(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(n) = args.get("name").and_then(|v| v.as_str()) {
            cli.push("--name".into());
            cli.push(n.into());
        }
        if let Some(s) = args.get("scope").and_then(|v| v.as_str()) {
            cli.push("--scope".into());
            cli.push(s.into());
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match az_json(&refs).await {
            Ok(v) => {
                let mut entities = Vec::new();
                if let Some(arr) = v.as_array() {
                    for r in arr.iter().take(limit) {
                        let name = r
                            .get("roleName")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .to_string();
                        entities.push(AccessEntity {
                            cloud: Cloud::Azure,
                            kind: AccessObjectKind::Role,
                            id: r
                                .get("id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .into(),
                            name,
                            profile_id: None,
                            account_ref: None,
                            path: None,
                            attached_policies: vec![],
                            groups: vec![],
                            tags: vec![],
                            description: r
                                .get("description")
                                .and_then(|x| x.as_str())
                                .map(|s| s.into()),
                            raw: Some(r.clone()),
                        });
                    }
                }
                ToolResult::success(
                    format!("{} role definition(s)", entities.len()),
                    json!({ "cloud": "azure", "kind": "role", "entities": entities }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AzureIamUsersList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.users.list",
                "List Entra ID users",
                "List Microsoft Entra (Azure AD) users via az ad user list.",
                Capability::Read,
                ["iam", "user", "entra", "aad", "list", "identity"],
                json!({
                    "type": "object",
                    "properties": {
                        "filter": { "type": "string", "description": "OData filter e.g. startswith(displayName,'A')" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 50 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let _p = match profile_or_auth(ctx, args.get("profile_id").and_then(|v| v.as_str())) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli: Vec<String> = vec![
            "ad".into(),
            "user".into(),
            "list".into(),
            "--output".into(),
            "json".into(),
        ];
        if let Some(f) = args.get("filter").and_then(|v| v.as_str()) {
            cli.push("--filter".into());
            cli.push(f.into());
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match az_json(&refs).await {
            Ok(v) => {
                let mut entities = Vec::new();
                if let Some(arr) = v.as_array() {
                    for u in arr.iter().take(limit) {
                        entities.push(AccessEntity {
                            cloud: Cloud::Azure,
                            kind: AccessObjectKind::User,
                            id: u
                                .get("id")
                                .and_then(|x| x.as_str())
                                .unwrap_or("")
                                .into(),
                            name: u
                                .get("userPrincipalName")
                                .and_then(|x| x.as_str())
                                .or_else(|| u.get("displayName").and_then(|x| x.as_str()))
                                .unwrap_or("")
                                .into(),
                            profile_id: None,
                            account_ref: None,
                            path: None,
                            attached_policies: vec![],
                            groups: vec![],
                            tags: vec![],
                            description: u
                                .get("displayName")
                                .and_then(|x| x.as_str())
                                .map(|s| s.into()),
                            raw: Some(u.clone()),
                        });
                    }
                }
                ToolResult::success(
                    format!("{} Entra user(s)", entities.len()),
                    json!({ "cloud": "azure", "kind": "user", "entities": entities }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AzureIamPrincipalsSearch {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.principals.search",
                "Search Entra principals (users/SPs)",
                "Search users and service principals by display name fragment.",
                Capability::Read,
                ["iam", "user", "service-principal", "search", "pattern", "entra"],
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 30 }
                    },
                    "required": ["pattern"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let pattern = match args.get("pattern").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing pattern"),
        };
        // Escape single quotes for OData
        let safe = pattern.replace('\'', "''");
        let filter = format!("startswith(displayName,'{safe}')");
        let mut user_args = args.clone();
        if let Some(obj) = user_args.as_object_mut() {
            obj.insert("filter".into(), json!(filter));
        }
        let users = AzureIamUsersList.execute(user_args, ctx).await;
        // SP search
        let sp = az_json(&[
            "ad",
            "sp",
            "list",
            "--display-name",
            pattern,
            "--output",
            "json",
        ])
        .await;
        let mut entities = Vec::new();
        if users.ok {
            if let Some(arr) = users.data.get("entities").and_then(|e| e.as_array()) {
                for e in arr {
                    if let Ok(ent) = serde_json::from_value::<AccessEntity>(e.clone()) {
                        entities.push(ent);
                    }
                }
            }
        }
        if let Ok(v) = sp {
            if let Some(arr) = v.as_array() {
                for s in arr {
                    entities.push(AccessEntity {
                        cloud: Cloud::Azure,
                        kind: AccessObjectKind::ServicePrincipal,
                        id: s
                            .get("id")
                            .and_then(|x| x.as_str())
                            .or_else(|| s.get("appId").and_then(|x| x.as_str()))
                            .unwrap_or("")
                            .into(),
                        name: s
                            .get("displayName")
                            .and_then(|x| x.as_str())
                            .unwrap_or("")
                            .into(),
                        profile_id: None,
                        account_ref: None,
                        path: None,
                        attached_policies: vec![],
                        groups: vec![],
                        tags: vec![],
                        description: None,
                        raw: Some(s.clone()),
                    });
                }
            }
        }
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(30) as usize;
        entities.truncate(limit);
        ToolResult::success(
            format!("{} principal(s) matching `{pattern}`", entities.len()),
            json!({ "cloud": "azure", "pattern": pattern, "entities": entities }),
        )
    }
}

#[async_trait]
impl Tool for AzureIamCheckAccess {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.check_access",
                "Check Azure resource access (permissions)",
                "Use az role assignment list + optional resource permission check. For full dataActions use role assignment list for the assignee.",
                Capability::Read,
                ["iam", "check", "access", "permission", "troubleshoot", "test", "rbac"],
                json!({
                    "type": "object",
                    "properties": {
                        "assignee": { "type": "string", "description": "Object id or UPN; omit for current user" },
                        "scope": { "type": "string" },
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        // Current account
        let account = az_json(&["account", "show", "--output", "json"]).await;
        let mut list_args = args.clone();
        if args.get("assignee").and_then(|v| v.as_str()).is_none() {
            if let Ok(ref acc) = account {
                if let Some(oid) = acc.pointer("/user/name").and_then(|v| v.as_str()) {
                    if let Some(obj) = list_args.as_object_mut() {
                        obj.insert("assignee".into(), json!(oid));
                    }
                }
            }
        }
        let listed = AzureIamRoleAssignmentsList
            .execute(list_args, ctx)
            .await;
        if !listed.ok {
            return listed;
        }
        let bindings = listed
            .data
            .get("bindings")
            .cloned()
            .unwrap_or(json!([]));
        let count = bindings.as_array().map(|a| a.len()).unwrap_or(0);
        ToolResult::success(
            format!("assignee has {count} role assignment(s) in scope"),
            json!({
                "cloud": "azure",
                "account": account.ok(),
                "bindings": bindings,
                "guidance": [
                    "If empty: no RBAC roles at this scope (subscription/RG)",
                    "Use azure.iam.role_assignment.create to grant (readwrite)",
                    "Use azure.iam.role_definitions.list to find role names",
                ]
            }),
        )
    }
}

#[async_trait]
impl Tool for AzureIamPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.pattern.search",
                "Search Azure IAM users/roles/assignments",
                "Combined search across principals and role assignment names.",
                Capability::Read,
                ["iam", "pattern", "search", "rbac", "user", "role", "discover"],
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string" },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 40 }
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
        let principals = AzureIamPrincipalsSearch.execute(args.clone(), ctx).await;
        let roles = AzureIamRoleDefinitionsList
            .execute(
                json!({
                    "name": args.get("pattern").and_then(|v| v.as_str()).unwrap_or(""),
                    "limit": args.get("limit").unwrap_or(&json!(40)),
                }),
                ctx,
            )
            .await;
        let assignments = AzureIamRoleAssignmentsList
            .execute(json!({}), ctx)
            .await;
        let mut entities = Vec::new();
        let mut bindings = Vec::new();
        if principals.ok {
            if let Some(arr) = principals.data.get("entities").and_then(|e| e.as_array()) {
                for e in arr {
                    if let Ok(ent) = serde_json::from_value::<AccessEntity>(e.clone()) {
                        entities.push(ent);
                    }
                }
            }
        }
        if roles.ok {
            if let Some(arr) = roles.data.get("entities").and_then(|e| e.as_array()) {
                for e in arr {
                    if let Ok(ent) = serde_json::from_value::<AccessEntity>(e.clone()) {
                        entities.push(ent);
                    }
                }
            }
        }
        if assignments.ok {
            if let Some(arr) = assignments.data.get("bindings").and_then(|e| e.as_array()) {
                for b in arr {
                    let hay = format!(
                        "{} {} {}",
                        b.get("principal_id").and_then(|x| x.as_str()).unwrap_or(""),
                        b.get("role_or_policy")
                            .and_then(|x| x.as_str())
                            .unwrap_or(""),
                        b.get("scope").and_then(|x| x.as_str()).unwrap_or("")
                    )
                    .to_ascii_lowercase();
                    if hay.contains(&pattern) {
                        if let Ok(bind) = serde_json::from_value::<AccessBinding>(b.clone()) {
                            bindings.push(bind);
                        }
                    }
                }
            }
        }
        ToolResult::success(
            format!(
                "azure IAM pattern: {} entities, {} bindings",
                entities.len(),
                bindings.len()
            ),
            json!({ "cloud": "azure", "pattern": pattern, "entities": entities, "bindings": bindings }),
        )
    }
}

#[async_trait]
impl Tool for AzureIamAccessTest {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "azure.iam.access.test",
                "Test whether assignee has a named role at scope",
                "Heuristic test: list role assignments for assignee and check for role name match.",
                Capability::Read,
                ["iam", "test", "permission", "access", "troubleshoot", "can-i", "rbac"],
                json!({
                    "type": "object",
                    "properties": {
                        "assignee": { "type": "string" },
                        "role": { "type": "string", "description": "Role name e.g. Contributor" },
                        "scope": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let role = match args.get("role").and_then(|v| v.as_str()) {
            Some(s) => s,
            None => return ToolResult::error("missing role"),
        };
        let listed = AzureIamRoleAssignmentsList.execute(args.clone(), ctx).await;
        if !listed.ok {
            return listed;
        }
        let role_l = role.to_ascii_lowercase();
        let mut matched = Vec::new();
        if let Some(arr) = listed.data.get("bindings").and_then(|b| b.as_array()) {
            for b in arr {
                let rn = b
                    .get("role_or_policy")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_ascii_lowercase();
                if rn.contains(&role_l) {
                    matched.push(b.clone());
                }
            }
        }
        let decision = if matched.is_empty() {
            AccessDecision::Denied
        } else {
            AccessDecision::Allowed
        };
        let check = AccessCheckResult {
            cloud: Cloud::Azure,
            principal: args
                .get("assignee")
                .and_then(|v| v.as_str())
                .unwrap_or("current")
                .into(),
            action: format!("role:{role}"),
            resource: args
                .get("scope")
                .and_then(|v| v.as_str())
                .map(|s| s.into()),
            decision,
            matched_statements: matched
                .iter()
                .filter_map(|m| m.get("binding_id").and_then(|x| x.as_str()).map(|s| s.into()))
                .collect(),
            missing_permissions: if matched.is_empty() {
                vec![role.into()]
            } else {
                vec![]
            },
            notes: vec![
                "Azure access.test matches role assignment names; for fine-grained dataActions use portal/ARM checkAccess API.".into(),
            ],
            raw: Some(json!({ "matched_assignments": matched })),
        };
        ToolResult::success(
            check.summary_line(),
            json!({ "checks": [check], "matched_count": matched.len() }),
        )
    }
}

//! AWS IAM — manage, troubleshoot, and test users / roles / groups / policies.
//!
//! Live via `aws iam` + `aws sts`. Mutations require session `readwrite` mode.
//! Secrets (access keys) are never returned to the model transcript.

use crate::aws_runtime::{arg_str, aws_cli, aws_json, require_str, resolve_aws_profile_ctx};
use async_trait::async_trait;
use oscar_core::{
    AccessCheckResult, AccessDecision, AccessEntity, AccessObjectKind, Capability, Cloud,
    ToolDomain,
};
use oscar_tools::{Tool, ToolContext, ToolMeta, ToolRegistry, ToolResult};
use serde_json::{json, Value};
use std::sync::Arc;

pub fn register_iam(registry: &mut ToolRegistry) {
    // Read / inventory
    registry.register(Arc::new(AwsIamCallerIdentity));
    registry.register(Arc::new(AwsIamUsersList));
    registry.register(Arc::new(AwsIamUserGet));
    registry.register(Arc::new(AwsIamRolesList));
    registry.register(Arc::new(AwsIamRoleGet));
    registry.register(Arc::new(AwsIamGroupsList));
    registry.register(Arc::new(AwsIamGroupGet));
    registry.register(Arc::new(AwsIamPoliciesList));
    registry.register(Arc::new(AwsIamPolicyGet));
    registry.register(Arc::new(AwsIamPatternSearch));
    // Troubleshoot / test
    registry.register(Arc::new(AwsIamSimulate));
    registry.register(Arc::new(AwsIamAccessTest));
    // Mutations (write mode)
    registry.register(Arc::new(AwsIamUserCreate));
    registry.register(Arc::new(AwsIamUserDelete));
    registry.register(Arc::new(AwsIamRoleCreate));
    registry.register(Arc::new(AwsIamRoleDelete));
    registry.register(Arc::new(AwsIamGroupCreate));
    registry.register(Arc::new(AwsIamGroupDelete));
    registry.register(Arc::new(AwsIamPolicyCreate));
    registry.register(Arc::new(AwsIamPolicyDelete));
    registry.register(Arc::new(AwsIamPolicyAttach));
    registry.register(Arc::new(AwsIamPolicyDetach));
    registry.register(Arc::new(AwsIamGroupAddUser));
    registry.register(Arc::new(AwsIamGroupRemoveUser));
    registry.register(Arc::new(AwsIamInlinePolicyPut));
    registry.register(Arc::new(AwsIamInlinePolicyDelete));
}

// ── helpers ──────────────────────────────────────────────────────────

fn profile_id_arg(args: &Value) -> Option<&str> {
    arg_str(args, "profile_id")
}

fn entity_from_user(u: &Value, profile_id: &str) -> AccessEntity {
    AccessEntity {
        cloud: Cloud::Aws,
        kind: AccessObjectKind::User,
        id: u
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: u
            .get("UserName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        profile_id: Some(profile_id.into()),
        account_ref: None,
        path: u.get("Path").and_then(|v| v.as_str()).map(|s| s.into()),
        attached_policies: vec![],
        groups: vec![],
        tags: vec![],
        description: None,
        raw: Some(u.clone()),
    }
}

fn entity_from_role(r: &Value, profile_id: &str) -> AccessEntity {
    AccessEntity {
        cloud: Cloud::Aws,
        kind: AccessObjectKind::Role,
        id: r
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: r
            .get("RoleName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        profile_id: Some(profile_id.into()),
        account_ref: None,
        path: r.get("Path").and_then(|v| v.as_str()).map(|s| s.into()),
        attached_policies: vec![],
        groups: vec![],
        tags: vec![],
        description: r
            .get("Description")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        raw: Some(r.clone()),
    }
}

fn entity_from_group(g: &Value, profile_id: &str) -> AccessEntity {
    AccessEntity {
        cloud: Cloud::Aws,
        kind: AccessObjectKind::Group,
        id: g
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: g
            .get("GroupName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        profile_id: Some(profile_id.into()),
        account_ref: None,
        path: g.get("Path").and_then(|v| v.as_str()).map(|s| s.into()),
        attached_policies: vec![],
        groups: vec![],
        tags: vec![],
        description: None,
        raw: Some(g.clone()),
    }
}

fn entity_from_policy(p: &Value, profile_id: &str) -> AccessEntity {
    AccessEntity {
        cloud: Cloud::Aws,
        kind: AccessObjectKind::Policy,
        id: p
            .get("Arn")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        name: p
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string(),
        profile_id: Some(profile_id.into()),
        account_ref: None,
        path: p.get("Path").and_then(|v| v.as_str()).map(|s| s.into()),
        attached_policies: vec![],
        groups: vec![],
        tags: vec![],
        description: p
            .get("Description")
            .and_then(|v| v.as_str())
            .map(|s| s.into()),
        raw: Some(p.clone()),
    }
}

fn name_matches(name: &str, pattern: &str) -> bool {
    let n = name.to_ascii_lowercase();
    let p = pattern.to_ascii_lowercase();
    if p.contains('*') {
        let parts: Vec<&str> = p.split('*').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return true;
        }
        let mut rest = n.as_str();
        for (i, part) in parts.iter().enumerate() {
            if let Some(idx) = rest.find(part) {
                if i == 0 && !p.starts_with('*') && idx != 0 {
                    return false;
                }
                rest = &rest[idx + part.len()..];
            } else {
                return false;
            }
        }
        return true;
    }
    n.contains(&p)
}

// ── tools ────────────────────────────────────────────────────────────

struct AwsIamCallerIdentity;
struct AwsIamUsersList;
struct AwsIamUserGet;
struct AwsIamRolesList;
struct AwsIamRoleGet;
struct AwsIamGroupsList;
struct AwsIamGroupGet;
struct AwsIamPoliciesList;
struct AwsIamPolicyGet;
struct AwsIamPatternSearch;
struct AwsIamSimulate;
struct AwsIamAccessTest;
struct AwsIamUserCreate;
struct AwsIamUserDelete;
struct AwsIamRoleCreate;
struct AwsIamRoleDelete;
struct AwsIamGroupCreate;
struct AwsIamGroupDelete;
struct AwsIamPolicyCreate;
struct AwsIamPolicyDelete;
struct AwsIamPolicyAttach;
struct AwsIamPolicyDetach;
struct AwsIamGroupAddUser;
struct AwsIamGroupRemoveUser;
struct AwsIamInlinePolicyPut;
struct AwsIamInlinePolicyDelete;

macro_rules! meta {
    ($id:expr, $name:expr, $desc:expr, $cap:expr, $tags:expr, $schema:expr) => {
        ToolMeta {
            id: $id.into(),
            name: $name.into(),
            description: $desc.into(),
            domain: ToolDomain::Access,
            clouds: vec![Cloud::Aws],
            capability: $cap,
            tags: $tags.into_iter().map(|s: &str| s.to_string()).collect(),
            input_schema: $schema,
            output_schema: None,
        }
    };
}

#[async_trait]
impl Tool for AwsIamCallerIdentity {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.caller.identity",
                "STS get-caller-identity",
                "Who am I? Returns Account, Arn, UserId for the current session. First step when troubleshooting permissions.",
                Capability::Read,
                ["iam", "sts", "identity", "whoami", "troubleshoot", "test"],
                json!({
                    "type": "object",
                    "properties": {
                        "profile_id": { "type": "string" }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        match aws_json(&profile, &["sts", "get-caller-identity"]).await {
            Ok(v) => ToolResult::success(
                format!(
                    "caller {}",
                    v.get("Arn").and_then(|a| a.as_str()).unwrap_or("?")
                ),
                json!({ "cloud": "aws", "identity": v, "profile_id": profile.id }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamUsersList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.users.list",
                "List IAM users",
                "List IAM users in the account. Prefer aws.iam.pattern.search for name fragments.",
                Capability::Read,
                ["iam", "user", "list", "users", "permission", "role"],
                json!({
                    "type": "object",
                    "properties": {
                        "profile_id": { "type": "string" },
                        "path_prefix": { "type": "string" },
                        "max_items": { "type": "integer", "default": 100 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli = vec!["iam".into(), "list-users".into()];
        if let Some(p) = arg_str(&args, "path_prefix") {
            cli.push("--path-prefix".into());
            cli.push(p.into());
        }
        let max = args
            .get("max_items")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        cli.push("--max-items".into());
        cli.push(max.to_string());
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => {
                let users: Vec<AccessEntity> = v
                    .get("Users")
                    .and_then(|u| u.as_array())
                    .map(|a| a.iter().map(|u| entity_from_user(u, &profile.id)).collect())
                    .unwrap_or_default();
                ToolResult::success(
                    format!("{} IAM user(s)", users.len()),
                    json!({ "cloud": "aws", "kind": "user", "count": users.len(), "entities": users }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamUserGet {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.user.get",
                "Get IAM user + attached policies/groups",
                "Fetch user detail, attached managed policies, inline policy names, and group memberships. Use for permission troubleshooting.",
                Capability::Read,
                ["iam", "user", "get", "policy", "group", "troubleshoot"],
                json!({
                    "type": "object",
                    "properties": {
                        "user_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["user_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "user_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let user = match aws_json(&profile, &["iam", "get-user", "--user-name", &name]).await {
            Ok(v) => v,
            Err(e) => return e,
        };
        let attached = aws_json(
            &profile,
            &[
                "iam",
                "list-attached-user-policies",
                "--user-name",
                &name,
            ],
        )
        .await
        .unwrap_or(json!({}));
        let inline = aws_json(
            &profile,
            &["iam", "list-user-policies", "--user-name", &name],
        )
        .await
        .unwrap_or(json!({}));
        let groups = aws_json(
            &profile,
            &["iam", "list-groups-for-user", "--user-name", &name],
        )
        .await
        .unwrap_or(json!({}));
        let mut ent = entity_from_user(user.get("User").unwrap_or(&user), &profile.id);
        ent.attached_policies = attached
            .get("AttachedPolicies")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        p.get("PolicyArn")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        ent.groups = groups
            .get("Groups")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|g| {
                        g.get("GroupName")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        ToolResult::success(
            format!("user `{name}`"),
            json!({
                "entity": ent,
                "inline_policies": inline.get("PolicyNames").unwrap_or(&json!([])),
                "attached_policies": attached.get("AttachedPolicies").unwrap_or(&json!([])),
                "groups": groups.get("Groups").unwrap_or(&json!([])),
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsIamRolesList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.roles.list",
                "List IAM roles",
                "List IAM roles. Prefer aws.iam.pattern.search for name fragments.",
                Capability::Read,
                ["iam", "role", "list", "roles", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "profile_id": { "type": "string" },
                        "path_prefix": { "type": "string" },
                        "max_items": { "type": "integer", "default": 100 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli = vec!["iam".into(), "list-roles".into()];
        if let Some(p) = arg_str(&args, "path_prefix") {
            cli.push("--path-prefix".into());
            cli.push(p.into());
        }
        let max = args
            .get("max_items")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        cli.push("--max-items".into());
        cli.push(max.to_string());
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => {
                let roles: Vec<AccessEntity> = v
                    .get("Roles")
                    .and_then(|u| u.as_array())
                    .map(|a| a.iter().map(|r| entity_from_role(r, &profile.id)).collect())
                    .unwrap_or_default();
                ToolResult::success(
                    format!("{} IAM role(s)", roles.len()),
                    json!({ "cloud": "aws", "kind": "role", "count": roles.len(), "entities": roles }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamRoleGet {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.role.get",
                "Get IAM role + attached policies",
                "Role detail, trust policy, attached managed policies, and inline policy names.",
                Capability::Read,
                ["iam", "role", "get", "trust", "policy", "troubleshoot"],
                json!({
                    "type": "object",
                    "properties": {
                        "role_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "role_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let role = match aws_json(&profile, &["iam", "get-role", "--role-name", &name]).await {
            Ok(v) => v,
            Err(e) => return e,
        };
        let attached = aws_json(
            &profile,
            &[
                "iam",
                "list-attached-role-policies",
                "--role-name",
                &name,
            ],
        )
        .await
        .unwrap_or(json!({}));
        let inline = aws_json(
            &profile,
            &["iam", "list-role-policies", "--role-name", &name],
        )
        .await
        .unwrap_or(json!({}));
        let mut ent = entity_from_role(role.get("Role").unwrap_or(&role), &profile.id);
        ent.attached_policies = attached
            .get("AttachedPolicies")
            .and_then(|a| a.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|p| {
                        p.get("PolicyArn")
                            .and_then(|x| x.as_str())
                            .map(|s| s.to_string())
                    })
                    .collect()
            })
            .unwrap_or_default();
        ToolResult::success(
            format!("role `{name}`"),
            json!({
                "entity": ent,
                "assume_role_policy": role.pointer("/Role/AssumeRolePolicyDocument"),
                "attached_policies": attached.get("AttachedPolicies").unwrap_or(&json!([])),
                "inline_policies": inline.get("PolicyNames").unwrap_or(&json!([])),
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsIamGroupsList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.groups.list",
                "List IAM groups",
                "List IAM groups in the account.",
                Capability::Read,
                ["iam", "group", "list", "groups"],
                json!({
                    "type": "object",
                    "properties": {
                        "profile_id": { "type": "string" },
                        "path_prefix": { "type": "string" },
                        "max_items": { "type": "integer", "default": 100 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let mut cli = vec!["iam".into(), "list-groups".into()];
        if let Some(p) = arg_str(&args, "path_prefix") {
            cli.push("--path-prefix".into());
            cli.push(p.into());
        }
        let max = args
            .get("max_items")
            .and_then(|v| v.as_u64())
            .unwrap_or(100);
        cli.push("--max-items".into());
        cli.push(max.to_string());
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => {
                let groups: Vec<AccessEntity> = v
                    .get("Groups")
                    .and_then(|u| u.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|g| entity_from_group(g, &profile.id))
                            .collect()
                    })
                    .unwrap_or_default();
                ToolResult::success(
                    format!("{} IAM group(s)", groups.len()),
                    json!({ "cloud": "aws", "kind": "group", "count": groups.len(), "entities": groups }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamGroupGet {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.group.get",
                "Get IAM group + members + policies",
                "Group detail, users in group, attached managed policies.",
                Capability::Read,
                ["iam", "group", "get", "members", "policy"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["group_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "group_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let group = match aws_json(&profile, &["iam", "get-group", "--group-name", &name]).await {
            Ok(v) => v,
            Err(e) => return e,
        };
        let attached = aws_json(
            &profile,
            &[
                "iam",
                "list-attached-group-policies",
                "--group-name",
                &name,
            ],
        )
        .await
        .unwrap_or(json!({}));
        let ent = entity_from_group(group.get("Group").unwrap_or(&group), &profile.id);
        ToolResult::success(
            format!("group `{name}`"),
            json!({
                "entity": ent,
                "users": group.get("Users").unwrap_or(&json!([])),
                "attached_policies": attached.get("AttachedPolicies").unwrap_or(&json!([])),
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsIamPoliciesList {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policies.list",
                "List IAM managed policies",
                "List customer or AWS managed policies (Scope=Local|AWS|All).",
                Capability::Read,
                ["iam", "policy", "list", "policies", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "scope": { "type": "string", "enum": ["Local", "AWS", "All"], "default": "Local" },
                        "profile_id": { "type": "string" },
                        "max_items": { "type": "integer", "default": 100 }
                    }
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let scope = arg_str(&args, "scope").unwrap_or("Local");
        let max = args
            .get("max_items")
            .and_then(|v| v.as_u64())
            .unwrap_or(100)
            .to_string();
        match aws_json(
            &profile,
            &["iam", "list-policies", "--scope", scope, "--max-items", &max],
        )
        .await
        {
            Ok(v) => {
                let policies: Vec<AccessEntity> = v
                    .get("Policies")
                    .and_then(|u| u.as_array())
                    .map(|a| {
                        a.iter()
                            .map(|p| entity_from_policy(p, &profile.id))
                            .collect()
                    })
                    .unwrap_or_default();
                ToolResult::success(
                    format!("{} managed policies (scope={scope})", policies.len()),
                    json!({ "cloud": "aws", "kind": "policy", "scope": scope, "count": policies.len(), "entities": policies }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamPolicyGet {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policy.get",
                "Get managed policy document",
                "Fetch policy metadata and default version document (permissions JSON).",
                Capability::Read,
                ["iam", "policy", "get", "document", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_arn": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_arn"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let arn = match require_str(&args, "policy_arn") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let pol = match aws_json(&profile, &["iam", "get-policy", "--policy-arn", &arn]).await {
            Ok(v) => v,
            Err(e) => return e,
        };
        let ver = pol
            .pointer("/Policy/DefaultVersionId")
            .and_then(|v| v.as_str())
            .unwrap_or("v1")
            .to_string();
        let doc = aws_json(
            &profile,
            &[
                "iam",
                "get-policy-version",
                "--policy-arn",
                &arn,
                "--version-id",
                &ver,
            ],
        )
        .await
        .unwrap_or(json!({}));
        ToolResult::success(
            format!("policy {arn}"),
            json!({
                "policy": pol.get("Policy"),
                "version_id": ver,
                "document": doc.pointer("/PolicyVersion/Document"),
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsIamPatternSearch {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.pattern.search",
                "Search IAM users/roles/groups/policies by name",
                "Partial-match discovery for IAM entities (substring contains by default; simple glob with *). kinds: user|role|group|policy.",
                Capability::Read,
                ["iam", "pattern", "search", "user", "role", "group", "policy", "discover", "partial"],
                json!({
                    "type": "object",
                    "properties": {
                        "pattern": { "type": "string", "description": "Name fragment (partial contains) or simple glob (*)" },
                        "kinds": {
                            "type": "array",
                            "items": { "type": "string", "enum": ["user", "role", "group", "policy"] }
                        },
                        "profile_id": { "type": "string" },
                        "limit": { "type": "integer", "default": 50 }
                    },
                    "required": ["pattern"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let pattern = match require_str(&args, "pattern") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let kinds: Vec<String> = args
            .get("kinds")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["user".into(), "role".into(), "group".into()]);
        let limit = args.get("limit").and_then(|v| v.as_u64()).unwrap_or(50) as usize;
        let mut entities = Vec::new();
        let mut notes = Vec::new();

        if kinds.iter().any(|k| k == "user") {
            match aws_json(&profile, &["iam", "list-users", "--max-items", "200"]).await {
                Ok(v) => {
                    if let Some(arr) = v.get("Users").and_then(|a| a.as_array()) {
                        for u in arr {
                            let ent = entity_from_user(u, &profile.id);
                            if name_matches(&ent.name, &pattern) || name_matches(&ent.id, &pattern)
                            {
                                entities.push(ent);
                            }
                        }
                    }
                }
                Err(e) => notes.push(format!("users: {}", e.summary)),
            }
        }
        if kinds.iter().any(|k| k == "role") {
            match aws_json(&profile, &["iam", "list-roles", "--max-items", "200"]).await {
                Ok(v) => {
                    if let Some(arr) = v.get("Roles").and_then(|a| a.as_array()) {
                        for r in arr {
                            let ent = entity_from_role(r, &profile.id);
                            if name_matches(&ent.name, &pattern) || name_matches(&ent.id, &pattern)
                            {
                                entities.push(ent);
                            }
                        }
                    }
                }
                Err(e) => notes.push(format!("roles: {}", e.summary)),
            }
        }
        if kinds.iter().any(|k| k == "group") {
            match aws_json(&profile, &["iam", "list-groups", "--max-items", "200"]).await {
                Ok(v) => {
                    if let Some(arr) = v.get("Groups").and_then(|a| a.as_array()) {
                        for g in arr {
                            let ent = entity_from_group(g, &profile.id);
                            if name_matches(&ent.name, &pattern) || name_matches(&ent.id, &pattern)
                            {
                                entities.push(ent);
                            }
                        }
                    }
                }
                Err(e) => notes.push(format!("groups: {}", e.summary)),
            }
        }
        if kinds.iter().any(|k| k == "policy") {
            match aws_json(
                &profile,
                &["iam", "list-policies", "--scope", "Local", "--max-items", "200"],
            )
            .await
            {
                Ok(v) => {
                    if let Some(arr) = v.get("Policies").and_then(|a| a.as_array()) {
                        for p in arr {
                            let ent = entity_from_policy(p, &profile.id);
                            if name_matches(&ent.name, &pattern) || name_matches(&ent.id, &pattern)
                            {
                                entities.push(ent);
                            }
                        }
                    }
                }
                Err(e) => notes.push(format!("policies: {}", e.summary)),
            }
        }

        entities.truncate(limit);
        ToolResult::success(
            format!(
                "{} IAM hit(s) for pattern `{pattern}`",
                entities.len()
            ),
            json!({
                "cloud": "aws",
                "pattern": pattern,
                "count": entities.len(),
                "entities": entities,
                "notes": notes,
            }),
        )
    }
}

#[async_trait]
impl Tool for AwsIamSimulate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.simulate",
                "Simulate principal policy (troubleshoot)",
                "Run iam simulate-principal-policy: test whether a user/role ARN can perform action(s) on resource(s). Primary permission troubleshooting tool.",
                Capability::Read,
                ["iam", "simulate", "troubleshoot", "permission", "test", "policy", "access"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_source_arn": {
                            "type": "string",
                            "description": "User or role ARN to evaluate"
                        },
                        "action_names": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "e.g. s3:GetObject, ec2:DescribeInstances"
                        },
                        "resource_arns": {
                            "type": "array",
                            "items": { "type": "string" },
                            "description": "Resource ARNs; default *"
                        },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_source_arn", "action_names"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let source = match require_str(&args, "policy_source_arn") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let actions: Vec<String> = args
            .get("action_names")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if actions.is_empty() {
            return ToolResult::error("action_names must be a non-empty array");
        }
        let resources: Vec<String> = args
            .get("resource_arns")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["*".into()]);

        let mut cli = vec![
            "iam".into(),
            "simulate-principal-policy".into(),
            "--policy-source-arn".into(),
            source.clone(),
        ];
        cli.push("--action-names".into());
        cli.extend(actions.clone());
        cli.push("--resource-arns".into());
        cli.extend(resources.clone());
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => {
                let results = v
                    .get("EvaluationResults")
                    .cloned()
                    .unwrap_or(json!([]));
                let mut checks = Vec::new();
                if let Some(arr) = results.as_array() {
                    for r in arr {
                        let decision = match r
                            .get("EvalDecision")
                            .and_then(|d| d.as_str())
                            .unwrap_or("")
                        {
                            "allowed" => AccessDecision::Allowed,
                            "explicitDeny" => AccessDecision::Denied,
                            "implicitDeny" => AccessDecision::ImplicitDeny,
                            _ => AccessDecision::Unknown,
                        };
                        checks.push(AccessCheckResult {
                            cloud: Cloud::Aws,
                            principal: source.clone(),
                            action: r
                                .get("EvalActionName")
                                .and_then(|a| a.as_str())
                                .unwrap_or("")
                                .into(),
                            resource: r
                                .get("EvalResourceName")
                                .and_then(|a| a.as_str())
                                .map(|s| s.into()),
                            decision,
                            matched_statements: vec![],
                            missing_permissions: vec![],
                            notes: vec![],
                            raw: Some(r.clone()),
                        });
                    }
                }
                let allowed = checks
                    .iter()
                    .filter(|c| c.decision == AccessDecision::Allowed)
                    .count();
                let denied = checks.len().saturating_sub(allowed);
                ToolResult::success(
                    format!(
                        "simulate {source}: {allowed} allowed, {denied} denied/other"
                    ),
                    json!({
                        "cloud": "aws",
                        "policy_source_arn": source,
                        "checks": checks,
                        "raw": v,
                        "guidance": [
                            "allowed = explicit allow matched",
                            "implicitDeny = no allow (add policy or attach role)",
                            "explicitDeny = Deny statement — remove or adjust Deny",
                            "Use aws.iam.user.get / role.get to inspect attached policies",
                        ]
                    }),
                )
            }
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamAccessTest {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.access.test",
                "Test if principal can action resource",
                "Convenience wrapper around simulate for a single action+resource. Also reports current caller identity.",
                Capability::Read,
                ["iam", "test", "permission", "access", "troubleshoot", "can-i"],
                json!({
                    "type": "object",
                    "properties": {
                        "principal_arn": {
                            "type": "string",
                            "description": "User/role ARN; omit to use current caller"
                        },
                        "action": { "type": "string", "description": "e.g. s3:GetObject" },
                        "resource": { "type": "string", "default": "*" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["action"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let action = match require_str(&args, "action") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let resource = arg_str(&args, "resource").unwrap_or("*").to_string();
        let principal = if let Some(p) = arg_str(&args, "principal_arn") {
            p.to_string()
        } else {
            match aws_json(&profile, &["sts", "get-caller-identity"]).await {
                Ok(id) => id
                    .get("Arn")
                    .and_then(|a| a.as_str())
                    .unwrap_or("")
                    .to_string(),
                Err(e) => return e,
            }
        };
        // IAM simulate needs user/role ARN; convert assumed-role session ARN if needed
        let source = normalize_policy_source_arn(&principal);
        let sim_args = json!({
            "policy_source_arn": source,
            "action_names": [action],
            "resource_arns": [resource],
            "profile_id": profile.id,
        });
        AwsIamSimulate.execute(sim_args, ctx).await
    }
}

/// Convert assumed-role session ARN → role ARN for simulate-principal-policy.
fn normalize_policy_source_arn(arn: &str) -> String {
    // arn:aws:sts::ACCOUNT:assumed-role/ROLE_NAME/session → arn:aws:iam::ACCOUNT:role/ROLE_NAME
    if let Some(rest) = arn.strip_prefix("arn:aws:sts::") {
        if let Some((account, after)) = rest.split_once(':') {
            if let Some(role_part) = after.strip_prefix("assumed-role/") {
                let role_name = role_part.split('/').next().unwrap_or(role_part);
                return format!("arn:aws:iam::{account}:role/{role_name}");
            }
        }
    }
    arn.to_string()
}

// ── mutations ────────────────────────────────────────────────────────

#[async_trait]
impl Tool for AwsIamUserCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.user.create",
                "Create IAM user",
                "Create an IAM user (readwrite mode). Does not create access keys (use console/CLI separately to avoid secret leakage to the agent).",
                Capability::Write,
                ["iam", "user", "create", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "user_name": { "type": "string" },
                        "path": { "type": "string", "default": "/" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["user_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "user_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let path = arg_str(&args, "path").unwrap_or("/");
        match aws_json(
            &profile,
            &["iam", "create-user", "--user-name", &name, "--path", path],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("created user `{name}`"),
                json!({ "mutation": "create", "kind": "user", "user": v.get("User") }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamUserDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.user.delete",
                "Delete IAM user",
                "Delete IAM user. May fail if keys/policies still attached — detach first.",
                Capability::Write,
                ["iam", "user", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "user_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["user_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "user_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(&profile, &["iam", "delete-user", "--user-name", &name]).await {
            Ok(_) => ToolResult::success(
                format!("deleted user `{name}`"),
                json!({ "mutation": "delete", "kind": "user", "user_name": name }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamRoleCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.role.create",
                "Create IAM role",
                "Create IAM role with trust policy JSON (assume-role policy document).",
                Capability::Write,
                ["iam", "role", "create", "write", "manage", "trust"],
                json!({
                    "type": "object",
                    "properties": {
                        "role_name": { "type": "string" },
                        "assume_role_policy_document": {
                            "type": "string",
                            "description": "Trust policy JSON string"
                        },
                        "description": { "type": "string" },
                        "path": { "type": "string", "default": "/" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role_name", "assume_role_policy_document"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "role_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let trust = match require_str(&args, "assume_role_policy_document") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let path = arg_str(&args, "path").unwrap_or("/");
        let mut cli = vec![
            "iam".into(),
            "create-role".into(),
            "--role-name".into(),
            name.clone(),
            "--assume-role-policy-document".into(),
            trust,
            "--path".into(),
            path.into(),
        ];
        if let Some(d) = arg_str(&args, "description") {
            cli.push("--description".into());
            cli.push(d.into());
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("created role `{name}`"),
                json!({ "mutation": "create", "kind": "role", "role": v.get("Role") }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamRoleDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.role.delete",
                "Delete IAM role",
                "Delete IAM role after detaching policies/instance profiles.",
                Capability::Write,
                ["iam", "role", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "role_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["role_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "role_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(&profile, &["iam", "delete-role", "--role-name", &name]).await {
            Ok(_) => ToolResult::success(
                format!("deleted role `{name}`"),
                json!({ "mutation": "delete", "kind": "role", "role_name": name }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamGroupCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.group.create",
                "Create IAM group",
                "Create an IAM group.",
                Capability::Write,
                ["iam", "group", "create", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_name": { "type": "string" },
                        "path": { "type": "string", "default": "/" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["group_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "group_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let path = arg_str(&args, "path").unwrap_or("/");
        match aws_json(
            &profile,
            &[
                "iam",
                "create-group",
                "--group-name",
                &name,
                "--path",
                path,
            ],
        )
        .await
        {
            Ok(v) => ToolResult::success(
                format!("created group `{name}`"),
                json!({ "mutation": "create", "kind": "group", "group": v.get("Group") }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamGroupDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.group.delete",
                "Delete IAM group",
                "Delete IAM group (detach policies/users first if required).",
                Capability::Write,
                ["iam", "group", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["group_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "group_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(&profile, &["iam", "delete-group", "--group-name", &name]).await {
            Ok(_) => ToolResult::success(
                format!("deleted group `{name}`"),
                json!({ "mutation": "delete", "kind": "group", "group_name": name }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamPolicyCreate {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policy.create",
                "Create customer managed policy",
                "Create a customer managed IAM policy from a policy document JSON string.",
                Capability::Write,
                ["iam", "policy", "create", "write", "manage", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_name": { "type": "string" },
                        "policy_document": { "type": "string", "description": "IAM policy JSON" },
                        "description": { "type": "string" },
                        "path": { "type": "string", "default": "/" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_name", "policy_document"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let name = match require_str(&args, "policy_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let doc = match require_str(&args, "policy_document") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let path = arg_str(&args, "path").unwrap_or("/");
        let mut cli = vec![
            "iam".into(),
            "create-policy".into(),
            "--policy-name".into(),
            name.clone(),
            "--policy-document".into(),
            doc,
            "--path".into(),
            path.into(),
        ];
        if let Some(d) = arg_str(&args, "description") {
            cli.push("--description".into());
            cli.push(d.into());
        }
        let refs: Vec<&str> = cli.iter().map(|s| s.as_str()).collect();
        match aws_json(&profile, &refs).await {
            Ok(v) => ToolResult::success(
                format!("created policy `{name}`"),
                json!({ "mutation": "create", "kind": "policy", "policy": v.get("Policy") }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamPolicyDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policy.delete",
                "Delete customer managed policy",
                "Delete a customer managed policy by ARN (detach from all entities first).",
                Capability::Write,
                ["iam", "policy", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_arn": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_arn"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let arn = match require_str(&args, "policy_arn") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(&profile, &["iam", "delete-policy", "--policy-arn", &arn]).await {
            Ok(_) => ToolResult::success(
                format!("deleted policy {arn}"),
                json!({ "mutation": "delete", "kind": "policy", "policy_arn": arn }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamPolicyAttach {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policy.attach",
                "Attach managed policy to user/role/group",
                "Attach a managed policy ARN to a user, role, or group (target_type).",
                Capability::Write,
                ["iam", "policy", "attach", "write", "manage", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_arn": { "type": "string" },
                        "target_type": { "type": "string", "enum": ["user", "role", "group"] },
                        "target_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_arn", "target_type", "target_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let arn = match require_str(&args, "policy_arn") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let ttype = match require_str(&args, "target_type") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let tname = match require_str(&args, "target_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let (cmd, flag) = match ttype.as_str() {
            "user" => ("attach-user-policy", "--user-name"),
            "role" => ("attach-role-policy", "--role-name"),
            "group" => ("attach-group-policy", "--group-name"),
            _ => return ToolResult::error("target_type must be user|role|group"),
        };
        match aws_cli(
            &profile,
            &["iam", cmd, flag, &tname, "--policy-arn", &arn],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("attached {arn} to {ttype}/{tname}"),
                json!({
                    "mutation": "attach",
                    "policy_arn": arn,
                    "target_type": ttype,
                    "target_name": tname
                }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamPolicyDetach {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.policy.detach",
                "Detach managed policy from user/role/group",
                "Detach a managed policy ARN from a user, role, or group.",
                Capability::Write,
                ["iam", "policy", "detach", "write", "manage", "remove", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "policy_arn": { "type": "string" },
                        "target_type": { "type": "string", "enum": ["user", "role", "group"] },
                        "target_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["policy_arn", "target_type", "target_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let arn = match require_str(&args, "policy_arn") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let ttype = match require_str(&args, "target_type") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let tname = match require_str(&args, "target_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let (cmd, flag) = match ttype.as_str() {
            "user" => ("detach-user-policy", "--user-name"),
            "role" => ("detach-role-policy", "--role-name"),
            "group" => ("detach-group-policy", "--group-name"),
            _ => return ToolResult::error("target_type must be user|role|group"),
        };
        match aws_cli(
            &profile,
            &["iam", cmd, flag, &tname, "--policy-arn", &arn],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("detached {arn} from {ttype}/{tname}"),
                json!({
                    "mutation": "detach",
                    "policy_arn": arn,
                    "target_type": ttype,
                    "target_name": tname
                }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamGroupAddUser {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.group.add_user",
                "Add user to IAM group",
                "Add an IAM user to a group (grants group's policies).",
                Capability::Write,
                ["iam", "group", "user", "add", "member", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_name": { "type": "string" },
                        "user_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["group_name", "user_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let group = match require_str(&args, "group_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let user = match require_str(&args, "user_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(
            &profile,
            &[
                "iam",
                "add-user-to-group",
                "--group-name",
                &group,
                "--user-name",
                &user,
            ],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("added user `{user}` to group `{group}`"),
                json!({ "mutation": "add_member", "group_name": group, "user_name": user }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamGroupRemoveUser {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.group.remove_user",
                "Remove user from IAM group",
                "Remove an IAM user from a group.",
                Capability::Write,
                ["iam", "group", "user", "remove", "member", "write", "manage"],
                json!({
                    "type": "object",
                    "properties": {
                        "group_name": { "type": "string" },
                        "user_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["group_name", "user_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let group = match require_str(&args, "group_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let user = match require_str(&args, "user_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        match aws_cli(
            &profile,
            &[
                "iam",
                "remove-user-from-group",
                "--group-name",
                &group,
                "--user-name",
                &user,
            ],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("removed user `{user}` from group `{group}`"),
                json!({ "mutation": "remove_member", "group_name": group, "user_name": user }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamInlinePolicyPut {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.inline_policy.put",
                "Put inline policy on user/role/group",
                "Create or replace an inline policy document on a user, role, or group.",
                Capability::Write,
                ["iam", "policy", "inline", "put", "write", "manage", "permission"],
                json!({
                    "type": "object",
                    "properties": {
                        "target_type": { "type": "string", "enum": ["user", "role", "group"] },
                        "target_name": { "type": "string" },
                        "policy_name": { "type": "string" },
                        "policy_document": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["target_type", "target_name", "policy_name", "policy_document"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ttype = match require_str(&args, "target_type") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let tname = match require_str(&args, "target_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let pname = match require_str(&args, "policy_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let doc = match require_str(&args, "policy_document") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let (cmd, flag) = match ttype.as_str() {
            "user" => ("put-user-policy", "--user-name"),
            "role" => ("put-role-policy", "--role-name"),
            "group" => ("put-group-policy", "--group-name"),
            _ => return ToolResult::error("target_type must be user|role|group"),
        };
        match aws_cli(
            &profile,
            &[
                "iam",
                cmd,
                flag,
                &tname,
                "--policy-name",
                &pname,
                "--policy-document",
                &doc,
            ],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("put inline policy `{pname}` on {ttype}/{tname}"),
                json!({
                    "mutation": "update",
                    "target_type": ttype,
                    "target_name": tname,
                    "policy_name": pname
                }),
            ),
            Err(e) => e,
        }
    }
}

#[async_trait]
impl Tool for AwsIamInlinePolicyDelete {
    fn meta(&self) -> &ToolMeta {
        static M: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        M.get_or_init(|| {
            meta!(
                "aws.iam.inline_policy.delete",
                "Delete inline policy from user/role/group",
                "Remove a named inline policy from a user, role, or group.",
                Capability::Write,
                ["iam", "policy", "inline", "delete", "write", "manage", "remove"],
                json!({
                    "type": "object",
                    "properties": {
                        "target_type": { "type": "string", "enum": ["user", "role", "group"] },
                        "target_name": { "type": "string" },
                        "policy_name": { "type": "string" },
                        "profile_id": { "type": "string" }
                    },
                    "required": ["target_type", "target_name", "policy_name"]
                })
            )
        })
    }
    async fn execute(&self, args: Value, ctx: &ToolContext) -> ToolResult {
        let profile = match resolve_aws_profile_ctx(ctx, profile_id_arg(&args)) {
            Ok(p) => p,
            Err(e) => return e,
        };
        let ttype = match require_str(&args, "target_type") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let tname = match require_str(&args, "target_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let pname = match require_str(&args, "policy_name") {
            Ok(n) => n,
            Err(e) => return e,
        };
        let (cmd, flag) = match ttype.as_str() {
            "user" => ("delete-user-policy", "--user-name"),
            "role" => ("delete-role-policy", "--role-name"),
            "group" => ("delete-group-policy", "--group-name"),
            _ => return ToolResult::error("target_type must be user|role|group"),
        };
        match aws_cli(
            &profile,
            &["iam", cmd, flag, &tname, "--policy-name", &pname],
        )
        .await
        {
            Ok(_) => ToolResult::success(
                format!("deleted inline policy `{pname}` from {ttype}/{tname}"),
                json!({
                    "mutation": "delete",
                    "target_type": ttype,
                    "target_name": tname,
                    "policy_name": pname
                }),
            ),
            Err(e) => e,
        }
    }
}

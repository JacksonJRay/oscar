//! Unified multi-cloud identity / access (IAM) model.
//!
//! CSP-specific tools map into these shapes so the agent can manage, troubleshoot,
//! and test users/roles/permissions consistently across AWS IAM, GCP IAM, and Azure RBAC.

use crate::types::Cloud;
use serde::{Deserialize, Serialize};
use std::fmt;

/// Kind of identity or access object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessObjectKind {
    User,
    Group,
    Role,
    ServiceAccount,
    ServicePrincipal,
    ManagedIdentity,
    Policy,
    RoleAssignment,
    Binding,
    Permission,
    Other,
}

impl fmt::Display for AccessObjectKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::User => "user",
            Self::Group => "group",
            Self::Role => "role",
            Self::ServiceAccount => "service_account",
            Self::ServicePrincipal => "service_principal",
            Self::ManagedIdentity => "managed_identity",
            Self::Policy => "policy",
            Self::RoleAssignment => "role_assignment",
            Self::Binding => "binding",
            Self::Permission => "permission",
            Self::Other => "other",
        };
        write!(f, "{s}")
    }
}

/// A principal or access-related entity (user, role, policy, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessEntity {
    pub cloud: Cloud,
    pub kind: AccessObjectKind,
    /// Stable id (ARN, full resource name, object id, …).
    pub id: String,
    /// Human name (UserName, role id, SA email, …).
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub attached_policies: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// CSP-native payload (already redacted of secrets).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

/// Role/policy binding: principal → role/policy on a scope/resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessBinding {
    pub cloud: Cloud,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub principal_type: Option<String>,
    /// Role name, role definition id, or policy ARN.
    pub role_or_policy: String,
    /// Project / subscription / account / resource scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
}

/// Result of an access simulation / permission test.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessCheckResult {
    pub cloud: Cloud,
    pub principal: String,
    /// Action / permission tested (e.g. s3:GetObject, resourcemanager.projects.get).
    pub action: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource: Option<String>,
    /// allowed | denied | unknown | error
    pub decision: AccessDecision,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub matched_statements: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub missing_permissions: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub raw: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessDecision {
    Allowed,
    Denied,
    ImplicitDeny,
    Unknown,
    Error,
}

impl fmt::Display for AccessDecision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::ImplicitDeny => "implicit_deny",
            Self::Unknown => "unknown",
            Self::Error => "error",
        };
        write!(f, "{s}")
    }
}

impl AccessCheckResult {
    pub fn summary_line(&self) -> String {
        format!(
            "{} principal={} action={} resource={} → {}",
            self.cloud,
            self.principal,
            self.action,
            self.resource.as_deref().unwrap_or("*"),
            self.decision
        )
    }
}

/// Lightweight IAM inventory snapshot (optional cache).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessInventory {
    pub cloud: Cloud,
    pub profile_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub account_ref: Option<String>,
    #[serde(default)]
    pub entities: Vec<AccessEntity>,
    #[serde(default)]
    pub bindings: Vec<AccessBinding>,
    #[serde(default)]
    pub notes: Vec<String>,
}

impl Default for AccessInventory {
    fn default() -> Self {
        Self {
            cloud: Cloud::Multi,
            profile_id: String::new(),
            account_ref: None,
            entities: vec![],
            bindings: vec![],
            notes: vec![],
        }
    }
}

/// Mutation kind for audit-friendly write tools.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessMutation {
    Create,
    Delete,
    Update,
    Attach,
    Detach,
    AddMember,
    RemoveMember,
    Bind,
    Unbind,
}

impl fmt::Display for AccessMutation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Create => "create",
            Self::Delete => "delete",
            Self::Update => "update",
            Self::Attach => "attach",
            Self::Detach => "detach",
            Self::AddMember => "add_member",
            Self::RemoveMember => "remove_member",
            Self::Bind => "bind",
            Self::Unbind => "unbind",
        };
        write!(f, "{s}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn check_summary() {
        let r = AccessCheckResult {
            cloud: Cloud::Aws,
            principal: "arn:aws:iam::1:user/a".into(),
            action: "s3:GetObject".into(),
            resource: Some("arn:aws:s3:::bucket/*".into()),
            decision: AccessDecision::Allowed,
            matched_statements: vec![],
            missing_permissions: vec![],
            notes: vec![],
            raw: None,
        };
        assert!(r.summary_line().contains("allowed"));
    }
}

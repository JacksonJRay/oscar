use serde::{Deserialize, Serialize};
use std::fmt;

/// Cloud service provider (or multi / k8s).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Cloud {
    Aws,
    Gcp,
    Azure,
    Multi,
    K8s,
}

impl fmt::Display for Cloud {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Cloud::Aws => write!(f, "aws"),
            Cloud::Gcp => write!(f, "gcp"),
            Cloud::Azure => write!(f, "azure"),
            Cloud::Multi => write!(f, "multi"),
            Cloud::K8s => write!(f, "k8s"),
        }
    }
}

impl Cloud {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "aws" | "amazon" => Some(Cloud::Aws),
            "gcp" | "google" | "gcloud" => Some(Cloud::Gcp),
            "azure" | "az" => Some(Cloud::Azure),
            "multi" | "any" => Some(Cloud::Multi),
            "k8s" | "kubernetes" | "kube" => Some(Cloud::K8s),
            _ => None,
        }
    }

    /// Stable id prefix used for oscar profile ids: `aws-…`, `gcp-…`, `azure-…`, `k8s-…`.
    pub fn id_prefix(self) -> &'static str {
        match self {
            Cloud::Aws => "aws",
            Cloud::Gcp => "gcp",
            Cloud::Azure => "azure",
            Cloud::K8s => "k8s",
            Cloud::Multi => "multi",
        }
    }

    /// Human label for lists / agent context (CSP distinction).
    pub fn display_name(self) -> &'static str {
        match self {
            Cloud::Aws => "AWS",
            Cloud::Gcp => "GCP",
            Cloud::Azure => "Azure",
            Cloud::K8s => "Kubernetes",
            Cloud::Multi => "Multi-cloud",
        }
    }

    /// What `account_ref` means for this CSP (helps agents not confuse account vs project vs sub).
    pub fn account_kind(self) -> &'static str {
        match self {
            Cloud::Aws => "account_id",
            Cloud::Gcp => "project_id",
            Cloud::Azure => "subscription_id",
            Cloud::K8s => "cluster_or_context",
            Cloud::Multi => "account_ref",
        }
    }

    /// Short tag for UI tables: `[AWS]` `[GCP]` `[AZURE]` `[K8S]`.
    pub fn tag(self) -> &'static str {
        match self {
            Cloud::Aws => "[AWS]",
            Cloud::Gcp => "[GCP]",
            Cloud::Azure => "[AZURE]",
            Cloud::K8s => "[K8S]",
            Cloud::Multi => "[MULTI]",
        }
    }
}

/// Tool capability relative to the session mode gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Capability {
    Read,
    Write,
}

impl fmt::Display for Capability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Capability::Read => write!(f, "read"),
            Capability::Write => write!(f, "write"),
        }
    }
}

/// Session execution mode. Read-only is the default and is enforced in the tool registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ExecutionMode {
    #[default]
    ReadOnly,
    ReadWrite,
}

impl fmt::Display for ExecutionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ExecutionMode::ReadOnly => write!(f, "readonly"),
            ExecutionMode::ReadWrite => write!(f, "readwrite"),
        }
    }
}

impl ExecutionMode {
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "readonly" | "ro" | "read-only" | "read_only" => Some(ExecutionMode::ReadOnly),
            "readwrite" | "rw" | "read-write" | "read_write" => Some(ExecutionMode::ReadWrite),
            _ => None,
        }
    }

    pub fn allows(&self, cap: Capability) -> bool {
        match (self, cap) {
            (ExecutionMode::ReadWrite, _) => true,
            (ExecutionMode::ReadOnly, Capability::Read) => true,
            (ExecutionMode::ReadOnly, Capability::Write) => false,
        }
    }
}

/// High-level tool domain for inventory search.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolDomain {
    Dns,
    Network,
    Access,
    Account,
    Cluster,
    Infra,
    Meta,
}

impl fmt::Display for ToolDomain {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            ToolDomain::Dns => "dns",
            ToolDomain::Network => "network",
            ToolDomain::Access => "access",
            ToolDomain::Account => "account",
            ToolDomain::Cluster => "cluster",
            ToolDomain::Infra => "infra",
            ToolDomain::Meta => "meta",
        };
        write!(f, "{s}")
    }
}

/// Reference to a Kubernetes cluster attached to a cloud profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterRef {
    pub name: String,
    pub context: Option<String>,
    pub region: Option<String>,
}

/// DNS scope for lookups.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DnsScope {
    Public,
    Private { network_or_vpc: Option<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsRecord {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub ttl: Option<u32>,
    pub values: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ZoneRef {
    pub id: String,
    pub name: String,
    pub private: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DnsLookupResult {
    pub query: String,
    pub scope: DnsScope,
    pub cloud: Cloud,
    pub profile_id: String,
    pub records: Vec<DnsRecord>,
    pub zone: Option<ZoneRef>,
    pub authority: Option<String>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathStatus {
    Reachable,
    Unreachable,
    Partial,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathHop {
    pub order: u32,
    pub resource: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathBlocker {
    pub kind: String,
    pub resource: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PathTraceResult {
    pub cloud: Cloud,
    pub status: PathStatus,
    pub hops: Vec<PathHop>,
    pub blockers: Vec<PathBlocker>,
    pub raw_ref: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Diagnostic {
    pub code: Option<String>,
    pub message: String,
    pub severity: DiagnosticSeverity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiagnosticSeverity {
    Info,
    Warning,
    Error,
}

/// Credential kinds the TUI / headless auth may solicit or store.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecretKind {
    /// LLM provider API key (stored under provider id, not cloud profile).
    ApiKey,
    AccessKeyId,
    SecretAccessKey,
    /// Short-lived STS / federated token (AWS session, similar for other CSPs).
    SessionToken,
    ServiceAccountJson,
    AzureClientSecret,
    AzureClientId,
    AzureTenantId,
    Kubeconfig,
    /// AWS role ARN to assume (metadata; not always secret).
    RoleArn,
    Other,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum AuthSource {
    /// OS keychain long-lived or pasted secrets.
    #[default]
    Keychain,
    /// Short-lived role/session credentials.
    ShortLived,
    /// Detected local binary session (aws/gcloud/az/kubectl already authenticated).
    BinarySession,
    /// Explicit custom provider env var only when configured.
    CustomEnv,
    HeadlessFlag,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthRequest {
    pub profile_hint: Option<String>,
    pub cloud: Cloud,
    pub kinds: Vec<SecretKind>,
    pub reason: String,
    /// When true, existing credentials were rejected (expired/invalid) — re-prompt.
    #[serde(default)]
    pub reauth: bool,
    /// Operator-facing how-to (SSO, role, paste keys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub hint_commands: Vec<String>,
    /// Human guidance for short-term vs long-term auth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub guidance: Option<String>,
}

impl AuthRequest {
    pub fn new(cloud: Cloud, reason: impl Into<String>, kinds: Vec<SecretKind>) -> Self {
        Self {
            profile_hint: None,
            cloud,
            kinds,
            reason: reason.into(),
            reauth: false,
            hint_commands: vec![],
            guidance: None,
        }
    }

    pub fn with_hints<I, S>(mut self, hints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.hint_commands = hints.into_iter().map(|s| s.into()).collect();
        self
    }

    pub fn with_guidance(mut self, g: impl Into<String>) -> Self {
        self.guidance = Some(g.into());
        self
    }

    pub fn reauth(mut self) -> Self {
        self.reauth = true;
        self
    }

    pub fn profile(mut self, id: impl Into<String>) -> Self {
        self.profile_hint = Some(id.into());
        self
    }
}

/// Classification of a CSP CLI/API failure for re-auth decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthFailureKind {
    Missing,
    Expired,
    Invalid,
    PermissionDenied,
    BinaryMissing,
    Other,
}

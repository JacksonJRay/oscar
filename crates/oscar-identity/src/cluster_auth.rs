//! Kubernetes cluster auth kinds and prepare plans.
//!
//! Managed clouds (EKS/GKE/AKS) use **short-lived CSP credentials** + kubeconfig
//! `exec` plugins. Local clusters (kind/k3s/minikube/…) use **kubeconfig only**.
//! When kind is unknown, callers must ask the user before preparing secrets.

use oscar_core::{AuthRequest, Cloud, ClusterKind, ClusterRef, Paths, SecretKind};
use serde::Serialize;
use std::path::PathBuf;

use crate::profiles::Profile;

/// Infer [`ClusterKind`] from free text (user utterance or cluster name).
///
/// Returns [`ClusterKind::Unknown`] when ambiguous — agent must ask.
pub fn infer_cluster_kind(text: &str) -> ClusterKind {
    let t = text.to_ascii_lowercase();
    // Order matters: more specific first.
    if t.contains("eks") || t.contains("elastic kubernetes") {
        return ClusterKind::Eks;
    }
    if t.contains("gke") || t.contains("google kubernetes") {
        return ClusterKind::Gke;
    }
    if t.contains("aks") || t.contains("azure kubernetes") {
        return ClusterKind::Aks;
    }
    if t.contains("kind") {
        return ClusterKind::Kind;
    }
    if t.contains("k3d") || t.contains("k3s") {
        return ClusterKind::K3s;
    }
    if t.contains("minikube") {
        return ClusterKind::Minikube;
    }
    if t.contains("k0s") {
        return ClusterKind::K0s;
    }
    if t.contains("local")
        || t.contains("on-prem")
        || t.contains("onprem")
        || t.contains("self-managed")
        || t.contains("self managed")
        || t.contains("docker-desktop")
        || t.contains("docker desktop")
        || t.contains("rancher-desktop")
    {
        return ClusterKind::Local;
    }
    ClusterKind::Unknown
}

/// Result of inspecting a pasted kubeconfig (or fragment) for cluster kind.
#[derive(Debug, Clone, Serialize)]
pub struct KubeconfigInfer {
    pub kind: ClusterKind,
    pub confidence: &'static str,
    pub context_names: Vec<String>,
    pub cluster_names: Vec<String>,
    pub signals: Vec<String>,
    pub guidance: String,
}

/// Infer cluster kind from a full kubeconfig paste (YAML).
///
/// Detects exec plugins and server URLs used by EKS / GKE / AKS / kind / k3s.
/// Falls back to [`ClusterKind::Local`] for generic kubeconfig without cloud markers.
pub fn infer_cluster_kind_from_kubeconfig(paste: &str) -> KubeconfigInfer {
    let t = paste.to_ascii_lowercase();
    let mut signals = Vec::new();
    let contexts = extract_kube_names(paste, "contexts");
    let clusters = extract_kube_names(paste, "clusters");

    // EKS: aws eks get-token exec, or arn:aws:eks, or *.eks.amazonaws.com
    if t.contains("eks get-token")
        || t.contains("aws eks")
        || t.contains("arn:aws:eks:")
        || t.contains(".eks.amazonaws.com")
        || t.contains("eks.amazonaws.com")
    {
        signals.push("aws eks get-token / EKS ARN or endpoint".into());
        return KubeconfigInfer {
            kind: ClusterKind::Eks,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig is EKS-style (exec aws eks get-token). Store AWS short-lived STS \
                       on the linked aws-* profile; do not treat this paste as the long-term secret alone."
                .into(),
        };
    }

    // GKE: gke-gcloud-auth-plugin, gke_ project, container.googleapis.com
    if t.contains("gke-gcloud-auth-plugin")
        || t.contains("gke_")
        || t.contains("container.googleapis.com")
        || t.contains("gcloud auth")
        || (t.contains("cmd-path") && t.contains("gcloud"))
    {
        signals.push("gke-gcloud-auth-plugin / GKE endpoint".into());
        return KubeconfigInfer {
            kind: ClusterKind::Gke,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig is GKE-style (gke-gcloud-auth-plugin). Prefer gcloud login/ADC or SA; \
                       install gke-gcloud-auth-plugin. Full kubeconfig is a fallback once GCP auth works."
                .into(),
        };
    }

    // AKS: kubelogin, login.microsoftonline.com, azure
    if t.contains("kubelogin")
        || t.contains("azurecli")
        || t.contains("login.microsoftonline.com")
        || t.contains("az aks")
        || t.contains("azure.com")
        || t.contains("msi-resourceid")
        || t.contains("aad-server-app-id")
        || t.contains("serverappid")
    {
        signals.push("kubelogin / Microsoft Entra AKS markers".into());
        return KubeconfigInfer {
            kind: ClusterKind::Aks,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig is AKS/Entra-style (kubelogin exec). Prefer az login; install kubelogin. \
                       Pasted kubeconfig works as fallback after Entra/az session is valid."
                .into(),
        };
    }

    // kind
    if t.contains("kind-")
        || contexts.iter().any(|c| c.starts_with("kind-"))
        || clusters.iter().any(|c| c.starts_with("kind-"))
    {
        signals.push("kind- context/cluster name".into());
        return KubeconfigInfer {
            kind: ClusterKind::Kind,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig looks like kind — store as local kubeconfig (no cloud STS).".into(),
        };
    }

    // k3s / k3d
    if t.contains("k3s") || t.contains("k3d") {
        signals.push("k3s/k3d marker".into());
        return KubeconfigInfer {
            kind: ClusterKind::K3s,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig looks like k3s/k3d — store as local kubeconfig.".into(),
        };
    }

    if t.contains("minikube") {
        signals.push("minikube marker".into());
        return KubeconfigInfer {
            kind: ClusterKind::Minikube,
            confidence: "high",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Kubeconfig looks like minikube — store as local kubeconfig.".into(),
        };
    }

    // Generic kubeconfig shape
    let looks_like_kc = t.contains("apiVersion:")
        && (t.contains("kind: config") || t.contains("clusters:") || t.contains("contexts:"));
    if looks_like_kc {
        signals.push("generic kubeconfig YAML".into());
        return KubeconfigInfer {
            kind: ClusterKind::Local,
            confidence: "medium",
            context_names: contexts,
            cluster_names: clusters,
            signals,
            guidance: "Generic kubeconfig — treat as local/self-managed. Store for the k8s profile."
                .into(),
        };
    }

    KubeconfigInfer {
        kind: ClusterKind::Unknown,
        confidence: "low",
        context_names: contexts,
        cluster_names: clusters,
        signals,
        guidance: "Could not infer cluster kind from paste — ask user: eks|gke|aks|kind|k3s|local."
            .into(),
    }
}

/// Pull rough context/cluster names from kubeconfig YAML without a full parser.
fn extract_kube_names(paste: &str, section: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_section = false;
    for line in paste.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(section) && trimmed.ends_with(':') {
            in_section = true;
            continue;
        }
        if in_section {
            // next top-level key ends section
            if !line.starts_with(' ') && !line.starts_with('\t') && trimmed.ends_with(':') && !trimmed.starts_with('-')
            {
                if !trimmed.starts_with('#') {
                    break;
                }
            }
            if let Some(rest) = trimmed.strip_prefix("- name:") {
                let name = rest.trim().trim_matches('"').trim_matches('\'').to_string();
                if !name.is_empty() {
                    out.push(name);
                }
            } else if trimmed.starts_with("name:") && line.starts_with("    ") {
                let name = trimmed
                    .trim_start_matches("name:")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                if !name.is_empty() && !out.contains(&name) {
                    out.push(name);
                }
            }
        }
    }
    out
}

/// Score how well `query` matches a candidate cluster/context name (0–100).
/// Users often give fragments (`2ptt`) not full ARNs or DNS names.
pub fn fuzzy_cluster_score(query: &str, candidate: &str) -> u32 {
    let q = query.trim().to_ascii_lowercase();
    let c = candidate.trim().to_ascii_lowercase();
    if q.is_empty() || c.is_empty() {
        return 0;
    }
    if q == c {
        return 100;
    }
    // strip common noise
    let c_clean = c
        .replace("arn:aws:eks:", "")
        .replace(":cluster/", "/")
        .replace("kind-", "");
    if c_clean == q || c.ends_with(&q) || c_clean.ends_with(&q) {
        return 95;
    }
    if c.contains(&q) || c_clean.contains(&q) {
        // longer fragment = better
        let ratio = (q.len() * 80 / c.len().max(1)).min(90) as u32;
        return 70 + ratio.min(20);
    }
    // token overlap (split on - _ / :)
    let q_toks: Vec<_> = q
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 2)
        .collect();
    let c_toks: Vec<_> = c
        .split(|ch: char| !ch.is_ascii_alphanumeric())
        .filter(|t| t.len() >= 2)
        .collect();
    if q_toks.is_empty() {
        return 0;
    }
    let hits = q_toks.iter().filter(|t| c_toks.iter().any(|ct| ct.contains(*t) || t.contains(ct))).count();
    if hits == 0 {
        return 0;
    }
    ((hits * 100) / q_toks.len()) as u32
}

/// Pick best cluster name matches for a user fragment.
///
/// Returns `(best, alternatives)` where best is unique high-confidence match.
pub fn resolve_cluster_name_fuzzy(
    query: &str,
    candidates: &[String],
) -> FuzzyClusterResolve {
    let mut scored: Vec<(u32, String)> = candidates
        .iter()
        .map(|c| (fuzzy_cluster_score(query, c), c.clone()))
        .filter(|(s, _)| *s >= 40)
        .collect();
    scored.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    scored.dedup_by(|a, b| a.1 == b.1);

    if scored.is_empty() {
        return FuzzyClusterResolve {
            query: query.to_string(),
            best: None,
            confidence: "none",
            alternatives: vec![],
            note: format!(
                "No cluster name close to `{query}`. List clusters (aws eks list-clusters / kubectl config get-contexts) and match again."
            ),
        };
    }
    let top = scored[0].0;
    let best_name = scored[0].1.clone();
    let alts: Vec<String> = scored.iter().skip(1).take(5).map(|(_, n)| n.clone()).collect();

    // Unique if clear winner
    let unique = scored.len() == 1 || (scored.len() > 1 && top >= scored[1].0 + 15 && top >= 70);
    if unique && top >= 70 {
        FuzzyClusterResolve {
            query: query.to_string(),
            best: Some(best_name.clone()),
            confidence: if top >= 90 { "high" } else { "medium" },
            alternatives: alts,
            note: format!(
                "Inferred cluster `{best_name}` from fragment `{query}` (score {top}). Confirm if wrong."
            ),
        }
    } else {
        let names: Vec<_> = scored.iter().take(5).map(|(s, n)| format!("{n} ({s})")).collect();
        FuzzyClusterResolve {
            query: query.to_string(),
            best: if top >= 85 { Some(best_name) } else { None },
            confidence: "ambiguous",
            alternatives: scored.into_iter().take(5).map(|(_, n)| n).collect(),
            note: format!(
                "Fragment `{query}` matches multiple clusters: {}. Ask user or pick highest if clearly dominant.",
                names.join(", ")
            ),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct FuzzyClusterResolve {
    pub query: String,
    pub best: Option<String>,
    pub confidence: &'static str,
    pub alternatives: Vec<String>,
    pub note: String,
}

/// Auth surface for a cluster kind (what oscar asks the user to provide).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterAuthSurface {
    /// AWS short-lived STS / SSO (then `aws eks update-kubeconfig` + get-token).
    AwsShortLived,
    /// gcloud login / ADC (then `gcloud container clusters get-credentials`).
    GcpShortLived,
    /// az login / Entra (then `az aks get-credentials` + kubelogin).
    AzureShortLived,
    /// kubeconfig file or ambient context (kind/k3s/local).
    Kubeconfig,
    /// Kind unknown — do not prepare secrets yet.
    NeedClusterKind,
}

impl ClusterAuthSurface {
    pub fn for_kind(kind: ClusterKind) -> Self {
        match kind {
            ClusterKind::Eks => Self::AwsShortLived,
            ClusterKind::Gke => Self::GcpShortLived,
            ClusterKind::Aks => Self::AzureShortLived,
            ClusterKind::Kind
            | ClusterKind::K3s
            | ClusterKind::Minikube
            | ClusterKind::K0s
            | ClusterKind::Local => Self::Kubeconfig,
            ClusterKind::Unknown => Self::NeedClusterKind,
        }
    }
}

/// Structured plan returned by `system.cluster.prepare` / helpers.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterAuthPlan {
    pub cluster_kind: ClusterKind,
    pub auth_surface: ClusterAuthSurface,
    pub needs_user_clarification: bool,
    pub clarification_question: Option<String>,
    pub k8s_profile_id: String,
    pub linked_cloud_profile_id: Option<String>,
    pub cluster: ClusterRef,
    pub kubeconfig_path: Option<String>,
    pub secret_kinds: Vec<SecretKind>,
    pub guidance: String,
    pub next_steps: Vec<String>,
    pub setup_commands: Vec<String>,
}

/// Path for oscar-managed kubeconfig for a k8s profile.
pub fn oscar_kubeconfig_path(paths: &Paths, k8s_profile_id: &str) -> PathBuf {
    paths
        .config_dir
        .join("kube")
        .join(format!("{k8s_profile_id}.yaml"))
}

/// Build clarification when kind is missing.
pub fn need_kind_question(label: &str) -> String {
    format!(
        "Which kind of Kubernetes cluster is `{label}`? \
         Reply with one of: **eks** (AWS short-term creds), **gke** (GCP short-term), \
         **aks** (Azure short-term), **kind**, **k3s**/k3d, **minikube**, **k0s**, \
         or **local**/kubeconfig-only. Auth setup differs by type."
    )
}

/// Build an [`AuthRequest`] for the linked cloud profile (managed clusters)
/// or kubeconfig secret (local).
pub fn auth_request_for_cluster_plan(plan: &ClusterAuthPlan) -> Option<AuthRequest> {
    if plan.needs_user_clarification {
        return None;
    }
    match plan.auth_surface {
        ClusterAuthSurface::NeedClusterKind => None,
        ClusterAuthSurface::AwsShortLived => {
            let pid = plan
                .linked_cloud_profile_id
                .clone()
                .unwrap_or_else(|| "aws-default".into());
            Some(
                AuthRequest::new(
                    Cloud::Aws,
                    format!(
                        "EKS cluster `{}` needs short-lived AWS credentials on profile `{pid}` \
                         (kubectl uses `aws eks get-token` — tokens are not stored)",
                        plan.cluster.name
                    ),
                    vec![
                        SecretKind::AccessKeyId,
                        SecretKind::SecretAccessKey,
                        SecretKind::SessionToken,
                    ],
                )
                .profile(pid)
                .with_guidance(
                    "Paste STS session for the AWS account that owns the EKS cluster \
                     (or complete SSO). Oscar will not store EKS bearer tokens — only AWS session.",
                )
                .with_hints(plan.next_steps.clone()),
            )
        }
        ClusterAuthSurface::GcpShortLived => {
            let pid = plan
                .linked_cloud_profile_id
                .clone()
                .unwrap_or_else(|| "gcp-default".into());
            Some(
                AuthRequest::new(
                    Cloud::Gcp,
                    format!(
                        "GKE cluster `{}` needs GCP credentials (gcloud/ADC or SA) on profile `{pid}`",
                        plan.cluster.name
                    ),
                    vec![SecretKind::ServiceAccountJson],
                )
                .profile(pid)
                .with_guidance(
                    "Prefer `gcloud auth login` / ADC for short-lived user creds. \
                     Or store SA JSON for this profile — never paste into chat.",
                )
                .with_hints(plan.next_steps.clone()),
            )
        }
        ClusterAuthSurface::AzureShortLived => {
            let pid = plan
                .linked_cloud_profile_id
                .clone()
                .unwrap_or_else(|| "azure-default".into());
            Some(
                AuthRequest::new(
                    Cloud::Azure,
                    format!(
                        "AKS cluster `{}` needs Azure credentials (`az login` / Entra) on profile `{pid}`",
                        plan.cluster.name
                    ),
                    vec![
                        SecretKind::AzureTenantId,
                        SecretKind::AzureClientId,
                        SecretKind::AzureClientSecret,
                    ],
                )
                .profile(pid)
                .with_guidance(
                    "Prefer `az login` (browser/device). AKS uses kubelogin/exec for short-lived tokens.",
                )
                .with_hints(plan.next_steps.clone()),
            )
        }
        ClusterAuthSurface::Kubeconfig => Some(
            AuthRequest::new(
                Cloud::K8s,
                format!(
                    "Local/self-managed cluster `{}` ({}) needs a kubeconfig context or file",
                    plan.cluster.name,
                    plan.cluster_kind
                ),
                vec![SecretKind::Kubeconfig],
            )
            .profile(plan.k8s_profile_id.clone())
            .with_guidance(
                "For kind/k3s/minikube/local: point kubectl at the cluster context, or paste/store \
                 kubeconfig for this k8s profile. No cloud STS required.",
            )
            .with_hints(plan.next_steps.clone()),
        ),
    }
}

/// Construct a full prepare plan (does not write profiles — caller does).
pub fn build_cluster_auth_plan(
    paths: &Paths,
    kind: ClusterKind,
    label: &str,
    cluster_name: &str,
    region: Option<&str>,
    context: Option<&str>,
    linked_cloud_profile_id: Option<&str>,
    k8s_profile_id: &str,
) -> ClusterAuthPlan {
    let surface = ClusterAuthSurface::for_kind(kind);
    if matches!(surface, ClusterAuthSurface::NeedClusterKind) {
        return ClusterAuthPlan {
            cluster_kind: kind,
            auth_surface: surface,
            needs_user_clarification: true,
            clarification_question: Some(need_kind_question(label)),
            k8s_profile_id: k8s_profile_id.to_string(),
            linked_cloud_profile_id: None,
            cluster: ClusterRef::new(cluster_name).with_kind(ClusterKind::Unknown),
            kubeconfig_path: None,
            secret_kinds: vec![],
            guidance: need_kind_question(label),
            next_steps: vec![
                "Ask the user: eks | gke | aks | kind | k3s | minikube | k0s | local".into(),
                format!("Then: system.cluster.prepare cluster_kind=<kind> label={label}"),
            ],
            setup_commands: vec![],
        };
    }

    let kube_path = oscar_kubeconfig_path(paths, k8s_profile_id);
    let kube_path_s = kube_path.display().to_string();
    let region = region.unwrap_or("us-east-1");
    let ctx = context.unwrap_or(cluster_name);

    let mut cluster = ClusterRef::new(cluster_name)
        .with_kind(kind)
        .with_context(ctx)
        .with_region(region);
    cluster.kubeconfig_path = Some(kube_path_s.clone());

    let (linked, secret_kinds, guidance, next_steps, setup_commands) = match kind {
        ClusterKind::Eks => {
            let aws_pid = linked_cloud_profile_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| Profile::make_id(Cloud::Aws, label));
            cluster.linked_cloud_profile_id = Some(aws_pid.clone());
            (
                Some(aws_pid.clone()),
                vec![
                    SecretKind::AccessKeyId,
                    SecretKind::SecretAccessKey,
                    SecretKind::SessionToken,
                ],
                format!(
                    "EKS uses **AWS short-lived credentials** on `{aws_pid}`. \
                     After STS is stored, run update-kubeconfig into oscar's kubeconfig; \
                     kubectl refreshes tokens via `aws eks get-token` (not stored in oscar)."
                ),
                vec![
                    format!(
                        "oscar auth aws-session --profile {aws_pid} --access-key-id … --secret-access-key … --session-token …"
                    ),
                    format!("oscar auth aws-sso-login --profile {aws_pid}"),
                    format!("oscar auth aws-test --profile {aws_pid}"),
                    "TUI secure bar: paste export AWS_* block for the account that owns EKS".into(),
                ],
                vec![
                    format!(
                        "aws eks update-kubeconfig --name {cluster_name} --region {region} --kubeconfig {kube_path_s}"
                    ),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
            )
        }
        ClusterKind::Gke => {
            let gcp_pid = linked_cloud_profile_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| Profile::make_id(Cloud::Gcp, label));
            cluster.linked_cloud_profile_id = Some(gcp_pid.clone());
            (
                Some(gcp_pid.clone()),
                vec![SecretKind::ServiceAccountJson],
                format!(
                    "GKE (common path): **gcloud auth login** / ADC, install **gke-gcloud-auth-plugin**, \
                     then `gcloud container clusters get-credentials` (writes exec plugin kubeconfig; \
                     short-lived tokens). SA JSON on `{gcp_pid}` is an automation fallback. \
                     Pasted full kubeconfig also works if plugin + ADC are present."
                ),
                vec![
                    "oscar auth gcloud-login".into(),
                    "oscar auth gcloud-login --adc".into(),
                    "gcloud components install gke-gcloud-auth-plugin".into(),
                    format!("oscar auth gcp-sa --profile {gcp_pid} --file /path/to/sa.json"),
                ],
                vec![
                    format!(
                        "gcloud container clusters get-credentials {cluster_name} --region {region} --project <project>"
                    ),
                    format!(
                        "# ensure plugin: gcloud components install gke-gcloud-auth-plugin"
                    ),
                    format!("kubectl config view --minify --flatten > {kube_path_s}"),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
            )
        }
        ClusterKind::Aks => {
            let az_pid = linked_cloud_profile_id
                .map(|s| s.to_string())
                .unwrap_or_else(|| Profile::make_id(Cloud::Azure, label));
            cluster.linked_cloud_profile_id = Some(az_pid.clone());
            (
                Some(az_pid.clone()),
                vec![
                    SecretKind::AzureTenantId,
                    SecretKind::AzureClientId,
                    SecretKind::AzureClientSecret,
                ],
                format!(
                    "AKS (common path): **az login** (Microsoft Entra) then \
                     `az aks get-credentials` which writes kubeconfig with **kubelogin** exec \
                     (K8s ≥1.24). Tokens are short-lived; install kubelogin via `az aks install-cli`. \
                     Fallback: paste full kubeconfig after convert-kubeconfig. Profile `{az_pid}`."
                ),
                vec![
                    "oscar auth az-login".into(),
                    format!("oscar auth az-login --tenant <tenant>  # profile {az_pid}"),
                    "az aks install-cli   # kubectl + kubelogin".into(),
                    "kubelogin convert-kubeconfig -l azurecli  # if needed".into(),
                ],
                vec![
                    format!(
                        "az aks get-credentials --resource-group <rg> --name {cluster_name} --file {kube_path_s}"
                    ),
                    format!("kubelogin convert-kubeconfig --kubeconfig {kube_path_s} -l azurecli"),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
            )
        }
        ClusterKind::Kind
        | ClusterKind::K3s
        | ClusterKind::Minikube
        | ClusterKind::K0s
        | ClusterKind::Local => (
            None,
            vec![SecretKind::Kubeconfig],
            format!(
                "**{kind}** is local/self-managed: auth is **kubeconfig only** (no cloud STS). \
                 Point oscar at the existing context or store kubeconfig for `{k8s_profile_id}`."
            ),
            vec![
                "kubectl config get-contexts".into(),
                format!("kubectl config use-context {ctx}"),
                format!(
                    "# or copy context into oscar kubeconfig: kubectl config view --minify --flatten > {kube_path_s}"
                ),
                "TUI secure bar may accept kubeconfig paste for this k8s profile".into(),
            ],
            match kind {
                ClusterKind::Kind => vec![
                    format!("kind get kubeconfig --name {cluster_name} > {kube_path_s}"),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
                ClusterKind::K3s => vec![
                    "# k3s: use /etc/rancher/k3s/k3s.yaml or k3d kubeconfig write".into(),
                    format!("k3d kubeconfig get {cluster_name} > {kube_path_s}  # if k3d"),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
                ClusterKind::Minikube => vec![
                    format!("minikube update-context -p {cluster_name}"),
                    format!(
                        "kubectl config view --minify --flatten --context={cluster_name} > {kube_path_s}"
                    ),
                ],
                _ => vec![
                    format!(
                        "kubectl config view --minify --flatten --context={ctx} > {kube_path_s}"
                    ),
                    format!("kubectl --kubeconfig {kube_path_s} cluster-info"),
                ],
            },
        ),
        ClusterKind::Unknown => unreachable!(),
    };

    ClusterAuthPlan {
        cluster_kind: kind,
        auth_surface: surface,
        needs_user_clarification: false,
        clarification_question: None,
        k8s_profile_id: k8s_profile_id.to_string(),
        linked_cloud_profile_id: linked,
        cluster,
        kubeconfig_path: Some(kube_path_s),
        secret_kinds,
        guidance,
        next_steps,
        setup_commands,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn infer_eks_gke_local() {
        assert_eq!(infer_cluster_kind("our prod EKS in us-east-1"), ClusterKind::Eks);
        assert_eq!(infer_cluster_kind("gke-dev-cluster"), ClusterKind::Gke);
        assert_eq!(infer_cluster_kind("kind create cluster"), ClusterKind::Kind);
        assert_eq!(infer_cluster_kind("k3d local"), ClusterKind::K3s);
        assert_eq!(infer_cluster_kind("the cluster"), ClusterKind::Unknown);
    }

    #[test]
    fn infer_from_kubeconfig_paste() {
        let eks = r#"
apiVersion: v1
kind: Config
clusters:
- name: arn:aws:eks:us-east-1:123:cluster/foo-2ptt
  cluster:
    server: https://XXXX.yl4.us-east-1.eks.amazonaws.com
users:
- name: arn:aws:eks:us-east-1:123:cluster/foo
  user:
    exec:
      command: aws
      args: [eks, get-token, --cluster-name, foo]
"#;
        let i = infer_cluster_kind_from_kubeconfig(eks);
        assert_eq!(i.kind, ClusterKind::Eks);
        assert_eq!(i.confidence, "high");

        let gke = r#"
apiVersion: v1
kind: Config
users:
- name: gke_proj_us_cluster
  user:
    exec:
      command: gke-gcloud-auth-plugin
"#;
        assert_eq!(infer_cluster_kind_from_kubeconfig(gke).kind, ClusterKind::Gke);

        let aks = r#"
apiVersion: v1
kind: Config
users:
- name: clusterUser_rg_aks
  user:
    exec:
      command: kubelogin
      args: [get-token, --login, azurecli]
"#;
        assert_eq!(infer_cluster_kind_from_kubeconfig(aks).kind, ClusterKind::Aks);

        let kind = r#"
apiVersion: v1
kind: Config
contexts:
- name: kind-oscar-test
  context: {cluster: kind-oscar-test, user: kind-oscar-test}
"#;
        assert_eq!(infer_cluster_kind_from_kubeconfig(kind).kind, ClusterKind::Kind);
    }

    #[test]
    fn fuzzy_2ptt_matches_cluster() {
        let cands = vec![
            "prod-app-2ptt-eks".into(),
            "staging-other".into(),
            "dev-2ptt-code".into(),
        ];
        let r = resolve_cluster_name_fuzzy("2ptt", &cands);
        assert!(r.best.is_some() || !r.alternatives.is_empty());
        // both 2ptt clusters score; either best set or ambiguous with alts
        let all: Vec<_> = r
            .best
            .iter()
            .chain(r.alternatives.iter())
            .cloned()
            .collect();
        assert!(all.iter().any(|n| n.contains("2ptt")));
        assert_eq!(fuzzy_cluster_score("2ptt", "prod-app-2ptt-eks"), fuzzy_cluster_score("2ptt", "prod-app-2ptt-eks"));
        assert!(fuzzy_cluster_score("2ptt", "prod-app-2ptt-eks") >= 70);
        assert!(fuzzy_cluster_score("2ptt", "staging-other") < 40);
    }

    #[test]
    fn surface_mapping() {
        assert_eq!(
            ClusterAuthSurface::for_kind(ClusterKind::Eks),
            ClusterAuthSurface::AwsShortLived
        );
        assert_eq!(
            ClusterAuthSurface::for_kind(ClusterKind::Kind),
            ClusterAuthSurface::Kubeconfig
        );
        assert_eq!(
            ClusterAuthSurface::for_kind(ClusterKind::Unknown),
            ClusterAuthSurface::NeedClusterKind
        );
    }

    #[test]
    fn unknown_plan_asks() {
        let paths = Paths {
            config_dir: PathBuf::from("/tmp/oscar-test"),
            config_file: PathBuf::from("/tmp/oscar-test/config.toml"),
            profiles_file: PathBuf::from("/tmp/oscar-test/profiles.toml"),
            sessions_dir: PathBuf::from("/tmp/oscar-test/sessions"),
            artifacts_dir: PathBuf::from("/tmp/oscar-test/artifacts"),
            logs_dir: PathBuf::from("/tmp/oscar-test/logs"),
            mcp_credentials_file: PathBuf::from("/tmp/oscar-test/mcp.json"),
            auth_file: PathBuf::from("/tmp/oscar-test/auth.json"),
        };
        let plan = build_cluster_auth_plan(
            &paths,
            ClusterKind::Unknown,
            "prod",
            "prod",
            None,
            None,
            None,
            "k8s-prod",
        );
        assert!(plan.needs_user_clarification);
        assert!(plan.clarification_question.is_some());
        assert!(auth_request_for_cluster_plan(&plan).is_none());
    }

    #[test]
    fn eks_plan_links_aws() {
        let paths = Paths {
            config_dir: PathBuf::from("/tmp/oscar-test"),
            config_file: PathBuf::from("/tmp/oscar-test/config.toml"),
            profiles_file: PathBuf::from("/tmp/oscar-test/profiles.toml"),
            sessions_dir: PathBuf::from("/tmp/oscar-test/sessions"),
            artifacts_dir: PathBuf::from("/tmp/oscar-test/artifacts"),
            logs_dir: PathBuf::from("/tmp/oscar-test/logs"),
            mcp_credentials_file: PathBuf::from("/tmp/oscar-test/mcp.json"),
            auth_file: PathBuf::from("/tmp/oscar-test/auth.json"),
        };
        let plan = build_cluster_auth_plan(
            &paths,
            ClusterKind::Eks,
            "sandbox",
            "my-eks",
            Some("us-east-1"),
            None,
            Some("aws-sandbox"),
            "k8s-sandbox",
        );
        assert!(!plan.needs_user_clarification);
        assert_eq!(plan.linked_cloud_profile_id.as_deref(), Some("aws-sandbox"));
        assert!(plan
            .setup_commands
            .iter()
            .any(|c| c.contains("eks update-kubeconfig")));
        let auth = auth_request_for_cluster_plan(&plan).unwrap();
        assert_eq!(auth.cloud, Cloud::Aws);
    }
}

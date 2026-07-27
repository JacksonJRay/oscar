//! System binary inventory for the agent.
//!
//! On agent start (and via `oscar binaries`), oscar builds a snapshot of CLIs on
//! PATH that tools may invoke. First-class tools declare required binaries;
//! search/execute gate on this inventory so the agent knows what is feasible:
//! first-class tool vs CLI binary vs API-only fallback.

use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Role of a binary for agent planning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BinaryRole {
    /// Cloud provider CLI (aws, gcloud, az, …)
    CspCli,
    /// Kubernetes / cluster tooling
    Kubernetes,
    /// Network / CNI / observability
    Network,
    /// Infra as code / packaging
    Infra,
    /// Security / identity
    Security,
    /// General shell/ops utility
    General,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInfo {
    pub name: String,
    pub present: bool,
    pub path: Option<String>,
    pub version_hint: Option<String>,
    pub role: BinaryRole,
    /// Short note for the agent (what this binary enables).
    pub agent_use: String,
}

/// Snapshot of tooling available when the agent session starts.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryInventory {
    /// Unix epoch seconds when this inventory was built.
    pub built_at_unix: u64,
    pub binaries: Vec<BinaryInfo>,
    /// Present names only (fast lookup list for the agent).
    pub available: Vec<String>,
    /// Catalog entries that are missing (agent should avoid CLI-gated tools).
    pub missing_critical: Vec<String>,
}

impl Default for BinaryInventory {
    fn default() -> Self {
        Self {
            built_at_unix: 0,
            binaries: vec![],
            available: vec![],
            missing_critical: vec![],
        }
    }
}

/// Curated catalog: name → (role, agent_use, critical for multi-cloud oscar).
fn catalog() -> &'static [(&'static str, BinaryRole, &'static str, bool)] {
    &[
        // CSP
        ("aws", BinaryRole::CspCli, "AWS CLI for Route53, EC2, Reachability Analyzer, STS", true),
        ("gcloud", BinaryRole::CspCli, "Google Cloud CLI for Cloud DNS, Connectivity Tests, projects", true),
        ("az", BinaryRole::CspCli, "Azure CLI for DNS, Network Watcher, ARM resources", true),
        ("doctl", BinaryRole::CspCli, "DigitalOcean CLI", false),
        ("oci", BinaryRole::CspCli, "Oracle Cloud CLI", false),
        // K8s
        ("kubectl", BinaryRole::Kubernetes, "Kubernetes API via kubeconfig; cluster inventory/pivot", true),
        ("helm", BinaryRole::Kubernetes, "Helm charts / releases", false),
        ("k9s", BinaryRole::Kubernetes, "Interactive cluster TUI (optional)", false),
        ("stern", BinaryRole::Kubernetes, "Multi-pod log tail", false),
        ("kubectx", BinaryRole::Kubernetes, "Fast kube context switch", false),
        ("kubens", BinaryRole::Kubernetes, "Fast namespace switch", false),
        ("kustomize", BinaryRole::Kubernetes, "Kustomize builds", false),
        // CNI / network observability
        ("cilium", BinaryRole::Network, "Cilium CNI CLI", false),
        ("hubble", BinaryRole::Network, "Cilium Hubble flow observe", false),
        ("calicoctl", BinaryRole::Network, "Calico policy/IPAM diagnostics", false),
        ("istioctl", BinaryRole::Network, "Istio service mesh CLI", false),
        ("linkerd", BinaryRole::Network, "Linkerd mesh CLI", false),
        ("dig", BinaryRole::Network, "DNS lookup (public/resolver checks)", false),
        ("nslookup", BinaryRole::Network, "DNS lookup fallback", false),
        ("host", BinaryRole::Network, "DNS host lookup", false),
        ("traceroute", BinaryRole::Network, "Path tracing host tool", false),
        ("tracepath", BinaryRole::Network, "Path MTU / traceroute variant", false),
        ("mtr", BinaryRole::Network, "Combined traceroute/ping", false),
        ("nmap", BinaryRole::Network, "Port/path scanning (careful)", false),
        ("curl", BinaryRole::General, "HTTP(S) probes", false),
        ("wget", BinaryRole::General, "HTTP(S) fetch", false),
        ("nc", BinaryRole::Network, "netcat TCP/UDP checks", false),
        ("netcat", BinaryRole::Network, "netcat alias", false),
        ("ss", BinaryRole::Network, "Socket statistics", false),
        ("ip", BinaryRole::Network, "iproute2 interface/route dump", false),
        ("ping", BinaryRole::Network, "ICMP reachability", false),
        // Infra
        ("terraform", BinaryRole::Infra, "Terraform state/plan (read-only prefer)", false),
        ("tofu", BinaryRole::Infra, "OpenTofu", false),
        ("pulumi", BinaryRole::Infra, "Pulumi", false),
        ("ansible", BinaryRole::Infra, "Ansible", false),
        ("packer", BinaryRole::Infra, "Packer", false),
        ("docker", BinaryRole::Infra, "Docker engine CLI", false),
        ("podman", BinaryRole::Infra, "Podman", false),
        ("nerdctl", BinaryRole::Infra, "containerd nerdctl", false),
        ("crane", BinaryRole::Infra, "OCI image inspect", false),
        ("jq", BinaryRole::General, "JSON processing for CLI pipelines", false),
        ("yq", BinaryRole::General, "YAML processing", false),
        ("rg", BinaryRole::General, "ripgrep search", false),
        ("git", BinaryRole::General, "Git VCS", false),
        // Security / identity
        ("vault", BinaryRole::Security, "HashiCorp Vault", false),
        ("sops", BinaryRole::Security, "Secrets ops encrypt/decrypt", false),
        ("age", BinaryRole::Security, "age encryption", false),
        ("gpg", BinaryRole::Security, "GPG", false),
        ("ssh", BinaryRole::Security, "SSH client", false),
        ("openssl", BinaryRole::Security, "TLS/cert inspection", false),
    ]
}

/// Extra PATH basenames worth picking up if present (not full catalog).
fn path_scan_allowlist() -> &'static BTreeSet<&'static str> {
    static S: OnceLock<BTreeSet<&'static str>> = OnceLock::new();
    S.get_or_init(|| {
        let mut s = BTreeSet::new();
        for (name, _, _, _) in catalog() {
            s.insert(*name);
        }
        // common variants
        for n in [
            "aws-iam-authenticator",
            "eksctl",
            "kubelogin",
            "flux",
            "argocd",
            "helmfile",
            "k3s",
            "minikube",
            "kind",
            "skaffold",
            "tilt",
            "vault",
            "consul",
            "nomad",
            "boundary",
            "trivy",
            "grype",
            "syft",
            "cosign",
            "tfenv",
            "terragrunt",
            "infracost",
            "checkov",
            "kube-score",
            "popeye",
            "kubeseal",
            "sops",
            "direnv",
            "envsubst",
            "env",
            "bash",
            "zsh",
            "python3",
            "node",
            "go",
            "rustc",
            "cargo",
        ] {
            s.insert(n);
        }
        s
    })
}

impl BinaryInventory {
    /// Build inventory: curated catalog probes + PATH scan for allowlisted names.
    pub fn detect() -> Self {
        let mut by_name: BTreeMap<String, BinaryInfo> = BTreeMap::new();

        // 1) Curated catalog
        for (name, role, use_note, _) in catalog() {
            let info = probe(name, *role, use_note);
            by_name.entry(name.to_string()).or_insert(info);
        }

        // 2) PATH scan for allowlisted basenames (picks up installs not in first pass)
        for path in path_dirs() {
            if let Ok(rd) = fs::read_dir(&path) {
                for ent in rd.flatten() {
                    let name = ent.file_name().to_string_lossy().to_string();
                    if !path_scan_allowlist().contains(name.as_str()) {
                        // also accept aws-*, kubectl-* prefixes lightly
                        if !(name.starts_with("aws-")
                            || name.starts_with("kubectl-")
                            || name.starts_with("gcloud-"))
                        {
                            continue;
                        }
                    }
                    let p = ent.path();
                    if !is_executable(&p) {
                        continue;
                    }
                    if by_name.contains_key(&name) && by_name[&name].present {
                        continue;
                    }
                    let role = catalog()
                        .iter()
                        .find(|(n, _, _, _)| *n == name)
                        .map(|(_, r, _, _)| *r)
                        .unwrap_or(BinaryRole::General);
                    let use_note = catalog()
                        .iter()
                        .find(|(n, _, _, _)| *n == name)
                        .map(|(_, _, u, _)| *u)
                        .unwrap_or("Discovered on PATH; available for agent CLI use when gated");
                    let mut info = probe(&name, role, use_note);
                    if info.path.is_none() {
                        info.path = Some(p.display().to_string());
                        info.present = true;
                    }
                    by_name.insert(name, info);
                }
            }
        }

        let mut binaries: Vec<BinaryInfo> = by_name.into_values().collect();
        binaries.sort_by(|a, b| a.name.cmp(&b.name));

        let available: Vec<String> = binaries
            .iter()
            .filter(|b| b.present)
            .map(|b| b.name.clone())
            .collect();

        let missing_critical: Vec<String> = catalog()
            .iter()
            .filter(|(_, _, _, crit)| *crit)
            .filter(|(n, _, _, _)| !available.iter().any(|a| a == *n))
            .map(|(n, _, _, _)| (*n).to_string())
            .collect();

        let built_at_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Self {
            built_at_unix,
            binaries,
            available,
            missing_critical,
        }
    }

    pub fn has(&self, name: &str) -> bool {
        self.available.iter().any(|a| a == name)
    }

    pub fn has_aws(&self) -> bool {
        self.has("aws")
    }
    pub fn has_gcloud(&self) -> bool {
        self.has("gcloud")
    }
    pub fn has_az(&self) -> bool {
        self.has("az")
    }
    pub fn has_kubectl(&self) -> bool {
        self.has("kubectl")
    }

    /// All required names present?
    pub fn has_all(&self, names: &[&str]) -> bool {
        names.iter().all(|n| self.has(n))
    }

    pub fn missing_of(&self, names: &[&str]) -> Vec<String> {
        names
            .iter()
            .filter(|n| !self.has(n))
            .map(|n| (*n).to_string())
            .collect()
    }

    /// Compact agent-facing summary for system prompt.
    pub fn agent_summary(&self) -> String {
        let mut lines = Vec::new();
        lines.push("## Binary inventory (built at session start)".to_string());
        lines.push(format!(
            "Available ({}): {}",
            self.available.len(),
            if self.available.is_empty() {
                "(none)".into()
            } else {
                self.available.join(", ")
            }
        ));
        if !self.missing_critical.is_empty() {
            lines.push(format!(
                "Missing critical CSP CLIs: {} — tools needing these will report binary_missing; prefer install or API/fallback paths.",
                self.missing_critical.join(", ")
            ));
        }
        lines.push(
            "Feasibility: prefer first-class oscar tools; use CLI binaries only when inventory marks them present; if binary missing, do not invent shell commands — report install need or use API-capable tools.".into(),
        );

        // Group present by role for planning
        let mut by_role: BTreeMap<String, Vec<&str>> = BTreeMap::new();
        for b in &self.binaries {
            if !b.present {
                continue;
            }
            by_role
                .entry(format!("{:?}", b.role).to_ascii_lowercase())
                .or_default()
                .push(b.name.as_str());
        }
        for (role, names) in by_role {
            lines.push(format!("  {role}: {}", names.join(", ")));
        }
        lines.join("\n")
    }

    /// Machine-readable slice for tools_search gating responses.
    pub fn feasibility_json(&self) -> serde_json::Value {
        serde_json::json!({
            "built_at_unix": self.built_at_unix,
            "available": self.available,
            "missing_critical": self.missing_critical,
            "binaries": self.binaries.iter().filter(|b| b.present).map(|b| serde_json::json!({
                "name": b.name,
                "path": b.path,
                "role": b.role,
                "agent_use": b.agent_use,
                "version_hint": b.version_hint,
            })).collect::<Vec<_>>(),
        })
    }
}

fn path_dirs() -> Vec<PathBuf> {
    env::var_os("PATH")
        .map(|p| env::split_paths(&p).collect())
        .unwrap_or_default()
}

fn is_executable(path: &Path) -> bool {
    #[cfg(unix)]
    {
        fs::metadata(path)
            .map(|m| m.is_file() && (m.permissions().mode() & 0o111) != 0)
            .unwrap_or(false)
    }
    #[cfg(not(unix))]
    {
        // Windows: presence as a file (or .exe sibling) is enough; no Unix mode bits.
        path.is_file()
            || path.with_extension("exe").is_file()
            || path.with_extension("cmd").is_file()
            || path.with_extension("bat").is_file()
    }
}

/// Resolve `name` on PATH in a cross-platform way.
fn which_on_path(name: &str) -> Option<String> {
    #[cfg(unix)]
    {
        Command::new("sh")
            .arg("-c")
            .arg(format!("command -v {name}"))
            .output()
            .ok()
            .filter(|o| o.status.success())
            .and_then(|o| {
                let s = String::from_utf8_lossy(&o.stdout).trim().to_string();
                if s.is_empty() {
                    None
                } else {
                    Some(s)
                }
            })
    }
    #[cfg(not(unix))]
    {
        // Prefer `where.exe` (Windows); fall back to walking PATH.
        if let Ok(o) = Command::new("where.exe").arg(name).output() {
            if o.status.success() {
                let s = String::from_utf8_lossy(&o.stdout)
                    .lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if !s.is_empty() {
                    return Some(s);
                }
            }
        }
        for dir in path_dirs() {
            for cand in [
                dir.join(name),
                dir.join(format!("{name}.exe")),
                dir.join(format!("{name}.cmd")),
                dir.join(format!("{name}.bat")),
            ] {
                if cand.is_file() {
                    return Some(cand.display().to_string());
                }
            }
        }
        None
    }
}

fn probe(name: &str, role: BinaryRole, agent_use: &str) -> BinaryInfo {
    let path = which_on_path(name);

    let present = path.is_some();
    let version_hint = if present {
        let args: &[&str] = match name {
            "kubectl" => &["version", "--client", "--output=yaml"],
            "helm" => &["version", "--short"],
            "terraform" | "tofu" => &["version"],
            "git" => &["--version"],
            "python3" => &["--version"],
            _ => &["--version"],
        };
        Command::new(name)
            .args(args)
            .output()
            .ok()
            .map(|o| {
                let out = if o.stdout.is_empty() {
                    String::from_utf8_lossy(&o.stderr)
                } else {
                    String::from_utf8_lossy(&o.stdout)
                };
                out.lines()
                    .next()
                    .unwrap_or("")
                    .trim()
                    .chars()
                    .take(100)
                    .collect()
            })
            .filter(|s: &String| !s.is_empty() && !s.starts_with("error:"))
    } else {
        None
    };

    BinaryInfo {
        name: name.into(),
        present,
        path,
        version_hint,
        role,
        agent_use: agent_use.into(),
    }
}

/// Map first-class tool_id → required PATH binaries (empty = pure first-class / no CLI).
pub fn required_binaries_for_tool(tool_id: &str) -> Vec<&'static str> {
    // MCP tools are process-backed, not host PATH binaries
    if tool_id.starts_with("mcp.") {
        return vec![];
    }
    if tool_id.starts_with("aws.") {
        return vec!["aws"];
    }
    if tool_id.starts_with("gcp.") {
        return vec!["gcloud"];
    }
    if tool_id.starts_with("azure.") {
        return vec!["az"];
    }
    if tool_id.starts_with("k8s.") {
        // Cache-only pattern tools can run without kubectl when inventory is warm.
        let cache_ok = tool_id.contains("pattern.search")
            || tool_id.contains("pattern") && tool_id.contains("search")
            || tool_id.ends_with(".pattern")
            || tool_id == "k8s.contexts.list";
        if cache_ok
            && !tool_id.contains("inventory")
            && !tool_id.contains("cni")
            && !tool_id.contains("hubble")
            && !tool_id.contains("calico")
            && !tool_id.contains("coredns")
            && !tool_id.contains("networkpolicy")
            && !tool_id.contains("cilium")
        {
            return vec![];
        }
        // Live cluster reads (inventory sync, CNI, CoreDNS, policy narratives)
        return vec!["kubectl"];
    }
    // multi-cloud DNS where: public resolver needs nothing; private needs at least one CSP CLI for sync
    if tool_id == "dns.pattern.find"
        || tool_id == "dns.where"
        || tool_id == "dns.inventory.sync"
        || tool_id == "dns.forwarding.map"
    {
        return vec![]; // soft: can use public resolver / cache
    }
    if tool_id == "network.pattern.find" {
        return vec![]; // cache only
    }
    if tool_id.starts_with("system.") || tool_id.starts_with("access.") {
        return vec![];
    }
    vec![]
}

/// How a tool can run given binary inventory.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ToolFeasibility {
    /// First-class tool ready (binaries OK or not required).
    Available,
    /// Runnable but degraded (e.g. multi-cloud without all CLIs).
    Degraded { missing: Vec<String>, note: String },
    /// Cannot use CLI path; install binary or use alternate approach.
    Unavailable {
        missing: Vec<String>,
        fallback: String,
    },
}

pub fn feasibility_for_tool(tool_id: &str, inv: &BinaryInventory) -> ToolFeasibility {
    let req = required_binaries_for_tool(tool_id);
    if req.is_empty() {
        return ToolFeasibility::Available;
    }
    let missing = inv.missing_of(&req);
    if missing.is_empty() {
        return ToolFeasibility::Available;
    }
    // Multi tools soft-degrade
    if tool_id.starts_with("dns.") || tool_id.starts_with("network.pattern") {
        return ToolFeasibility::Degraded {
            missing: missing.clone(),
            note: "Partial: public/cache paths may work; live CSP sync needs missing CLIs".into(),
        };
    }
    ToolFeasibility::Unavailable {
        missing,
        fallback: format!(
            "Install missing CLI(s) or use API-capable path if any; cannot run `{tool_id}` via binary backend"
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_builds_available_list() {
        let inv = BinaryInventory::detect();
        assert!(!inv.binaries.is_empty());
        // sh is not in catalog; aws entry exists as present or missing
        assert!(inv.binaries.iter().any(|b| b.name == "aws"));
        assert_eq!(inv.available.len(), inv.binaries.iter().filter(|b| b.present).count());
    }

    #[test]
    fn feasibility_aws_needs_aws_cli() {
        let mut inv = BinaryInventory::default();
        inv.available = vec![];
        match feasibility_for_tool("aws.network.path.analyze", &inv) {
            ToolFeasibility::Unavailable { missing, .. } => {
                assert!(missing.contains(&"aws".into()));
            }
            other => panic!("expected unavailable, got {other:?}"),
        }
        inv.available = vec!["aws".into()];
        assert_eq!(
            feasibility_for_tool("aws.network.path.analyze", &inv),
            ToolFeasibility::Available
        );
    }

    #[test]
    fn pattern_tools_without_cli_available() {
        let inv = BinaryInventory::default();
        assert_eq!(
            feasibility_for_tool("network.pattern.find", &inv),
            ToolFeasibility::Available
        );
        assert_eq!(
            feasibility_for_tool("k8s.pods.pattern.search", &inv),
            ToolFeasibility::Available
        );
        // Live CNI tools need kubectl
        match feasibility_for_tool("k8s.cni.detect", &inv) {
            ToolFeasibility::Unavailable { missing, .. } => {
                assert!(missing.iter().any(|m| m == "kubectl"));
            }
            other => panic!("expected unavailable without kubectl, got {other:?}"),
        }
    }
}

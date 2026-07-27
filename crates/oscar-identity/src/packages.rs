//! Package-manager plans for installing missing binaries (user-approved / elevated).

use crate::binaries::{required_binaries_for_tool, BinaryInventory};
use serde::{Deserialize, Serialize};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageManager {
    Apt,
    Dnf,
    Pacman,
    Brew,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstallPlan {
    pub package_manager: PackageManager,
    /// Logical binary names requested.
    pub binaries: Vec<String>,
    /// Distro package names (best-effort).
    pub packages: Vec<String>,
    /// Full shell commands (may include sudo).
    pub commands: Vec<String>,
    /// Non-elevated alternate commands when possible.
    pub user_commands: Vec<String>,
    pub notes: Vec<String>,
}

impl PackageManager {
    pub fn detect() -> Self {
        if which("brew") {
            return Self::Brew;
        }
        if which("apt-get") || which("apt") {
            return Self::Apt;
        }
        if which("dnf") {
            return Self::Dnf;
        }
        if which("pacman") {
            return Self::Pacman;
        }
        Self::Unknown
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::Pacman => "pacman",
            Self::Brew => "brew",
            Self::Unknown => "unknown",
        }
    }
}

fn which(name: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {name}"))
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Map binary name → package name for a package manager.
fn package_for(binary: &str, pm: PackageManager) -> Option<&'static str> {
    match (binary, pm) {
        ("aws", PackageManager::Apt) => Some("awscli"),
        ("aws", PackageManager::Dnf) => Some("awscli"),
        ("aws", PackageManager::Pacman) => Some("aws-cli"),
        ("aws", PackageManager::Brew) => Some("awscli"),
        ("gcloud", PackageManager::Brew) => Some("google-cloud-sdk"),
        // apt google-cloud-cli often via google's repo; still list
        ("gcloud", PackageManager::Apt) => Some("google-cloud-cli"),
        ("az", PackageManager::Apt) => Some("azure-cli"),
        ("az", PackageManager::Dnf) => Some("azure-cli"),
        ("az", PackageManager::Brew) => Some("azure-cli"),
        ("kubectl", PackageManager::Apt) => Some("kubectl"),
        ("kubectl", PackageManager::Dnf) => Some("kubernetes-client"),
        ("kubectl", PackageManager::Pacman) => Some("kubectl"),
        ("kubectl", PackageManager::Brew) => Some("kubernetes-cli"),
        ("helm", PackageManager::Apt) => Some("helm"),
        ("helm", PackageManager::Brew) => Some("helm"),
        ("helm", PackageManager::Pacman) => Some("helm"),
        ("jq", PackageManager::Apt | PackageManager::Dnf | PackageManager::Pacman) => Some("jq"),
        ("jq", PackageManager::Brew) => Some("jq"),
        ("curl", PackageManager::Apt | PackageManager::Dnf) => Some("curl"),
        ("curl", PackageManager::Brew) => Some("curl"),
        ("dig", PackageManager::Apt) => Some("dnsutils"),
        ("dig", PackageManager::Dnf) => Some("bind-utils"),
        ("dig", PackageManager::Pacman) => Some("bind"),
        ("dig", PackageManager::Brew) => Some("bind"),
        ("mtr", PackageManager::Apt | PackageManager::Dnf | PackageManager::Pacman) => Some("mtr"),
        ("mtr", PackageManager::Brew) => Some("mtr"),
        ("git", PackageManager::Apt | PackageManager::Dnf | PackageManager::Pacman) => Some("git"),
        ("git", PackageManager::Brew) => Some("git"),
        _ => None,
    }
}

/// Build install plan for missing binaries among `wanted`.
pub fn plan_install(wanted: &[String], inv: &BinaryInventory) -> InstallPlan {
    let missing: Vec<String> = wanted
        .iter()
        .filter(|b| !inv.has(b))
        .cloned()
        .collect();
    let pm = PackageManager::detect();
    let mut packages = Vec::new();
    let mut notes = Vec::new();
    for b in &missing {
        if let Some(pkg) = package_for(b, pm) {
            if !packages.iter().any(|p| p == pkg) {
                packages.push(pkg.to_string());
            }
        } else {
            notes.push(format!(
                "no known package mapping for `{b}` on {} — install manually",
                pm.as_str()
            ));
        }
    }
    if matches!(pm, PackageManager::Unknown) {
        notes.push("no supported package manager detected (apt/dnf/pacman/brew)".into());
    }
    if missing.iter().any(|b| b == "gcloud") && matches!(pm, PackageManager::Apt | PackageManager::Dnf) {
        notes.push(
            "gcloud on Linux often needs Google's apt/yum repo — see https://cloud.google.com/sdk/docs/install"
                .into(),
        );
    }
    if missing.iter().any(|b| b == "aws") && matches!(pm, PackageManager::Apt) {
        notes.push(
            "awscli apt package may be v1; prefer official AWS CLI v2 installer if needed".into(),
        );
    }

    let mut commands = Vec::new();
    let mut user_commands = Vec::new();
    if !packages.is_empty() {
        match pm {
            PackageManager::Apt => {
                let pkgs = packages.join(" ");
                commands.push(format!("sudo apt-get update && sudo apt-get install -y {pkgs}"));
                user_commands.push(format!("sudo apt-get update && sudo apt-get install -y {pkgs}"));
            }
            PackageManager::Dnf => {
                let pkgs = packages.join(" ");
                commands.push(format!("sudo dnf install -y {pkgs}"));
                user_commands.push(format!("sudo dnf install -y {pkgs}"));
            }
            PackageManager::Pacman => {
                let pkgs = packages.join(" ");
                commands.push(format!("sudo pacman -S --noconfirm {pkgs}"));
                user_commands.push(format!("sudo pacman -S --noconfirm {pkgs}"));
            }
            PackageManager::Brew => {
                let pkgs = packages.join(" ");
                // brew typically no sudo
                let c = format!("brew install {pkgs}");
                commands.push(c.clone());
                user_commands.push(c);
            }
            PackageManager::Unknown => {}
        }
    }

    InstallPlan {
        package_manager: pm,
        binaries: missing,
        packages,
        commands,
        user_commands,
        notes,
    }
}

/// Binaries required by a set of enabled first-class tool ids.
pub fn binaries_for_tools(tool_ids: &[String]) -> Vec<String> {
    let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for id in tool_ids {
        for b in required_binaries_for_tool(id) {
            set.insert(b.to_string());
        }
    }
    set.into_iter().collect()
}

/// Critical CSP binaries for multi-cloud oscar.
pub fn critical_csp_binaries() -> Vec<String> {
    vec!["aws".into(), "gcloud".into(), "az".into(), "kubectl".into()]
}

/// Run install commands (caller must have obtained user approval). Returns combined stdout/stderr summary.
pub fn run_install_commands(commands: &[String]) -> (bool, String) {
    let mut ok_all = true;
    let mut out = String::new();
    for cmd in commands {
        out.push_str(&format!("$ {cmd}\n"));
        let status = Command::new("sh").arg("-c").arg(cmd).status();
        match status {
            Ok(s) if s.success() => out.push_str("exit=0\n"),
            Ok(s) => {
                ok_all = false;
                out.push_str(&format!("exit={s}\n"));
            }
            Err(e) => {
                ok_all = false;
                out.push_str(&format!("spawn error: {e}\n"));
            }
        }
    }
    (ok_all, out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plan_for_missing_aws() {
        let inv = BinaryInventory::default();
        let plan = plan_install(&["aws".into(), "jq".into()], &inv);
        assert!(plan.binaries.contains(&"aws".into()));
        assert!(!plan.packages.is_empty() || !plan.notes.is_empty());
    }
}

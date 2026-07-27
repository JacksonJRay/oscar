//! User and project **skills** — prompt packages that steer the agent outside the fixed harness.
//!
//! Discovery (highest priority wins on name collision):
//! 1. `./.oscar/skills/` (cwd / project)
//! 2. `~/.config/oscar/skills/` (user)
//! 3. Built-in skills shipped with oscar

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Skill {
    pub name: String,
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub when_to_use: Option<String>,
    #[serde(default = "default_true")]
    pub user_invocable: bool,
    /// When true, model should not auto-pull; only user `/skill` activation.
    #[serde(default)]
    pub disable_model_invocation: bool,
    /// Full markdown body (after frontmatter).
    pub body: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// builtin | user | project
    pub source: String,
}

fn default_true() -> bool {
    true
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SkillsSettings {
    /// Skill names disabled (listed but not offered to the model).
    #[serde(default)]
    pub disabled: Vec<String>,
    /// Extra directories to scan for skill folders.
    #[serde(default)]
    pub paths: Vec<String>,
}

impl SkillsSettings {
    pub fn is_enabled(&self, name: &str) -> bool {
        !self.disabled.iter().any(|d| d.eq_ignore_ascii_case(name))
    }
}

/// Parse SKILL.md: optional YAML frontmatter between --- fences, then body.
pub fn parse_skill_md(raw: &str, fallback_name: &str, source: &str, path: Option<PathBuf>) -> Skill {
    let (meta, body) = split_frontmatter(raw);
    let name = meta
        .get("name")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback_name.to_string());
    let description = meta
        .get("description")
        .cloned()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            body.lines()
                .find(|l| !l.trim().is_empty() && !l.trim().starts_with('#'))
                .unwrap_or("User skill")
                .trim()
                .to_string()
        });
    let when_to_use = meta.get("when-to-use").cloned().or_else(|| meta.get("when_to_use").cloned());
    let user_invocable = meta
        .get("user-invocable")
        .or_else(|| meta.get("user_invocable"))
        .map(|v| !matches!(v.to_ascii_lowercase().as_str(), "false" | "0" | "no"))
        .unwrap_or(true);
    let disable_model_invocation = meta
        .get("disable-model-invocation")
        .or_else(|| meta.get("disable_model_invocation"))
        .map(|v| matches!(v.to_ascii_lowercase().as_str(), "true" | "1" | "yes"))
        .unwrap_or(false);

    Skill {
        name: normalize_name(&name),
        description,
        when_to_use,
        user_invocable,
        disable_model_invocation,
        body: body.trim().to_string(),
        path: path.map(|p| p.display().to_string()),
        source: source.into(),
    }
}

fn normalize_name(s: &str) -> String {
    s.trim()
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect::<String>()
        .trim_matches('-')
        .chars()
        .take(64)
        .collect()
}

fn split_frontmatter(raw: &str) -> (std::collections::BTreeMap<String, String>, String) {
    let mut map = std::collections::BTreeMap::new();
    let text = raw.trim_start_matches('\u{feff}');
    if !text.starts_with("---") {
        return (map, text.to_string());
    }
    let rest = text.trim_start_matches("---").trim_start_matches('\n');
    if let Some(end) = rest.find("\n---") {
        let yaml = &rest[..end];
        let body = rest[end + 4..].trim_start_matches('\n').to_string();
        for line in yaml.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some((k, v)) = line.split_once(':') {
                let k = k.trim().to_string();
                let v = v.trim().trim_matches('"').trim_matches('\'').to_string();
                map.insert(k, v);
            }
        }
        return (map, body);
    }
    (map, text.to_string())
}

/// Built-in skills always available (overridable by same name on disk).
pub fn builtin_skills() -> Vec<Skill> {
    vec![
        parse_skill_md(BUILTIN_LEAST_PRIVILEGE, "least-privilege-iam", "builtin", None),
        parse_skill_md(BUILTIN_NETWORK_VLSM, "network-vlsm-path", "builtin", None),
        parse_skill_md(BUILTIN_K8S_CNI, "k8s-cni-connectivity", "builtin", None),
        parse_skill_md(BUILTIN_DISCOVERY_INTENT, "discovery-intent", "builtin", None),
        parse_skill_md(BUILTIN_PERMISSION_TEST, "permission-test-plan", "builtin", None),
    ]
}

/// Discover all skills with priority: project > user > extra paths > builtin.
pub fn discover_skills(settings: &SkillsSettings) -> Vec<Skill> {
    let mut by_name: std::collections::BTreeMap<String, Skill> = std::collections::BTreeMap::new();

    // Lowest priority first so higher overwrites
    for s in builtin_skills() {
        by_name.insert(s.name.clone(), s);
    }

    for p in &settings.paths {
        let expanded = expand_tilde(p);
        load_skills_dir(&expanded, "extra", &mut by_name);
    }

    if let Some(user) = user_skills_dir() {
        load_skills_dir(&user, "user", &mut by_name);
    }

    // Project: cwd/.oscar/skills and walk up a few parents
    if let Ok(cwd) = std::env::current_dir() {
        let mut dir = cwd.clone();
        for _ in 0..6 {
            load_skills_dir(&dir.join(".oscar").join("skills"), "project", &mut by_name);
            if !dir.pop() {
                break;
            }
        }
    }

    by_name
        .into_values()
        .filter(|s| settings.is_enabled(&s.name))
        .collect()
}

fn expand_tilde(p: &str) -> PathBuf {
    if let Some(rest) = p.strip_prefix("~/") {
        if let Some(home) = dirs::home_dir() {
            return home.join(rest);
        }
    }
    PathBuf::from(p)
}

pub fn user_skills_dir() -> Option<PathBuf> {
    dirs::config_dir().map(|c| c.join("oscar").join("skills"))
}

fn load_skills_dir(dir: &Path, source: &str, out: &mut std::collections::BTreeMap<String, Skill>) {
    let Ok(rd) = fs::read_dir(dir) else {
        return;
    };
    for ent in rd.flatten() {
        let path = ent.path();
        if path.is_dir() {
            let skill_md = path.join("SKILL.md");
            if skill_md.is_file() {
                if let Ok(raw) = fs::read_to_string(&skill_md) {
                    let name = path
                        .file_name()
                        .and_then(|s| s.to_str())
                        .unwrap_or("skill");
                    let skill = parse_skill_md(&raw, name, source, Some(skill_md));
                    out.insert(skill.name.clone(), skill);
                }
            }
        } else if path.extension().and_then(|e| e.to_str()) == Some("md") {
            if let Ok(raw) = fs::read_to_string(&path) {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("skill")
                    .to_string();
                let skill = parse_skill_md(&raw, &name, source, Some(path.clone()));
                out.insert(skill.name.clone(), skill);
            }
        }
    }
}

pub fn find_skill(name: &str, settings: &SkillsSettings) -> Option<Skill> {
    let n = normalize_name(name);
    discover_skills(settings)
        .into_iter()
        .find(|s| s.name == n || s.name.eq_ignore_ascii_case(name))
}

/// Compact catalog for the system prompt (descriptions only — load body via tools).
pub fn skills_catalog_prompt(skills: &[Skill]) -> String {
    if skills.is_empty() {
        return "## Skills\n(no skills discovered — add ~/.config/oscar/skills/<name>/SKILL.md)".into();
    }
    let mut lines = vec![
        "## Skills (user steering outside harness)".into(),
        "Skills are optional playbooks. When a skill applies, call `system.skills.get` with the skill name to load full instructions, then follow them.".into(),
        "User can also `/skill <name>` to pin a skill into this session.".into(),
        String::new(),
    ];
    for s in skills {
        if s.disable_model_invocation {
            lines.push(format!(
                "- `{}` [user-only] — {}",
                s.name, s.description
            ));
        } else {
            let when = s
                .when_to_use
                .as_deref()
                .map(|w| format!(" | when: {w}"))
                .unwrap_or_default();
            lines.push(format!(
                "- `{}` ({}) — {}{}",
                s.name, s.source, s.description, when
            ));
        }
    }
    lines.join("\n")
}

// ── Built-in skill bodies ───────────────────────────────────────────

const BUILTIN_LEAST_PRIVILEGE: &str = r#"---
name: least-privilege-iam
description: Least-privilege IAM guidance for AWS/GCP/Azure. Use when reviewing, adding, removing, or designing users, roles, policies, security groups, or access rules.
when-to-use: permissions, IAM, policy, role, security group, access denied, least privilege
---

# Least-privilege IAM

## Core rule
Recommend the **exact necessary** permissions for the stated task. Never recommend overbroad access (`*` on resources, `AdministratorAccess`, `roles/owner`, `Owner` RBAC) unless the user explicitly asks for break-glass and you label it as temporary.

## Workflow
1. Clarify the **action** (list/read/write/delete) and **resource scope** (bucket, account, project, subscription, SG, namespace).
2. Prefer managed job-function policies only when they match; otherwise craft a minimal custom statement / custom role / custom RBAC role.
3. Use first-class tools: `aws.iam.simulate` / `aws.iam.access.test`, `gcp.iam.test_permissions`, `azure.iam.check_access` to validate when feasible.
4. Distinguish **auth failure** (expired/missing creds → re-auth) from **authorization deny** (wrong policy → fix IAM, do not re-auth loop).

## When validation is required vs obvious
- **Obvious (no test needed):** user cannot list S3 buckets → `s3:ListAllMyBuckets` (and bucket-level list if needed). High confidence, state the policy clearly.
- **Validate when possible:** complex multi-service access, cross-account trusts, condition keys, resource ARNs with wildcards, SG rules with wide CIDRs.
- If you cannot run a tool, say so and give a **test plan** (see permission-test-plan skill).

## Output format
- Exact policy statements / role bindings / SG rules
- Scope (account/project/VPC/SG id)
- How to attach and how to **remove** after testing
"#;

const BUILTIN_NETWORK_VLSM: &str = r#"---
name: network-vlsm-path
description: Network design and path troubleshooting preferring VLSM (variable-length subnet masks) over overly broad CIDRs. Use for VPC/subnet planning, SG/NACL, and connectivity.
when-to-use: subnet, CIDR, VLSM, VPC, security group, reachability, path, firewall, route
---

# Network + VLSM preference

## Addressing
When recommending network solutions, **prefer VLSM** — right-sized prefixes for the workload — over wide `/16` or `0.0.0.0/0` grants.
- Size subnets to current + planned hosts with headroom, not an entire RFC1918 space by default.
- Prefer specific CIDR allows on SGs/NACLs/firewalls over open ingress.
- Document supernet vs subnet relationships when troubleshooting overlaps.

## Path troubleshooting order
1. Inventory / pattern locate endpoints (`*.network.pattern.search`, `*.ip.locate`).
2. Sync inventory if cache empty (`*.network.inventory.sync`).
3. Path tools: AWS Reachability/Access Analyzer, GCP Connectivity Tests, Azure Network Watcher.
4. Check routes, SG/NSG, NACL, UDR, private endpoints, DNS before blaming the app.

## Findings
Always include concrete resource IDs, CIDRs, ports, and blockers in the final answer.
"#;

const BUILTIN_K8S_CNI: &str = r#"---
name: k8s-cni-connectivity
description: Kubernetes connectivity troubleshooting. Detect CNI first; assume pod egress SNAT unless proven otherwise; validate with first-class then secondary tools.
when-to-use: kubernetes, kubernetes, pod network, service mesh, CNI, cilium, calico, connectivity, SNAT, egress
---

# Kubernetes CNI + connectivity

## Always first
1. **Identify the CNI** (Cilium, Calico, AWS VPC CNI, Azure CNI, GKE Dataplane, other) via cluster inventory, node labels, `kube-system` DaemonSets, or user statement.
2. Prefer **first-class oscar tools** (`k8s.*.pattern.search`, contexts) before ad-hoc kubectl/binary sprawl.
3. Secondary tools by CNI: Hubble (`hubble observe`), `calicoctl`, `kubectl -n kube-system logs`, aws-node logs — only after first-class options.

## SNAT assumption (must hard-validate)
- **Default assumption:** pod traffic leaving the cluster is **SNATed** (node/ENI/IP masquerade). When tracking egress, follow traffic **off the cluster** via node/primary IP / NAT GW / cloud LB path — not only the pod IP.
- **Hard validation required:** confirm SNAT/masquerade with CNI docs, iptables/nft, Hubble flows, VPC flow logs, or cloud path tools. State assumption vs evidence.

## Connectivity checklist
- Pod → Service → Endpoints/EndpointSlice
- NetworkPolicy / CiliumNetworkPolicy / Calico GNP
- DNS (CoreDNS) before L4 path
- Node routes, security groups, NACL for node-backed egress
"#;

const BUILTIN_DISCOVERY_INTENT: &str = r#"---
name: discovery-intent
description: Semantic discovery for misspelled or partial resource names. Use whenever the user gives fragments, typos, or incomplete identifiers.
when-to-use: find, where is, search, partial name, typo, pattern, which VPC, which bucket
---

# Discovery intent (semantic, not exact match)

Users almost always provide **misspellings**, **partial names**, or incomplete IDs. Do not require exact match.

## Practice
1. Infer intent: DNS name? IP/CIDR? role? pod? SG?
2. Use **pattern discovery** tools first (`dns.pattern.find`, `network.pattern.find`, `*.pattern.search`, `aws.iam.pattern.search`, etc.) with `partial` or `glob`.
3. Try multiple fragments if the first miss fails (stem of the word, without env suffix, IP octets).
4. Present ranked candidates and ask only when genuinely ambiguous.
5. Sync inventory when cache is empty, then re-search.

Never invent resources — only report tool hits or clearly labeled hypotheses to verify.
"#;

const BUILTIN_PERMISSION_TEST: &str = r#"---
name: permission-test-plan
description: Authorized temporary broad access for testing, then tighten. Use when diagnosing access issues that need a prove-it-works then least-privilege finish.
when-to-use: test policy, temporary admin, break glass, prove access, then least privilege
---

# Permission test plan (broad → scoped)

You are authorized to propose a **temporary broad access** experiment **only** as a labeled test, always paired with removal and the final least-privilege rule.

## Template
1. **Hypothesis:** what principal cannot do today.
2. **Temporary broad rule:** exact attach steps (policy ARN / binding / SG rule) — mark **TEMPORARY / REMOVE AFTER TEST**.
3. **How to validate:** tool (`aws.iam.simulate`, app retry, `aws s3 ls`, etc.).
4. **Remove temporary access:** exact detach/delete commands.
5. **Final least-privilege:** minimal statements/bindings/SG rules that replace the broad grant.
6. Prefer not using temporary broad when the needed permission is already obvious (e.g. ListBuckets).
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_frontmatter_skill() {
        let raw = "---\nname: demo\ndescription: Hello skill\n---\n\n# Body\nDo things.\n";
        let s = parse_skill_md(raw, "fallback", "user", None);
        assert_eq!(s.name, "demo");
        assert!(s.description.contains("Hello"));
        assert!(s.body.contains("Do things"));
    }

    #[test]
    fn builtins_discoverable() {
        let skills = discover_skills(&SkillsSettings::default());
        assert!(skills.iter().any(|s| s.name == "least-privilege-iam"));
        assert!(skills.iter().any(|s| s.name == "k8s-cni-connectivity"));
    }
}

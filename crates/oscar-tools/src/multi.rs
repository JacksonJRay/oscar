//! Multi-cloud discovery tools — find where a domain/IP lives across CSPs.

use crate::helpers::{
    auth_prepare_request, load_dns_cache, load_dns_resolver_cache, load_network_cache, AuthPrefer,
};
use crate::pattern_schema::{discovery_blurb, discovery_tool_result, pattern_properties, to_tool_result};
use crate::scan::{
    scan_dns_inventory, scan_dns_resolver_inventory, scan_network_inventory, PublicDnsProbe,
};
use crate::traits::{Tool, ToolContext, ToolMeta, ToolResult};
use crate::ToolRegistry;
use async_trait::async_trait;
use oscar_core::{
    discover_skills, find_skill, search_skills, write_skill, Capability, Cloud,
    InstallBinariesPolicy, PatternQuery, SkillScope, SkillsSettings, ToolDomain,
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
    registry.register(Arc::new(NetworkTroubleshootPlaybook));
    registry.register(Arc::new(NetworkIpLocateMulti));
    registry.register(Arc::new(NetworkTroubleshootStatus));
    registry.register(Arc::new(SystemBinariesList));
    registry.register(Arc::new(SystemBinariesInstallPlan));
    registry.register(Arc::new(SystemSettingsGet));
    registry.register(Arc::new(SystemSkillsList));
    registry.register(Arc::new(SystemSkillsGet));
    registry.register(Arc::new(SystemSkillsSearch));
    registry.register(Arc::new(SystemSkillsCreate));
    registry.register(Arc::new(SystemIdentitiesList));
    registry.register(Arc::new(SystemAccessPrepare));
    registry.register(Arc::new(SystemAccessReview));
    registry.register(Arc::new(SystemAccessSelect));
    registry.register(Arc::new(SystemProfilesList));
    registry.register(Arc::new(SystemClusterPrepare));
    registry.register(Arc::new(SystemClusterResolve));
    registry.register(Arc::new(SystemClusterInferKubeconfig));
    registry.register(Arc::new(AccessTroubleshootGuide));
    registry.register(Arc::new(AccessPatternFind));
    // Node + Envoy mesh (local dataplane)
    crate::node::register_node(registry);
    crate::mesh::register_mesh(registry);
}

struct SystemIdentitiesList;
struct SystemAccessPrepare;
struct SystemAccessReview;
struct SystemAccessSelect;
struct SystemProfilesList;
struct SystemClusterPrepare;
struct SystemClusterResolve;
struct SystemClusterInferKubeconfig;

struct SystemSkillsList;
struct SystemSkillsGet;
struct SystemSkillsSearch;
struct SystemSkillsCreate;

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

/// Create/update local oscar profile metadata so the user can sign in or paste short-lived keys.
/// Does **not** store secrets; returns auth_required + operator steps for TUI secure bar / oscar auth.
#[async_trait]
impl Tool for SystemAccessPrepare {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.access.prepare".into(),
            name: "Prepare cloud account access".into(),
            description: "REQUIRED when the user names a cloud account/label that is missing or unauthenticated (e.g. 'vdms', prod, account 123…). Creates/updates a dedicated local profile (label→id like aws-vdms) and requests short-lived secure paste or SSO. Sets session preferred profile. NEVER skip this to search another usable profile (aws-default ≠ vdms). After auth: system.access.select + domain tools with profile_id. User pastes keys in TUI secure bar only — agent never sees values.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "access".into(),
                "auth".into(),
                "profile".into(),
                "login".into(),
                "sso".into(),
                "credentials".into(),
                "account".into(),
                "onboard".into(),
                "prepare".into(),
                "sign-in".into(),
                "aws".into(),
                "gcp".into(),
                "azure".into(),
                "k8s".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cloud": {
                        "type": "string",
                        "description": "aws | gcp | azure | k8s",
                        "enum": ["aws", "gcp", "azure", "k8s"]
                    },
                    "label": {
                        "type": "string",
                        "description": "Human label for the profile (e.g. prod, sandbox). Default: default"
                    },
                    "account": {
                        "type": "string",
                        "description": "Account id (AWS 12-digit) / GCP project id / Azure subscription id. Use 'pending' if unknown."
                    },
                    "region": {
                        "type": "string",
                        "description": "Default region (e.g. us-east-1) when known"
                    },
                    "profile_id": {
                        "type": "string",
                        "description": "Optional explicit oscar profile id (otherwise cloud-label)"
                    },
                    "prefer": {
                        "type": "string",
                        "description": "Preferred auth path: sso (browser/CLI login, default) | session (short-lived STS) | keys (long-lived, last resort)",
                        "enum": ["sso", "session", "keys"]
                    },
                    "request_auth": {
                        "type": "boolean",
                        "default": true,
                        "description": "If true (default), emit auth_required so TUI opens secure entry / user runs SSO; host auto-retries after auth."
                    }
                },
                "required": ["cloud"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        use oscar_identity::ProfileStore;

        let cloud_s = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        let cloud = match Cloud::parse(cloud_s) {
            Some(c) if matches!(c, Cloud::Aws | Cloud::Gcp | Cloud::Azure | Cloud::K8s) => c,
            _ => {
                return ToolResult::error(
                    "cloud is required: aws | gcp | azure | k8s (not multi)",
                );
            }
        };
        let label = args
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .trim();
        let label = if label.is_empty() { "default" } else { label };
        let account = args
            .get("account")
            .and_then(|v| v.as_str())
            .unwrap_or("pending")
            .trim();
        let account = if account.is_empty() {
            "pending"
        } else {
            account
        };
        let region = args
            .get("region")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());
        let profile_id = args.get("profile_id").and_then(|v| v.as_str());
        let account_specific = {
            let a = account.to_ascii_lowercase();
            !a.is_empty() && a != "pending" && a != "unknown" && a != "ambient"
        };
        let prefer = args
            .get("prefer")
            .and_then(|v| v.as_str())
            .and_then(AuthPrefer::parse)
            .unwrap_or_else(|| {
                // Multi-account AWS: prefer short-lived keys bound to this profile over ambient SSO.
                if cloud == Cloud::Aws && account_specific {
                    AuthPrefer::ShortLived
                } else {
                    AuthPrefer::BinarySso
                }
            });
        let request_auth = args
            .get("request_auth")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        let paths = match oscar_core::Paths::discover() {
            Ok(p) => p,
            Err(e) => return ToolResult::error(format!("config paths: {e}")),
        };
        if let Err(e) = paths.ensure() {
            return ToolResult::error(format!("ensure config dir: {e}"));
        }
        let mut store = match ProfileStore::load(&paths) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("load profiles: {e}")),
        };

        let other_cloud_profiles: Vec<_> = store
            .list()
            .iter()
            .filter(|p| p.cloud == cloud)
            .map(|p| p.id.clone())
            .collect();

        let (profile, created) =
            store.ensure_profile(cloud, label, account, region.clone(), profile_id);
        if let Err(e) = store.save() {
            return ToolResult::error(format!("save profiles.toml: {e}"));
        }

        let auth = auth_prepare_request(&profile, prefer);
        let how: &str = match (cloud, prefer) {
            (Cloud::Aws, AuthPrefer::BinarySso) => {
                "Run AWS SSO / CLI login, or paste short-lived session keys in the TUI secure bar"
            }
            (Cloud::Aws, AuthPrefer::ShortLived) => {
                "Store STS/session credentials with oscar auth aws-session / aws-assume-role (or secure bar)"
            }
            (Cloud::Aws, AuthPrefer::LongLived) => {
                "Store long-lived access keys with oscar auth aws-keys (prefer short-lived when possible)"
            }
            (Cloud::Gcp, _) => "Run oscar auth gcloud-login (or store SA JSON via gcp-sa — not in chat)",
            (Cloud::Azure, _) => "Run oscar auth az-login (or paste SP secrets in TUI secure bar)",
            (Cloud::K8s, _) => {
                "For clusters use system.cluster.prepare (eks→AWS STS, kind/k3s→kubeconfig). Or select a kubectl context."
            }
            _ => "Follow hint_commands to authenticate",
        };

        let summary = if created {
            format!(
                "Created local profile `{}` ({cloud}, account={}) — {how}. Secrets are NOT stored yet.",
                profile.id, profile.account_ref
            )
        } else {
            format!(
                "Updated/using local profile `{}` ({cloud}, account={}) — {how}",
                profile.id, profile.account_ref
            )
        };

        let data = json!({
            "reload_profiles": true,
            "set_preferred_profile": profile.id,
            "created": created,
            "multi_profile": {
                "other_profiles_same_cloud": other_cloud_profiles,
                "note": "Each profile has its own keychain namespace (oscar/<profile_id>/*). Ambient CLI SSO is only reused when it matches this profile's account_ref — otherwise paste short-lived keys for this profile.",
            },
            "profile": {
                "id": profile.id,
                "cloud": profile.cloud.to_string(),
                "label": profile.label,
                "account_ref": profile.account_ref,
                "default_region": profile.default_region,
                "secret_keyring_id": profile.secret_keyring_id,
            },
            "profiles_file": paths.profiles_file.display().to_string(),
            "prefer": match prefer {
                AuthPrefer::BinarySso => "sso",
                AuthPrefer::ShortLived => "session",
                AuthPrefer::LongLived => "keys",
            },
            "auth_model": {
                "binary_session": "Logged-in aws/gcloud/az/kubectl — only used if account matches this profile",
                "short_lived_keychain": "STS/session keys in OS keychain under oscar/<profile_id>/* (recommended for multi-account)",
                "long_lived_keychain": "Long-lived access keys / SA JSON — last resort",
                "secure_paste": "TUI secure bar accepts a full `export AWS_ACCESS_KEY_ID=…` / SECRET / SESSION_TOKEN block in one paste, or field-by-field; values go to keychain only — agent never receives secret material",
                "never_in_chat": true,
            },
            "user_message_template": format!(
                "Please authenticate profile `{}` for {} account `{}`. Prefer short-lived credentials. In the TUI, use the secure input bar (masked) — do not paste keys into chat. Or run: {}",
                profile.id,
                cloud,
                profile.account_ref,
                auth.hint_commands.first().cloned().unwrap_or_else(|| "oscar auth …".into())
            ),
            "next_steps": auth.hint_commands,
            "guidance": auth.guidance,
            "cli_equivalent": format!(
                "oscar profiles add --cloud {} --label {} --account {}{}",
                cloud,
                profile.label,
                profile.account_ref,
                region.as_ref().map(|r| format!(" --region {r}")).unwrap_or_default()
            ),
            "after_auth": [
                "Host auto-retries paused tools after secure paste / type `retry` after SSO",
                "system.access.review to see which profiles are usable",
                "Pass profile_id on tools when pivoting; session preferred profile is set automatically",
            ],
            "ui": "/identities · SECURE bar (agent-blind) · never paste secrets into chat",
        });

        // If durable keys already exist for this profile, do NOT re-emit auth_required.
        // Previously prepare always paused on resume → infinite secure-bar loop after paste.
        let already_ready = match cloud {
            Cloud::Aws => oscar_identity::profile_has_stored_aws_keys(&profile),
            Cloud::Gcp => oscar_identity::KeychainStore::has(
                &profile.secret_keyring_id,
                oscar_core::SecretKind::ServiceAccountJson,
            ),
            Cloud::Azure => {
                oscar_identity::KeychainStore::has(
                    &profile.secret_keyring_id,
                    oscar_core::SecretKind::AzureClientId,
                ) && oscar_identity::KeychainStore::has(
                    &profile.secret_keyring_id,
                    oscar_core::SecretKind::AzureClientSecret,
                )
            }
            Cloud::K8s => oscar_identity::KeychainStore::has(
                &profile.secret_keyring_id,
                oscar_core::SecretKind::Kubeconfig,
            ),
            Cloud::Multi => false,
        };

        if already_ready {
            let ready_summary = format!(
                "Profile `{}` ready (credentials present for {}, account={}). Use domain tools with profile_id=`{}`.",
                profile.id, cloud, profile.account_ref, profile.id
            );
            let mut ready_data = data;
            if let Some(map) = ready_data.as_object_mut() {
                map.insert("credentials_present".into(), json!(true));
                map.insert("auth_required".into(), json!(false));
            }
            return ToolResult::success(ready_summary, ready_data);
        }

        if request_auth {
            // success path with auth_required so host opens secure/SSO UX but profile is already saved
            let mut r = ToolResult::needs_auth(auth);
            // Overlay rich data (keep auth_required)
            if let Some(obj) = data.as_object() {
                if let Some(map) = r.data.as_object_mut() {
                    for (k, v) in obj {
                        map.insert(k.clone(), v.clone());
                    }
                }
            }
            r.summary = summary;
            // ok=false from needs_auth is correct — auth still needed
            return r;
        }

        ToolResult::success(summary, data)
    }
}

/// Prepare a Kubernetes cluster profile with the correct auth surface for the cluster kind.
/// EKS → AWS short-lived; GKE → GCP; AKS → Azure; kind/k3s/local → kubeconfig.
/// If kind is missing and cannot be inferred, returns a clarification question (no secrets).
#[async_trait]
impl Tool for SystemClusterPrepare {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.cluster.prepare".into(),
            name: "Prepare Kubernetes cluster access".into(),
            description: "REQUIRED when the user wants to connect to a Kubernetes cluster. \
Creates/updates a `k8s-…` profile and binds auth by **cluster kind**: \
**eks** → short-lived AWS STS on a linked `aws-*` profile + `aws eks update-kubeconfig` (exec get-token); \
**gke** → GCP short-lived (gcloud/ADC or SA) + get-credentials; \
**aks** → Azure short-lived (az login/Entra) + get-credentials/kubelogin; \
**kind|k3s|minikube|k0s|local** → kubeconfig only (no cloud STS). \
If `cluster_kind` is omitted, infers from label/name; if still **unknown**, returns \
`needs_user_clarification` and the agent **must ask** eks|gke|aks|kind|k3s|local before auth. \
Never invent credentials; use secure bar for STS/kubeconfig — not chat.".into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "kubernetes".into(),
                "cluster".into(),
                "eks".into(),
                "gke".into(),
                "aks".into(),
                "kind".into(),
                "k3s".into(),
                "kubeconfig".into(),
                "access".into(),
                "auth".into(),
                "prepare".into(),
                "profile".into(),
                "connect".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cluster_kind": {
                        "type": "string",
                        "description": "eks | gke | aks | kind | k3s | minikube | k0s | local | unknown",
                        "enum": ["eks", "gke", "aks", "kind", "k3s", "minikube", "k0s", "local", "unknown"]
                    },
                    "label": {
                        "type": "string",
                        "description": "Human label for the k8s profile (e.g. sandbox, prod). Default: default"
                    },
                    "cluster_name": {
                        "type": "string",
                        "description": "EKS/GKE/AKS cluster name, or kind/k3s cluster name. Default: label"
                    },
                    "region": {
                        "type": "string",
                        "description": "Region (EKS/GKE) or location (AKS). Default us-east-1 for EKS"
                    },
                    "context": {
                        "type": "string",
                        "description": "kubectl context name when known"
                    },
                    "linked_cloud_profile_id": {
                        "type": "string",
                        "description": "For eks/gke/aks: existing oscar cloud profile (e.g. aws-sandbox) that holds short-lived CSP creds"
                    },
                    "cloud_label": {
                        "type": "string",
                        "description": "If linked cloud profile missing, create one with this label (default: same as label)"
                    },
                    "account": {
                        "type": "string",
                        "description": "AWS account / GCP project / Azure subscription for the linked cloud profile"
                    },
                    "infer_from": {
                        "type": "string",
                        "description": "Free text to infer cluster_kind when not set (user utterance)"
                    },
                    "request_auth": {
                        "type": "boolean",
                        "default": true,
                        "description": "Emit auth_required for secure bar / SSO when secrets missing"
                    },
                    "profile_id": {
                        "type": "string",
                        "description": "Optional explicit k8s profile id (default k8s-<label>)"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        use oscar_core::{Cloud, ClusterKind};
        use oscar_identity::{
            auth_request_for_cluster_plan, build_cluster_auth_plan, infer_cluster_kind,
            ProfileStore,
        };
        use std::fs;

        let label = args
            .get("label")
            .and_then(|v| v.as_str())
            .unwrap_or("default")
            .trim();
        let label = if label.is_empty() { "default" } else { label };
        let cluster_name = args
            .get("cluster_name")
            .and_then(|v| v.as_str())
            .unwrap_or(label)
            .trim();
        let cluster_name = if cluster_name.is_empty() {
            label
        } else {
            cluster_name
        };
        let region = args.get("region").and_then(|v| v.as_str());
        let context = args.get("context").and_then(|v| v.as_str());
        let linked_in = args
            .get("linked_cloud_profile_id")
            .and_then(|v| v.as_str());
        let cloud_label = args
            .get("cloud_label")
            .and_then(|v| v.as_str())
            .unwrap_or(label);
        let account = args
            .get("account")
            .and_then(|v| v.as_str())
            .unwrap_or("pending");
        let request_auth = args
            .get("request_auth")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let profile_id_arg = args.get("profile_id").and_then(|v| v.as_str());

        // Resolve kind: explicit → infer_from → label+name → unknown
        let mut kind = args
            .get("cluster_kind")
            .and_then(|v| v.as_str())
            .and_then(ClusterKind::parse)
            .unwrap_or(ClusterKind::Unknown);
        if matches!(kind, ClusterKind::Unknown) {
            if let Some(t) = args.get("infer_from").and_then(|v| v.as_str()) {
                kind = infer_cluster_kind(t);
            }
        }
        if matches!(kind, ClusterKind::Unknown) {
            kind = infer_cluster_kind(&format!("{label} {cluster_name}"));
        }

        let paths = match oscar_core::Paths::discover() {
            Ok(p) => p,
            Err(e) => return ToolResult::error(format!("config paths: {e}")),
        };
        if let Err(e) = paths.ensure() {
            return ToolResult::error(format!("ensure config dir: {e}"));
        }
        let mut store = match ProfileStore::load(&paths) {
            Ok(s) => s,
            Err(e) => return ToolResult::error(format!("load profiles: {e}")),
        };

        let k8s_id = profile_id_arg
            .map(|s| oscar_identity::Profile::normalize_id(Cloud::K8s, s))
            .unwrap_or_else(|| oscar_identity::Profile::make_id(Cloud::K8s, label));

        // Clarification-only plan (no profile writes that claim a kind).
        if matches!(kind, ClusterKind::Unknown) {
            let plan = build_cluster_auth_plan(
                &paths,
                ClusterKind::Unknown,
                label,
                cluster_name,
                region,
                context,
                linked_in,
                &k8s_id,
            );
            return ToolResult::success(
                format!(
                    "Cluster kind unknown for `{}` — ask the user before preparing credentials.",
                    label
                ),
                json!({
                    "needs_user_clarification": true,
                    "clarification_question": plan.clarification_question,
                    "cluster_kind": "unknown",
                    "auth_surface": "need_cluster_kind",
                    "plan": plan,
                    "agent_instruction": "STOP. Ask the user which cluster type (eks|gke|aks|kind|k3s|minikube|k0s|local). Do not call cloud auth or kubeconfig prepare until they answer. Then re-call system.cluster.prepare with cluster_kind set.",
                }),
            );
        }

        // Ensure k8s profile
        let (mut k8s_profile, k8s_created) = store.ensure_profile(
            Cloud::K8s,
            label,
            cluster_name,
            region.map(|s| s.to_string()),
            Some(&k8s_id),
        );

        // Linked cloud profile for managed kinds
        let mut linked_created = false;
        let linked_id = if kind.is_managed_cloud() {
            let cloud = kind.linked_cloud().unwrap();
            if let Some(id) = linked_in {
                let id = oscar_identity::Profile::normalize_id(cloud, id);
                if store.get(&id).is_none() {
                    let (p, c) = store.ensure_profile(
                        cloud,
                        cloud_label,
                        account,
                        region.map(|s| s.to_string()),
                        Some(&id),
                    );
                    linked_created = c;
                    let _ = p;
                }
                Some(id)
            } else {
                let (p, c) = store.ensure_profile(
                    cloud,
                    cloud_label,
                    account,
                    region.map(|s| s.to_string()),
                    None,
                );
                linked_created = c;
                Some(p.id)
            }
        } else {
            None
        };

        let plan = build_cluster_auth_plan(
            &paths,
            kind,
            label,
            cluster_name,
            region,
            context,
            linked_id.as_deref(),
            &k8s_profile.id,
        );

        // Attach cluster ref to k8s profile
        k8s_profile.clusters.retain(|c| c.name != plan.cluster.name);
        k8s_profile.clusters.push(plan.cluster.clone());
        // Also attach to linked cloud profile when present
        if let Some(ref lid) = plan.linked_cloud_profile_id {
            if let Some(cp) = store.get(lid).cloned() {
                let mut cp = cp;
                cp.clusters.retain(|c| c.name != plan.cluster.name);
                cp.clusters.push(plan.cluster.clone());
                store.upsert(cp);
            }
        }
        store.upsert(k8s_profile.clone());
        if let Err(e) = store.save() {
            return ToolResult::error(format!("save profiles: {e}"));
        }

        // Ensure kube dir exists
        if let Some(ref kp) = plan.kubeconfig_path {
            if let Some(parent) = std::path::Path::new(kp).parent() {
                let _ = fs::create_dir_all(parent);
            }
        }

        let summary = format!(
            "Prepared k8s profile `{}` as **{}** cluster `{}` — {}{}",
            k8s_profile.id,
            kind,
            cluster_name,
            plan.guidance.chars().take(160).collect::<String>(),
            if plan.guidance.len() > 160 { "…" } else { "" }
        );

        let data = json!({
            "reload_profiles": true,
            "set_preferred_profile": k8s_profile.id,
            "k8s_profile_created": k8s_created,
            "linked_cloud_profile_created": linked_created,
            "needs_user_clarification": false,
            "cluster_kind": kind.as_str(),
            "auth_surface": plan.auth_surface,
            "k8s_profile_id": k8s_profile.id,
            "linked_cloud_profile_id": plan.linked_cloud_profile_id,
            "cluster": plan.cluster,
            "kubeconfig_path": plan.kubeconfig_path,
            "guidance": plan.guidance,
            "next_steps": plan.next_steps,
            "setup_commands": plan.setup_commands,
            "auth_model": {
                "eks": "Short-lived AWS STS on linked aws-* profile; kubeconfig exec aws eks get-token (ephemeral)",
                "gke": "Short-lived GCP (gcloud/ADC or SA); get-credentials exec plugin",
                "aks": "Short-lived Azure/Entra (az login); get-credentials + kubelogin",
                "kind_k3s_local": "Kubeconfig file/context only — no cloud STS",
            },
            "after_auth": [
                "Run setup_commands once (update-kubeconfig / get-credentials / kind get kubeconfig)",
                "k8s.inventory.sync or k8s.contexts.list with profile_id",
                "Pass profile_id / context on k8s tools",
            ],
            "ui": "/identities · secure bar for AWS STS (EKS) or kubeconfig (local) — never paste secrets into chat",
        });

        // Auth readiness
        let already_ready = match plan.auth_surface {
            oscar_identity::ClusterAuthSurface::AwsShortLived => plan
                .linked_cloud_profile_id
                .as_ref()
                .and_then(|id| store.get(id))
                .map(oscar_identity::profile_has_stored_aws_keys)
                .unwrap_or(false),
            oscar_identity::ClusterAuthSurface::GcpShortLived => plan
                .linked_cloud_profile_id
                .as_ref()
                .and_then(|id| store.get(id))
                .map(|p| {
                    oscar_identity::KeychainStore::has(
                        &p.secret_keyring_id,
                        oscar_core::SecretKind::ServiceAccountJson,
                    )
                })
                .unwrap_or(false),
            oscar_identity::ClusterAuthSurface::AzureShortLived => plan
                .linked_cloud_profile_id
                .as_ref()
                .and_then(|id| store.get(id))
                .map(|p| {
                    oscar_identity::KeychainStore::has(
                        &p.secret_keyring_id,
                        oscar_core::SecretKind::AzureClientId,
                    ) && oscar_identity::KeychainStore::has(
                        &p.secret_keyring_id,
                        oscar_core::SecretKind::AzureClientSecret,
                    )
                })
                .unwrap_or(false),
            oscar_identity::ClusterAuthSurface::Kubeconfig => {
                oscar_identity::KeychainStore::has(
                    &k8s_profile.secret_keyring_id,
                    oscar_core::SecretKind::Kubeconfig,
                ) || plan
                    .kubeconfig_path
                    .as_ref()
                    .map(|p| std::path::Path::new(p).exists())
                    .unwrap_or(false)
            }
            oscar_identity::ClusterAuthSurface::NeedClusterKind => false,
        };

        if already_ready || !request_auth {
            let mut d = data;
            if let Some(m) = d.as_object_mut() {
                m.insert("credentials_present".into(), json!(already_ready));
            }
            return ToolResult::success(
                if already_ready {
                    format!("{summary} Credentials already present — run setup_commands if kubeconfig missing.")
                } else {
                    summary
                },
                d,
            );
        }

        if let Some(auth) = auth_request_for_cluster_plan(&plan) {
            let mut r = ToolResult::needs_auth(auth);
            if let Some(obj) = data.as_object() {
                if let Some(map) = r.data.as_object_mut() {
                    for (k, v) in obj {
                        map.insert(k.clone(), v.clone());
                    }
                }
            }
            r.summary = summary;
            return r;
        }

        ToolResult::success(summary, data)
    }
}

/// Fuzzy-resolve a user cluster fragment against live EKS names and/or kube contexts.
#[async_trait]
impl Tool for SystemClusterResolve {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.cluster.resolve".into(),
            name: "Resolve cluster name fragment".into(),
            description: "Users almost never give the full cluster name — they say fragments like `2ptt`. \
List EKS clusters (via linked AWS profile short-lived creds) and/or local kubectl contexts, \
then fuzzy-match the query. Returns best match + alternatives. Call this **before** \
system.cluster.prepare / inventory when the cluster name is incomplete. Never invent a cluster name."
                .into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Aws, Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "k8s".into(),
                "cluster".into(),
                "resolve".into(),
                "fuzzy".into(),
                "eks".into(),
                "name".into(),
                "match".into(),
                "context".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "User fragment (e.g. 2ptt, prod, sandbox)"
                    },
                    "cluster_kind": {
                        "type": "string",
                        "description": "eks | gke | aks | kind | local — default eks when aws profile set"
                    },
                    "aws_profile_id": {
                        "type": "string",
                        "description": "Oscar AWS profile for listing EKS clusters (short-lived STS)"
                    },
                    "region": {
                        "type": "string",
                        "description": "AWS region for eks list-clusters (default us-east-1)"
                    },
                    "include_kube_contexts": {
                        "type": "boolean",
                        "default": true
                    }
                },
                "required": ["query"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{resolve_aws_process_creds, resolve_cluster_name_fuzzy, ProfileStore};
        use std::process::Command;

        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if query.is_empty() {
            return ToolResult::error("query is required (user fragment like 2ptt)");
        }
        let region = args
            .get("region")
            .and_then(|v| v.as_str())
            .unwrap_or("us-east-1");
        let include_ctx = args
            .get("include_kube_contexts")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let kind = args
            .get("cluster_kind")
            .and_then(|v| v.as_str())
            .unwrap_or("eks");

        let mut candidates: Vec<String> = Vec::new();
        let mut notes: Vec<String> = Vec::new();

        // kubectl contexts
        if include_ctx {
            if let Ok(out) = Command::new("kubectl")
                .args(["config", "get-contexts", "-o", "name"])
                .output()
            {
                if out.status.success() {
                    for line in String::from_utf8_lossy(&out.stdout).lines() {
                        let n = line.trim();
                        if !n.is_empty() {
                            candidates.push(n.to_string());
                        }
                    }
                }
            }
        }

        // EKS list via AWS profile STS
        if kind.eq_ignore_ascii_case("eks") || kind.eq_ignore_ascii_case("unknown") {
            let paths = oscar_core::Paths::discover().ok();
            let store = paths.as_ref().and_then(|p| ProfileStore::load(p).ok());
            let aws_pid = args
                .get("aws_profile_id")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .or_else(|| {
                    store.as_ref().and_then(|s| {
                        s.list()
                            .iter()
                            .find(|p| p.cloud == Cloud::Aws)
                            .map(|p| p.id.clone())
                    })
                });
            if let (Some(store), Some(pid)) = (store.as_ref(), aws_pid) {
                if let Some(profile) = store.get(&pid) {
                    match resolve_aws_process_creds(profile, &ctx.binaries) {
                        Ok(creds) => {
                            let mut cmd = Command::new("aws");
                            cmd.args([
                                "eks",
                                "list-clusters",
                                "--region",
                                region,
                                "--output",
                                "json",
                            ]);
                            for (k, v) in &creds.env {
                                cmd.env(k, v);
                            }
                            match cmd.output() {
                                Ok(o) if o.status.success() => {
                                    if let Ok(v) =
                                        serde_json::from_slice::<serde_json::Value>(&o.stdout)
                                    {
                                        if let Some(arr) =
                                            v.get("clusters").and_then(|c| c.as_array())
                                        {
                                            for c in arr {
                                                if let Some(n) = c.as_str() {
                                                    candidates.push(n.to_string());
                                                }
                                            }
                                            notes.push(format!(
                                                "Listed EKS clusters via profile `{pid}` region {region}"
                                            ));
                                        }
                                    }
                                }
                                Ok(o) => {
                                    notes.push(format!(
                                        "eks list-clusters failed: {}",
                                        String::from_utf8_lossy(&o.stderr)
                                            .chars()
                                            .take(200)
                                            .collect::<String>()
                                    ));
                                }
                                Err(e) => notes.push(format!("aws cli error: {e}")),
                            }
                        }
                        Err(_) => notes.push(format!(
                            "No usable AWS creds for `{pid}` — run system.access.prepare / aws-session first"
                        )),
                    }
                }
            } else {
                notes.push("No aws_profile_id / AWS profile — skipped EKS list".into());
            }
        }

        candidates.sort();
        candidates.dedup();
        let resolved = resolve_cluster_name_fuzzy(query, &candidates);

        let summary = if let Some(ref best) = resolved.best {
            format!(
                "Resolved `{query}` → `{best}` ({}) among {} candidate(s)",
                resolved.confidence,
                candidates.len()
            )
        } else if !resolved.alternatives.is_empty() {
            format!(
                "Ambiguous fragment `{query}` — {} candidate(s); see alternatives",
                candidates.len()
            )
        } else {
            format!(
                "No match for `{query}` in {} candidate(s) — list may be empty or fragment too short",
                candidates.len()
            )
        };

        ToolResult::success(
            summary,
            json!({
                "query": query,
                "candidates": candidates,
                "resolve": resolved,
                "notes": notes,
                "next": "Pass resolve.best as cluster_name to system.cluster.prepare (cluster_kind=eks)",
            }),
        )
    }
}

/// Infer cluster kind from a pasted kubeconfig (agent never stores secrets from this alone —
/// host/TUI secure bar stores; this is classification + guidance).
#[async_trait]
impl Tool for SystemClusterInferKubeconfig {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.cluster.infer_kubeconfig".into(),
            name: "Infer cluster kind from kubeconfig paste".into(),
            description: "Classify a kubeconfig YAML paste: EKS (aws eks get-token), GKE (gke-gcloud-auth-plugin), \
AKS (kubelogin/Entra), kind/k3s/local. Returns kind + guidance for system.cluster.prepare. \
Do **not** echo the full kubeconfig back to the user. Prefer secure bar for storage."
                .into(),
            domain: ToolDomain::Cluster,
            clouds: vec![Cloud::K8s, Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "kubeconfig".into(),
                "infer".into(),
                "paste".into(),
                "eks".into(),
                "gke".into(),
                "aks".into(),
                "kind".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "kubeconfig": {
                        "type": "string",
                        "description": "Kubeconfig YAML text (from secure paste path preferred)"
                    }
                },
                "required": ["kubeconfig"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        use oscar_identity::infer_cluster_kind_from_kubeconfig;

        let kc = args
            .get("kubeconfig")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if kc.trim().len() < 20 {
            return ToolResult::error("kubeconfig text too short");
        }
        let inf = infer_cluster_kind_from_kubeconfig(kc);
        // Never return the paste body
        ToolResult::success(
            format!(
                "Inferred **{}** from kubeconfig ({} confidence)",
                inf.kind, inf.confidence
            ),
            json!({
                "cluster_kind": inf.kind.as_str(),
                "confidence": inf.confidence,
                "context_names": inf.context_names,
                "cluster_names": inf.cluster_names,
                "signals": inf.signals,
                "guidance": inf.guidance,
                "next": format!(
                    "system.cluster.prepare cluster_kind={} label=… (then store kubeconfig via secure bar if local, or CSP short-lived auth if managed)",
                    inf.kind.as_str()
                ),
                "redacted": true,
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemAccessReview {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.access.review".into(),
            name: "Review available cloud credentials".into(),
            description: "List all oscar profiles and ambient sessions with validity (no secret values) so the agent can pivot accounts/CSPs. Filter by cloud or account. Prefer this before troubleshooting when unsure which credentials are available. Does not print keys.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "access".into(),
                "review".into(),
                "credentials".into(),
                "profiles".into(),
                "pivot".into(),
                "multi-account".into(),
                "identity".into(),
                "whoami".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string", "description": "Optional filter aws|gcp|azure|k8s" },
                    "account": { "type": "string", "description": "Optional account/project/subscription filter" },
                    "live": { "type": "boolean", "default": true, "description": "Live-probe validity when true" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        use oscar_identity::{
            build_identity_inventory, build_identity_inventory_quick, ProfileStore, Validity,
        };
        let live = args.get("live").and_then(|v| v.as_bool()).unwrap_or(true);
        let cloud_f = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .and_then(Cloud::parse);
        let account_f = args
            .get("account")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let store = oscar_core::Paths::discover()
            .and_then(|p| ProfileStore::load(&p))
            .unwrap_or_else(|_| {
                ProfileStore::load_path(std::path::Path::new("/var/empty/oscar-no-profiles.toml"))
                    .expect("empty")
            });
        let inv = if live {
            build_identity_inventory(&store, &ctx.binaries)
        } else {
            build_identity_inventory_quick(&store)
        };

        let mut usable = Vec::new();
        let mut needs_auth = Vec::new();
        let mut rows = Vec::new();
        for e in &inv.entries {
            if let Some(c) = cloud_f {
                if e.cloud != c.to_string() && e.cloud != "multi" {
                    // allow binary session labels
                    if !e.cloud.eq_ignore_ascii_case(&c.to_string()) {
                        continue;
                    }
                }
            }
            if let Some(ref acc) = account_f {
                let needle = acc.to_ascii_lowercase();
                let hit = e
                    .account_ref
                    .as_deref()
                    .map(|a| a.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
                    || e.detail.to_ascii_lowercase().contains(&needle)
                    || e.id.to_ascii_lowercase().contains(&needle)
                    || e.label.to_ascii_lowercase().contains(&needle);
                if !hit {
                    continue;
                }
            }
            let csp_tag = match e.cloud.as_str() {
                "aws" => "[AWS]",
                "gcp" => "[GCP]",
                "azure" => "[AZURE]",
                "k8s" => "[K8S]",
                "llm" => "[LLM]",
                _ => "[?]",
            };
            let account_kind = match e.cloud.as_str() {
                "aws" => "account_id",
                "gcp" => "project_id",
                "azure" => "subscription_id",
                "k8s" => "cluster_or_context",
                _ => "account_ref",
            };
            let row = json!({
                "csp": e.cloud,
                "csp_tag": csp_tag,
                "id": e.id,
                "kind": e.kind,
                "label": e.label,
                "account_kind": account_kind,
                "account_ref": e.account_ref,
                "auth_source": e.auth_source,
                "secrets_present": e.secrets_present, // kinds only
                "validity": e.validity.as_str(),
                "detail": e.detail,
                "usable_now": matches!(e.validity, Validity::Valid),
                "display": format!("{csp_tag} {} ({})", e.id, e.cloud),
            });
            if matches!(e.validity, Validity::Valid) {
                usable.push(e.id.clone());
            } else if matches!(
                e.validity,
                Validity::Missing | Validity::Expired | Validity::Invalid
            ) {
                needs_auth.push(e.id.clone());
            }
            rows.push(row);
        }

        let preferred = ctx.preferred_profile_id.clone();
        // Group entries by CSP for unambiguous AWS vs GCP vs Azure pivot.
        let mut by_cloud = serde_json::Map::new();
        for row in &rows {
            let csp = row
                .get("csp")
                .and_then(|v| v.as_str())
                .unwrap_or("other")
                .to_string();
            by_cloud
                .entry(csp)
                .or_insert_with(|| json!([]))
                .as_array_mut()
                .unwrap()
                .push(row.clone());
        }
        let filter_miss = account_f.is_some() && rows.is_empty();
        let filter_needs_setup = account_f.is_some()
            && !rows.is_empty()
            && usable.is_empty()
            && !needs_auth.is_empty();
        let mut guidance = vec![
            "Distinguish CSP by csp_tag / id prefix — never use an aws-* profile for Azure tools".into(),
            "If the target account/label is missing from entries: system.access.prepare with cloud + label (+ account if known)".into(),
            "If profile exists but needs_auth: prepare again or secure-paste short-lived keys / SSO — do NOT search another profile".into(),
            "Pivot: system.access.select profile_id=aws-…|gcp-…|azure-… then pass profile_id on domain tools".into(),
            "Never request raw keys in chat; secure bar / oscar auth only".into(),
            "Never substitute a usable default profile for a differently named account (e.g. aws-default ≠ vdms)".into(),
        ];
        if filter_miss {
            if let Some(ref acc) = account_f {
                guidance.insert(
                    0,
                    format!(
                        "NO PROFILE matched filter `{acc}` — call system.access.prepare cloud=<csp> label={acc} account=pending (or real account id). Do NOT run DNS/network against other profiles."
                    ),
                );
            }
        }
        if filter_needs_setup {
            guidance.insert(
                0,
                "Matching profile(s) exist but none usable_now — complete auth via system.access.prepare / secure bar before domain tools."
                    .into(),
            );
        }
        ToolResult::success(
            format!(
                "access review: {} shown · usable_now={} · need_auth={} · preferred={} · CSPs={}{}",
                rows.len(),
                usable.len(),
                needs_auth.len(),
                preferred.as_deref().unwrap_or("(none)"),
                by_cloud.keys().cloned().collect::<Vec<_>>().join(","),
                if filter_miss {
                    " · TARGET_MISSING→prepare"
                } else if filter_needs_setup {
                    " · TARGET_NEEDS_AUTH"
                } else {
                    ""
                }
            ),
            json!({
                "preferred_profile_id": preferred,
                "usable_profile_ids": usable,
                "needs_auth_ids": needs_auth,
                "filter": {
                    "cloud": cloud_f.map(|c| c.to_string()),
                    "account_or_label": account_f,
                    "matched_rows": rows.len(),
                    "target_missing": filter_miss,
                    "target_needs_auth": filter_needs_setup,
                },
                "by_cloud": by_cloud,
                "entries": rows,
                "notes": inv.notes,
                "csp_legend": {
                    "aws": "[AWS] account_id · profile ids aws-*",
                    "gcp": "[GCP] project_id · profile ids gcp-*",
                    "azure": "[AZURE] subscription_id · profile ids azure-*",
                    "k8s": "[K8S] context/cluster · profile ids k8s-*",
                },
                "agent_guidance": guidance,
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemAccessSelect {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.access.select".into(),
            name: "Select preferred profile for session pivot".into(),
            description: "Set (or clear) the session preferred oscar profile so subsequent tools that omit profile_id target that account. Use after system.access.review when pivoting multi-account/CSP troubleshooting. Does not change secrets.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "access".into(),
                "select".into(),
                "pivot".into(),
                "profile".into(),
                "preferred".into(),
                "multi-account".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "profile_id": {
                        "type": "string",
                        "description": "Profile id to prefer for this session (omit or empty with clear=true to clear)"
                    },
                    "clear": {
                        "type": "boolean",
                        "default": false,
                        "description": "Clear preferred profile"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if args.get("clear").and_then(|v| v.as_bool()).unwrap_or(false) {
            return ToolResult::success(
                "cleared session preferred profile",
                json!({
                    "clear_preferred_profile": true,
                    "previous": ctx.preferred_profile_id,
                }),
            );
        }
        let pid = args
            .get("profile_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if pid.is_empty() {
            return ToolResult::error("profile_id required (or clear=true)");
        }
        if ctx.profiles.get(pid).is_none() {
            return ToolResult::error(format!(
                "unknown profile `{pid}` — system.access.prepare or system.profiles.list first"
            ));
        }
        let p = ctx.profiles.get(pid).unwrap();
        ToolResult::success(
            format!(
                "session preferred profile → `{pid}` ({} account {})",
                p.cloud, p.account_ref
            ),
            json!({
                "set_preferred_profile": pid,
                "profile": {
                    "id": p.id,
                    "cloud": p.cloud.to_string(),
                    "account_ref": p.account_ref,
                    "label": p.label,
                    "default_region": p.default_region,
                },
                "hint": "Tools without profile_id now prefer this profile when cloud matches. Override with explicit profile_id anytime.",
            }),
        )
    }
}

#[async_trait]
impl Tool for SystemProfilesList {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.profiles.list".into(),
            name: "List local oscar profiles".into(),
            description: "List oscar cloud profiles grouped by CSP (AWS vs GCP vs Azure vs K8s). Ids are always prefixed aws-|gcp-|azure-|k8s-. Returns by_cloud map + flat list. No secrets. Filter with cloud=aws|gcp|azure|k8s.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "profile".into(),
                "profiles".into(),
                "account".into(),
                "list".into(),
                "config".into(),
                "aws".into(),
                "gcp".into(),
                "azure".into(),
                "csp".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "cloud": { "type": "string", "description": "Optional filter: aws|gcp|azure|k8s" }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let filter = args
            .get("cloud")
            .and_then(|v| v.as_str())
            .and_then(Cloud::parse);
        let rows: Vec<_> = ctx
            .profiles
            .list()
            .iter()
            .filter(|p| filter.map(|c| p.cloud == c).unwrap_or(true))
            .map(|p| {
                json!({
                    "csp": p.cloud.id_prefix(),
                    "csp_tag": p.cloud.tag(),
                    "csp_name": p.cloud.display_name(),
                    "id": p.id,
                    "label": p.label,
                    "account_kind": p.cloud.account_kind(),
                    "account_ref": p.account_ref,
                    "default_region": p.default_region,
                    "display": p.display_line(),
                })
            })
            .collect();
        let by_cloud = if filter.is_some() {
            json!({ filter.unwrap().id_prefix(): rows.clone() })
        } else {
            ctx.profiles.by_cloud_json()
        };
        let counts = json!({
            "aws": ctx.profiles.list().iter().filter(|p| p.cloud == Cloud::Aws).count(),
            "gcp": ctx.profiles.list().iter().filter(|p| p.cloud == Cloud::Gcp).count(),
            "azure": ctx.profiles.list().iter().filter(|p| p.cloud == Cloud::Azure).count(),
            "k8s": ctx.profiles.list().iter().filter(|p| p.cloud == Cloud::K8s).count(),
        });
        ToolResult::success(
            format!(
                "{} profile(s) · by CSP aws={} gcp={} azure={} k8s={}",
                rows.len(),
                counts["aws"],
                counts["gcp"],
                counts["azure"],
                counts["k8s"]
            ),
            json!({
                "counts_by_csp": counts,
                "by_cloud": by_cloud,
                "profiles": rows,
                "id_convention": "aws-<label> | gcp-<label> | azure-<label> | k8s-<label>",
                "hint": "Never confuse CSP profiles: ids and csp_tag always encode the cloud. Create: system.access.prepare cloud=aws|gcp|azure.",
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
                "unknown skill `{name}` — call system.skills.search or system.skills.list"
            )),
        }
    }
}

/// Progressive search: name/description/when-to-use only (no body — Grok/OpenCode style).
#[async_trait]
impl Tool for SystemSkillsSearch {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.skills.search".into(),
            name: "Search skills / playbooks".into(),
            description: "Search playbooks by trigger phrase or topic (e.g. \"website down\", \"cni\", \"least privilege\"). \
Returns **short** matches only — then call system.skills.get or tools_execute tool_id=skill.<name> to load the full body. \
Does not bloat context with all skill text.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "skills".into(),
                "skill".into(),
                "playbook".into(),
                "search".into(),
                "discover".into(),
                "pattern".into(),
                "troubleshoot".into(),
                "system".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "query": {
                        "type": "string",
                        "description": "Free text: user intent or trigger phrases"
                    },
                    "limit": { "type": "integer", "default": 10 }
                },
                "required": ["query"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let query = args
            .get("query")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim();
        if query.is_empty() {
            return ToolResult::error("query is required");
        }
        let limit = args
            .get("limit")
            .and_then(|v| v.as_u64())
            .unwrap_or(10) as usize;
        let settings = skills_settings_from_ctx(ctx);
        let hits = search_skills(query, &settings, limit);
        let list: Vec<_> = hits
            .iter()
            .map(|s| {
                json!({
                    "name": s.name,
                    "tool_id": format!("skill.{}", s.name),
                    "description": s.description,
                    "when_to_use": s.when_to_use,
                    "source": s.source,
                })
            })
            .collect();
        ToolResult::success(
            format!("{} skill match(es) for `{query}`", list.len()),
            json!({
                "query": query,
                "skills": list,
                "next": "tools_execute tool_id=skill.<name>  OR  system.skills.get name=<name>  to load full playbook body",
            }),
        )
    }
}

/// Create a skill/playbook from user guidance (writes SKILL.md).
/// Local config only — **Read** capability so the agent can author playbooks in default readonly mode.
#[async_trait]
impl Tool for SystemSkillsCreate {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "system.skills.create".into(),
            name: "Create skill / playbook".into(),
            description: "[NATIVE] Create a reusable oscar skill (SKILL.md) from user guidance — e.g. \
\"when I say look for X, output Y…\". Pass `guidance` (natural language) and/or structured name/description/body. \
Writes to ~/.config/oscar/skills/ (user) or ./.oscar/skills/ (project). Local files only — works in readonly. \
Returns the full body so you can follow it immediately; user can /skill <name> to pin.".into(),
            domain: ToolDomain::Meta,
            clouds: vec![Cloud::Multi],
            capability: Capability::Read,
            tags: vec![
                "skills".into(),
                "skill".into(),
                "playbook".into(),
                "create".into(),
                "author".into(),
                "when i say".into(),
                "remember".into(),
                "system".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "name": {
                        "type": "string",
                        "description": "kebab-case skill id (optional — auto from description/guidance)"
                    },
                    "description": {
                        "type": "string",
                        "description": "What it does and when to use (drives search)"
                    },
                    "when_to_use": {
                        "type": "string",
                        "description": "Comma-separated trigger phrases"
                    },
                    "guidance": {
                        "type": "string",
                        "description": "User's natural-language request (used to build body if body omitted)"
                    },
                    "body": {
                        "type": "string",
                        "description": "Full markdown playbook body; optional if guidance provided"
                    },
                    "scope": {
                        "type": "string",
                        "enum": ["user", "project"],
                        "default": "user"
                    },
                    "allowed_tools": {
                        "type": "array",
                        "items": { "type": "string" },
                        "description": "Optional preferred tool ids"
                    }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let guidance = args
            .get("guidance")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());

        let description = args
            .get("description")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| {
                guidance.map(|g| {
                    let one: String = g.lines().next().unwrap_or(g).chars().take(160).collect();
                    one
                })
            });
        let Some(description) = description else {
            return ToolResult::error(
                "Provide description and/or guidance (user's when-I-say procedure)",
            );
        };

        let name_raw = args
            .get("name")
            .and_then(|v| v.as_str())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .unwrap_or_else(|| slug_skill_name(&description));
        if name_raw.len() < 2 {
            return ToolResult::error("could not derive skill name — pass name= kebab-case id");
        }

        let when = args
            .get("when_to_use")
            .and_then(|v| v.as_str())
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| guidance.map(|g| extract_when_phrases(g)));

        let body_owned: String = if let Some(b) = args.get("body").and_then(|v| v.as_str()) {
            if b.trim().is_empty() {
                if let Some(g) = guidance {
                    synthesize_skill_body(g, when.as_deref())
                } else {
                    return ToolResult::error("body is empty — pass body or guidance");
                }
            } else {
                b.to_string()
            }
        } else if let Some(g) = guidance {
            synthesize_skill_body(g, when.as_deref())
        } else {
            return ToolResult::error("body or guidance is required");
        };

        let scope = args
            .get("scope")
            .and_then(|v| v.as_str())
            .and_then(SkillScope::parse)
            .unwrap_or(SkillScope::User);
        let allowed: Vec<String> = args
            .get("allowed_tools")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        match write_skill(
            scope,
            &name_raw,
            &description,
            when.as_deref(),
            &body_owned,
            &allowed,
        ) {
            Ok(path) => {
                // Re-discover including the file we just wrote
                let settings = SkillsSettings::default();
                let loaded = find_skill(&name_raw, &settings);
                let skill_name = loaded
                    .as_ref()
                    .map(|s| s.name.clone())
                    .unwrap_or_else(|| name_raw.to_ascii_lowercase());
                let body_out = loaded
                    .as_ref()
                    .map(|s| s.body.clone())
                    .unwrap_or(body_owned);
                ToolResult::success(
                    format!(
                        "Created playbook `{}` at {} — follow the returned body now; user can /skill {} to pin",
                        skill_name,
                        path.display(),
                        skill_name
                    ),
                    json!({
                        "name": skill_name,
                        "path": path.display().to_string(),
                        "scope": match scope {
                            SkillScope::User => "user",
                            SkillScope::Project => "project",
                        },
                        "tool_id": format!("skill.{skill_name}"),
                        "description": description,
                        "when_to_use": when,
                        "body": body_out,
                        "instruction": "Follow this playbook for the current task. Tell the user /skill <name> to pin into the session.",
                        "next": [
                            format!("/skill {skill_name}"),
                            format!("system.skills.get name={skill_name}"),
                            "system.skills.search to verify discoverability",
                        ],
                        "reload": "Host/session: call /skills or reload_skills so catalog picks up the new skill",
                    }),
                )
            }
            Err(e) => ToolResult::error(format!("write skill failed: {e}")),
        }
    }
}

fn slug_skill_name(text: &str) -> String {
    let s: String = text
        .to_ascii_lowercase()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
        .collect();
    let s = s
        .split('-')
        .filter(|t| {
            !t.is_empty()
                && !matches!(
                    *t,
                    "a" | "an"
                        | "the"
                        | "for"
                        | "when"
                        | "i"
                        | "say"
                        | "to"
                        | "and"
                        | "or"
                        | "my"
                        | "create"
                        | "skill"
                        | "playbook"
                )
        })
        .take(6)
        .collect::<Vec<_>>()
        .join("-");
    let s = s.trim_matches('-').chars().take(48).collect::<String>();
    if s.len() < 2 {
        "user-playbook".into()
    } else {
        s
    }
}

fn extract_when_phrases(guidance: &str) -> String {
    // Prefer quoted "when I say …" snippets; else first line truncated
    let g = guidance.trim();
    if let Some(idx) = g.to_ascii_lowercase().find("when i say") {
        let rest = &g[idx..];
        let end = rest.find(['.', '\n']).unwrap_or(rest.len().min(120));
        return rest[..end].trim().to_string();
    }
    g.lines()
        .next()
        .unwrap_or(g)
        .chars()
        .take(100)
        .collect()
}

fn synthesize_skill_body(guidance: &str, when: Option<&str>) -> String {
    let when_line = when.unwrap_or("as described by the user");
    format!(
        r#"# Playbook (user-authored)

## When to use
{when_line}

## User guidance (source)
{guidance}

## Procedure
1. Confirm the user's trigger matches this playbook.
2. Prefer first-class oscar tools (`tools_search` → `tools_execute`) over raw CLI.
3. Follow the user guidance above step by step.
4. Prefer least privilege and never put secrets in chat.
5. Summarize findings with concrete resource IDs / next actions.

## Output
- What was checked
- What was found (or not found)
- Recommended fix or next tool
"#
    )
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
                discovery_blurb(
                    "VPCs/VNets, subnets, IPs, SG/NSG/firewall, NACL, routes, peering, TGW, VPN, hybrid (DX/ER/Interconnect), private endpoints, NAT/IGW, prefix lists, shares, functions, and k8s addresses",
                )
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
                "broad".into(),
                "subnet".into(),
                "vpc".into(),
                "vnet".into(),
                "ip".into(),
                "cidr".into(),
                "partial".into(),
                "security-group".into(),
                "nacl".into(),
                "nsg".into(),
                "firewall".into(),
                "route".into(),
                "route-table".into(),
                "lambda".into(),
                "function".into(),
                "k8s".into(),
                "pod".into(),
                "connectivity".into(),
                "troubleshoot".into(),
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

// ─── Broad multi-cloud IP locate + status pack ─────────────────────────────

struct NetworkIpLocateMulti;
struct NetworkTroubleshootStatus;

#[async_trait]
impl Tool for NetworkIpLocateMulti {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "network.ip.locate".into(),
            name: "Multi-cloud IP / CIDR locate".into(),
            description: "Broad locate: find which VPC/subnet/ENI/address inventory owns an IP, fragment, or CIDR across AWS/GCP/Azure/k8s caches. Prefer after network.pattern.find or when narrowing from a destination IP.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "ip".into(),
                "locate".into(),
                "pattern".into(),
                "search".into(),
                "cidr".into(),
                "subnet".into(),
                "vpc".into(),
                "broad".into(),
                "discover".into(),
                "connectivity".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "pattern": { "type": "string", "description": "IP, fragment, or CIDR" },
                    "ip": { "type": "string" },
                    "query": { "type": "string" },
                    "profile_id": { "type": "string" },
                    "region": { "type": "string" },
                    "limit": { "type": "integer", "default": 50 }
                },
                "required": ["pattern"]
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, mut args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        if let Some(obj) = args.as_object_mut() {
            if !obj.contains_key("pattern") {
                if let Some(ip) = obj.get("ip").cloned().or_else(|| obj.get("query").cloned()) {
                    obj.insert("pattern".into(), ip);
                }
            }
            obj.insert("mode".into(), json!("ip_or_cidr"));
        }
        // Reuse multi network pattern find path via same scan logic
        let q = match PatternQuery::from_args(&args) {
            Ok(q) => q,
            Err(e) => return ToolResult::error(e),
        };
        let mut merged =
            oscar_core::DiscoveryResult::empty(&q.pattern, q.mode, "network.ip.locate:multi");
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
            let region = if p.cloud == Cloud::K8s {
                Some("cluster")
            } else {
                q.region.as_deref()
            };
            if let Some(inv) = load_network_cache(&ctx.config_dir, &p.id, region) {
                let mut part = scan_network_inventory(&inv, &q);
                merged.hits.append(&mut part.hits);
            }
        }
        if merged.hits.is_empty() {
            merged.partial = true;
            merged.notes.push(
                "No hits — run *.network.inventory.sync / k8s.inventory.sync then retry.".into(),
            );
        }
        merged.hits.truncate(q.limit);
        to_tool_result(discovery_tool_result(merged.finalize()))
    }
}

#[async_trait]
impl Tool for NetworkTroubleshootStatus {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "network.troubleshoot.status".into(),
            name: "Network troubleshoot status pack".into(),
            description: "Broad→narrow status snapshot: playbook steps for symptom + live node.net.status + recommended narrow pattern tools (sg/route/nacl/envoy). Does not start long CSP path jobs.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "status".into(),
                "troubleshoot".into(),
                "analyze".into(),
                "connectivity".into(),
                "broad".into(),
                "playbook".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symptom": {
                        "type": "string",
                        "default": "general",
                        "description": "dns|timeout|refused|mesh|node|cross_cloud|general"
                    },
                    "destination": { "type": "string" },
                    "source": { "type": "string" },
                    "include_node_status": { "type": "boolean", "default": true }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, ctx: &ToolContext) -> ToolResult {
        let symptom = args
            .get("symptom")
            .and_then(|v| v.as_str())
            .unwrap_or("general");
        let include_node = args
            .get("include_node_status")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);

        // Playbook steps
        let pb = NetworkTroubleshootPlaybook
            .execute(args.clone(), ctx)
            .await;

        let mut node_status = json!(null);
        if include_node {
            use crate::sync::{command_on_path, run_text_command};
            if command_on_path("ip").await {
                let def = run_text_command("ip", &["route", "show", "default"], 5)
                    .await
                    .unwrap_or_default();
                let br = run_text_command("ip", &["-br", "addr"], 5)
                    .await
                    .unwrap_or_default();
                node_status = json!({
                    "default_route_text": def.trim(),
                    "interfaces_brief": br.lines().take(20).collect::<Vec<_>>().join("\n"),
                    "tool": "node.net.status"
                });
            } else {
                node_status = json!({ "error": "ip not on PATH", "tool": "node.net.status" });
            }
        }

        let narrow = json!([
            {"layer": "broad", "tools": ["network.pattern.find", "network.ip.locate", "dns.pattern.find", "dns.where", "k8s.resources.pattern.search"]},
            {"layer": "cloud_narrow", "tools": [
                "aws.network.vpc.pattern", "aws.network.subnet.pattern", "aws.network.sg.pattern", "aws.network.nacl.pattern",
                "aws.network.route_table.pattern", "aws.network.route.pattern", "aws.compute.function.pattern",
                "gcp.network.vpc.pattern", "gcp.network.firewall.pattern", "gcp.network.route.pattern",
                "azure.network.vnet.pattern", "azure.network.nsg.pattern", "azure.network.route.pattern"
            ]},
            {"layer": "k8s_narrow", "tools": [
                "k8s.pods.pattern.search", "k8s.services.pattern.search", "k8s.endpoints.pattern.search",
                "k8s.nodes.pattern.search", "k8s.networkpolicy.pattern.search", "k8s.deployments.pattern.search",
                "k8s.ingress.pattern.search", "k8s.namespaces.pattern.search"
            ]},
            {"layer": "mesh_narrow", "tools": ["mesh.envoy.diagnose", "mesh.envoy.clusters.pattern", "mesh.envoy.stats.pattern"]},
            {"layer": "node", "tools": ["node.net.status", "node.net.route.get", "node.net.ss", "node.bpf.net.show"]},
            {"layer": "path_analyze", "tools": [
                "aws.network.path.analyze", "gcp.network.connectivity.test",
                "azure.network.path.troubleshoot", "azure.network.next_hop"
            ]}
        ]);

        ToolResult::success(
            format!(
                "Network status pack symptom={symptom}; playbook_ok={}; use narrow tools after broad locate",
                pb.ok
            ),
            json!({
                "format": "NetworkTroubleshootStatus",
                "symptom": symptom,
                "playbook": pb.data,
                "node_status": node_status,
                "ladder": narrow,
                "how_to_use": "1) broad pattern.find / ip.locate  2) narrow kind.pattern  3) path.analyze / envoy.diagnose  4) node/bpf"
            }),
        )
    }
}

// ─── Symptom → tool playbook (P0) ──────────────────────────────────────────

struct NetworkTroubleshootPlaybook;

#[async_trait]
impl Tool for NetworkTroubleshootPlaybook {
    fn meta(&self) -> &ToolMeta {
        static META: std::sync::OnceLock<ToolMeta> = std::sync::OnceLock::new();
        META.get_or_init(|| ToolMeta {
            id: "network.troubleshoot.playbook".into(),
            name: "Network troubleshoot playbook".into(),
            description: "Symptom → ordered tools_search/execute plan for network, node, DNS, mesh (Envoy), BPF, and CSP path/connectivity. Start here when the user reports timeout, DNS fail, connection refused, mesh 503, or node issues.".into(),
            domain: ToolDomain::Network,
            clouds: vec![Cloud::Multi, Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s],
            capability: Capability::Read,
            tags: vec![
                "network".into(),
                "troubleshoot".into(),
                "playbook".into(),
                "connectivity".into(),
                "status".into(),
                "analyze".into(),
                "path".into(),
                "dns".into(),
                "node".into(),
                "envoy".into(),
                "mesh".into(),
                "bpf".into(),
                "timeout".into(),
                "reachability".into(),
            ],
            input_schema: json!({
                "type": "object",
                "properties": {
                    "symptom": {
                        "type": "string",
                        "description": "dns | timeout | refused | mesh | node | cross_cloud | general",
                        "default": "general"
                    },
                    "source": { "type": "string" },
                    "destination": { "type": "string" },
                    "port": { "type": "integer", "default": 443 }
                }
            }),
            output_schema: None,
        })
    }

    async fn execute(&self, args: serde_json::Value, _ctx: &ToolContext) -> ToolResult {
        let symptom = args
            .get("symptom")
            .and_then(|v| v.as_str())
            .unwrap_or("general")
            .to_ascii_lowercase();
        let source = args.get("source").and_then(|v| v.as_str()).unwrap_or("");
        let dest = args
            .get("destination")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let port = args.get("port").and_then(|v| v.as_u64()).unwrap_or(443);

        let steps = match symptom.as_str() {
            "dns" => vec![
                json!({"step":1,"title":"Where does the name resolve?","tools":["dns.where","dns.pattern.find","dns.resolve.public","node.net.dns.lookup"],"hint":"Private vs public; then CSP zone inventory."}),
                json!({"step":2,"title":"Private DNS / hybrid forwarding","tools":["dns.forwarding.map","aws.dns.resolver.pattern.search","gcp.dns.policy.pattern.search","azure.dns.private_resolver.pattern.search"],"hint":"Resolver rules, VNet links, Cloud DNS policies."}),
                json!({"step":3,"title":"Cluster DNS","tools":["k8s.coredns.discover","k8s.pods.pattern.search"],"hint":"CoreDNS pods/logs if in-cluster name."}),
            ],
            "timeout" => vec![
                json!({"step":1,"title":"Locate endpoints","tools":["network.pattern.find","aws.network.ip.locate","gcp.network.ip.locate","azure.network.ip.locate","k8s.pods.pattern.search"],"hint":format!("Locate `{source}` and `{dest}` (partial/IP).")}),
                json!({"step":2,"title":"Routes + security","tools":["aws.network.route.pattern","aws.network.sg.pattern","aws.network.nacl.pattern","gcp.network.route.pattern","gcp.network.firewall.pattern","azure.network.route.pattern","azure.network.nsg.pattern","node.net.route.get"],"hint":"SG/NACL/NSG and route tables; node fib lookup for local."}),
                json!({"step":3,"title":"CSP connectivity / path analyze","tools":["aws.network.path.analyze","aws.network.access.analyze","gcp.network.connectivity.test","azure.network.path.troubleshoot","azure.network.next_hop"],"hint":format!("Path {source} → {dest}:{port}")}),
                json!({"step":4,"title":"Live node / BPF if config looks OK","tools":["node.net.status","node.net.ping","node.net.traceroute","node.bpf.progs.list","node.bpf.net.show"],"hint":"XDP/tc attachments after path analyzer clean."}),
            ],
            "refused" => vec![
                json!({"step":1,"title":"Is anything listening?","tools":["node.net.ss","k8s.services.pattern.search","k8s.pods.pattern.search"],"hint":format!("ss filter :{port}; check Service/endpoints.")}),
                json!({"step":2,"title":"Security groups / NSG","tools":["aws.network.sg.pattern","azure.network.nsg.pattern","gcp.network.firewall.pattern"],"hint":"Ingress allow for dest port."}),
                json!({"step":3,"title":"Mesh upstream health","tools":["mesh.envoy.ready","mesh.envoy.clusters","mesh.envoy.diagnose"],"hint":"503 no healthy upstream often shows here."}),
            ],
            "mesh" | "envoy" | "istio" | "503" => vec![
                json!({"step":1,"title":"Envoy readiness + diagnose pack","tools":["mesh.envoy.diagnose","mesh.envoy.ready","mesh.envoy.server_info"],"hint":"pod=ns/name for sidecar; admin_url for bare Envoy :9901."}),
                json!({"step":2,"title":"Clusters + stats","tools":["mesh.envoy.clusters","mesh.envoy.stats","mesh.envoy.listeners"],"hint":"unhealthy_only; filter upstream_rq_5xx / cx_connect_fail."}),
                json!({"step":3,"title":"Config dump (summarized)","tools":["mesh.envoy.config_dump"],"hint":"name_filter for route/cluster; avoid full dump in chat."}),
                json!({"step":4,"title":"Upstream path outside mesh","tools":["network.pattern.find","aws.network.path.analyze","dns.where"],"hint":"If Envoy healthy but upstream fails — cloud path + DNS."}),
            ],
            "node" | "bpf" => vec![
                json!({"step":1,"title":"Node network status","tools":["node.net.status","node.net.route.table","node.net.route.get"],"hint":"Default route, MTU, DNS resolvers."}),
                json!({"step":2,"title":"Sockets + L2","tools":["node.net.ss","node.net.neigh","node.net.ping"],"hint":"Listening ports; ARP for same-subnet."}),
                json!({"step":3,"title":"BPF attachments","tools":["node.bpf.progs.list","node.bpf.net.show"],"hint":"XDP/tc programs that can drop traffic."}),
                json!({"step":4,"title":"Path hops","tools":["node.net.traceroute"],"hint":"mtr/traceroute from the node."}),
            ],
            "cross_cloud" | "hybrid" => vec![
                json!({"step":1,"title":"Multi-cloud narrative","tools":["multicloud.path.narrative","multicloud.path.orchestrate","multicloud.interconnect.awareness"],"hint":"Ordered CSP hops + interconnect."}),
                json!({"step":2,"title":"DNS forwarding map","tools":["dns.forwarding.map","dns.where"],"hint":"Private zones across CSPs."}),
                json!({"step":3,"title":"Per-CSP path","tools":["aws.network.path.analyze","gcp.network.connectivity.test","azure.network.path.troubleshoot"],"hint":"One hop at a time."}),
            ],
            _ => vec![
                json!({"step":1,"title":"Access + locate","tools":["system.access.review","network.pattern.find","dns.where"],"hint":"Know profile; find resource ownership."}),
                json!({"step":2,"title":"DNS if name involved","tools":["dns.pattern.find","node.net.dns.lookup"],"hint":"Skip if pure IP."}),
                json!({"step":3,"title":"CSP path / connectivity test","tools":["aws.network.path.analyze","gcp.network.connectivity.test","azure.network.path.troubleshoot","azure.network.next_hop"],"hint":"Reachability / Connectivity Tests / Network Watcher."}),
                json!({"step":4,"title":"Node + mesh if needed","tools":["node.net.status","mesh.envoy.diagnose","k8s.cni.detect"],"hint":"Local fib/sockets; Envoy; CNI."}),
                json!({"step":5,"title":"BPF live signals","tools":["node.bpf.net.show","node.bpf.progs.list"],"hint":"When config path is clean but packets still fail."}),
            ],
        };

        ToolResult::success(
            format!(
                "Playbook symptom={symptom}: {} steps — execute tools in order via tools_execute",
                steps.len()
            ),
            json!({
                "format": "NetworkTroubleshootPlaybook",
                "symptom": symptom,
                "source": source,
                "destination": dest,
                "port": port,
                "steps": steps,
                "rule": "timeout/reset → network path; 403/401 after connect → IAM/RBAC; DNS fail before L4 → DNS first",
                "how_to_use": "For each step, tools_search if unsure then tools_execute with profile_id when multi-account."
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

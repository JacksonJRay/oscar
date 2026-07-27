use oscar_core::{Cloud, ClusterRef, OscarError, OscarResult, Paths};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Profile {
    pub id: String,
    pub cloud: Cloud,
    pub label: String,
    /// Account / project / subscription id (non-secret).
    pub account_ref: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_region: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub clusters: Vec<ClusterRef>,
    /// Keychain entry namespace for this profile's secrets.
    pub secret_keyring_id: String,
}

impl Profile {
    pub fn new(cloud: Cloud, label: impl Into<String>, account_ref: impl Into<String>) -> Self {
        let label = label.into();
        let id = Self::make_id(cloud, &label);
        let secret_keyring_id = format!("oscar/{id}");
        Self {
            id,
            cloud,
            label,
            account_ref: account_ref.into(),
            default_region: None,
            clusters: vec![],
            secret_keyring_id,
        }
    }

    /// Build a CSP-prefixed profile id: `aws-prod`, `gcp-sandbox`, `azure-corp`, `k8s-prod`.
    /// Strips a redundant leading cloud prefix from `label` so we never get `aws-aws-prod`.
    pub fn make_id(cloud: Cloud, label: &str) -> String {
        let prefix = cloud.id_prefix();
        let mut slug = label
            .to_ascii_lowercase()
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
            .collect::<String>();
        while slug.starts_with('-') {
            slug = slug.trim_start_matches('-').to_string();
        }
        // Drop leading "aws-" / "gcp-" / etc. if the user already included it in the label.
        for p in ["aws-", "gcp-", "azure-", "az-", "gcloud-", "k8s-", "kube-", "multi-"] {
            if slug.starts_with(p) {
                slug = slug[p.len()..].to_string();
                break;
            }
        }
        if slug.is_empty() {
            slug = "default".into();
        }
        format!("{prefix}-{slug}")
    }

    /// Ensure an explicit id is namespaced under the correct CSP (disambiguate aws vs azure vs gcp).
    pub fn normalize_id(cloud: Cloud, id: &str) -> String {
        let id = id.trim().to_ascii_lowercase();
        let prefix = format!("{}-", cloud.id_prefix());
        if id.starts_with(&prefix) {
            return id;
        }
        // Reject / re-prefix if id claims a *different* CSP.
        for c in [Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s, Cloud::Multi] {
            let p = format!("{}-", c.id_prefix());
            if id.starts_with(&p) && c != cloud {
                // strip wrong prefix and re-apply correct one
                let rest = &id[p.len()..];
                return Self::make_id(cloud, rest);
            }
        }
        Self::make_id(cloud, &id)
    }

    /// Human one-liner with CSP tag for agent/CLI lists.
    pub fn display_line(&self) -> String {
        let region = self
            .default_region
            .as_deref()
            .map(|r| format!(" region={r}"))
            .unwrap_or_default();
        format!(
            "{} id={} · {}={} · label={}{}",
            self.cloud.tag(),
            self.id,
            self.cloud.account_kind(),
            self.account_ref,
            self.label,
            region
        )
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProfilesFile {
    #[serde(default)]
    pub profiles: Vec<Profile>,
}

pub struct ProfileStore {
    path: std::path::PathBuf,
    data: ProfilesFile,
}

impl ProfileStore {
    pub fn load(paths: &Paths) -> OscarResult<Self> {
        Self::load_path(&paths.profiles_file)
    }

    pub fn load_path(path: &Path) -> OscarResult<Self> {
        if !path.exists() {
            return Ok(Self {
                path: path.to_path_buf(),
                data: ProfilesFile::default(),
            });
        }
        let raw = fs::read_to_string(path)?;
        let data: ProfilesFile = toml::from_str(&raw)?;
        Ok(Self {
            path: path.to_path_buf(),
            data,
        })
    }

    pub fn save(&self) -> OscarResult<()> {
        if let Some(parent) = self.path.parent() {
            fs::create_dir_all(parent)?;
        }
        let raw = toml::to_string_pretty(&self.data)
            .map_err(|e| OscarError::Config(format!("serialize profiles: {e}")))?;
        fs::write(&self.path, raw)?;
        Ok(())
    }

    pub fn list(&self) -> &[Profile] {
        &self.data.profiles
    }

    pub fn get(&self, id: &str) -> Option<&Profile> {
        self.data.profiles.iter().find(|p| p.id == id)
    }

    pub fn upsert(&mut self, profile: Profile) {
        if let Some(existing) = self.data.profiles.iter_mut().find(|p| p.id == profile.id) {
            *existing = profile;
        } else {
            self.data.profiles.push(profile);
        }
    }

    pub fn remove(&mut self, id: &str) -> bool {
        let before = self.data.profiles.len();
        self.data.profiles.retain(|p| p.id != id);
        self.data.profiles.len() != before
    }

    /// Find a profile by cloud + account id (for multi-account pivot).
    pub fn find_by_account(&self, cloud: Cloud, account_ref: &str) -> Option<&Profile> {
        let want = account_ref.trim();
        if want.is_empty()
            || want.eq_ignore_ascii_case("pending")
            || want.eq_ignore_ascii_case("unknown")
        {
            return None;
        }
        self.data
            .profiles
            .iter()
            .find(|p| p.cloud == cloud && p.account_ref.trim() == want)
    }

    /// Ensure a profile exists for `cloud` + `label` (or explicit id / account). Updates account/region when provided.
    /// Returns `(profile, created)` where `created` is true if a new row was inserted.
    ///
    /// Match order: explicit `profile_id` → same cloud+account → cloud+label id → insert new.
    /// Multiple profiles per cloud are supported (multi-account pivot).
    pub fn ensure_profile(
        &mut self,
        cloud: Cloud,
        label: impl Into<String>,
        account_ref: impl Into<String>,
        region: Option<String>,
        profile_id: Option<&str>,
    ) -> (Profile, bool) {
        let label = label.into();
        let account_ref = account_ref.into();
        if let Some(id) = profile_id {
            let id = Profile::normalize_id(cloud, id);
            if let Some(existing) = self.data.profiles.iter_mut().find(|p| p.id == id) {
                if !account_ref.is_empty() && account_ref != "unknown" && account_ref != "pending" {
                    existing.account_ref = account_ref;
                }
                if let Some(r) = region {
                    existing.default_region = Some(r);
                }
                return (existing.clone(), false);
            }
            let mut p = Profile::new(cloud, label, account_ref);
            p.id = id.clone();
            p.secret_keyring_id = format!("oscar/{id}");
            p.default_region = region;
            self.upsert(p.clone());
            return (p, true);
        }
        // Prefer reusing the profile already bound to this account (multi-account).
        if let Some(existing) = self
            .data
            .profiles
            .iter_mut()
            .find(|p| {
                p.cloud == cloud
                    && !account_ref.is_empty()
                    && account_ref != "pending"
                    && account_ref != "unknown"
                    && p.account_ref.trim() == account_ref.trim()
            })
        {
            if let Some(r) = region {
                existing.default_region = Some(r);
            }
            if existing.label != label && label != "default" {
                existing.label = label;
            }
            return (existing.clone(), false);
        }
        // Match by cloud+label id convention or existing cloud+label
        let provisional = Profile::new(cloud, &label, &account_ref);
        if let Some(existing) = self
            .data
            .profiles
            .iter_mut()
            .find(|p| p.id == provisional.id || (p.cloud == cloud && p.label == label))
        {
            if !account_ref.is_empty() && account_ref != "unknown" && account_ref != "pending" {
                existing.account_ref = account_ref;
            }
            if let Some(r) = region {
                existing.default_region = Some(r);
            }
            return (existing.clone(), false);
        }
        let mut p = provisional;
        p.default_region = region;
        self.upsert(p.clone());
        (p, true)
    }

    /// Compact non-secret summary for the agent system context — **grouped by CSP**.
    pub fn agent_summary(&self) -> String {
        if self.data.profiles.is_empty() {
            return "No cloud profiles configured. Use system.access.prepare with cloud=aws|gcp|azure|k8s.".into();
        }
        let mut lines = vec![
            "Known cloud profiles (metadata only; secrets in OS keychain per profile).".into(),
            "Ids are CSP-prefixed so they never collide: aws-… · gcp-… · azure-… · k8s-…".into(),
            "Filter tools/review by cloud; pass profile_id when pivoting accounts.".into(),
        ];
        for cloud in [Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s, Cloud::Multi] {
            let group: Vec<&Profile> = self
                .data
                .profiles
                .iter()
                .filter(|p| p.cloud == cloud)
                .collect();
            if group.is_empty() {
                continue;
            }
            lines.push(format!(
                "\n### {} profiles ({}) — account field = {}",
                cloud.display_name(),
                cloud.tag(),
                cloud.account_kind()
            ));
            for p in group {
                let clusters = if p.clusters.is_empty() {
                    String::new()
                } else {
                    format!(
                        " clusters=[{}]",
                        p.clusters
                            .iter()
                            .map(|c| c.name.as_str())
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                lines.push(format!("- {}{}", p.display_line(), clusters));
            }
        }
        lines.join("\n")
    }

    /// Profiles grouped by CSP for JSON tools (access.review / profiles.list).
    pub fn by_cloud_json(&self) -> serde_json::Value {
        use serde_json::json;
        let mut map = serde_json::Map::new();
        for cloud in [Cloud::Aws, Cloud::Gcp, Cloud::Azure, Cloud::K8s, Cloud::Multi] {
            let rows: Vec<_> = self
                .data
                .profiles
                .iter()
                .filter(|p| p.cloud == cloud)
                .map(|p| {
                    json!({
                        "csp": cloud.id_prefix(),
                        "csp_tag": cloud.tag(),
                        "csp_name": cloud.display_name(),
                        "id": p.id,
                        "label": p.label,
                        "account_kind": cloud.account_kind(),
                        "account_ref": p.account_ref,
                        "default_region": p.default_region,
                        "display": p.display_line(),
                    })
                })
                .collect();
            if !rows.is_empty() {
                map.insert(cloud.id_prefix().to_string(), json!(rows));
            }
        }
        serde_json::Value::Object(map)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use oscar_core::Cloud;

    #[test]
    fn ensure_profile_creates_and_updates() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("profiles.toml");
        let mut store = ProfileStore::load_path(&path).unwrap();
        let (p1, created) = store.ensure_profile(
            Cloud::Aws,
            "prod",
            "111122223333",
            Some("us-east-1".into()),
            None,
        );
        assert!(created);
        assert_eq!(p1.id, "aws-prod");
        assert_eq!(p1.account_ref, "111122223333");
        store.save().unwrap();

        let mut store2 = ProfileStore::load_path(&path).unwrap();
        let (p2, created2) = store2.ensure_profile(
            Cloud::Aws,
            "prod",
            "111122223333",
            Some("eu-west-1".into()),
            None,
        );
        assert!(!created2);
        assert_eq!(p2.default_region.as_deref(), Some("eu-west-1"));
    }

    #[test]
    fn profile_ids_are_csp_distinct() {
        let aws = Profile::new(Cloud::Aws, "prod", "111");
        let gcp = Profile::new(Cloud::Gcp, "prod", "my-proj");
        let azure = Profile::new(Cloud::Azure, "prod", "sub-1");
        assert_eq!(aws.id, "aws-prod");
        assert_eq!(gcp.id, "gcp-prod");
        assert_eq!(azure.id, "azure-prod");
        assert_ne!(aws.id, gcp.id);
        assert!(aws.display_line().contains("[AWS]"));
        assert!(gcp.display_line().contains("[GCP]"));
        assert!(azure.display_line().contains("[AZURE]"));
        // Wrong prefix corrected
        assert_eq!(Profile::normalize_id(Cloud::Aws, "azure-foo"), "aws-foo");
        assert_eq!(Profile::normalize_id(Cloud::Gcp, "sandbox"), "gcp-sandbox");
    }
}

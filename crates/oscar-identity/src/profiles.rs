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
        let id = format!(
            "{}-{}",
            cloud,
            label
                .to_ascii_lowercase()
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '-' })
                .collect::<String>()
        );
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

    /// Compact non-secret summary for the agent system context.
    pub fn agent_summary(&self) -> String {
        if self.data.profiles.is_empty() {
            return "No cloud profiles configured.".into();
        }
        let mut lines = vec!["Known cloud profiles (metadata only; secrets in keychain):".to_string()];
        for p in &self.data.profiles {
            let region = p
                .default_region
                .as_deref()
                .map(|r| format!(" region={r}"))
                .unwrap_or_default();
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
            lines.push(format!(
                "- id={} cloud={} label={} account={}{}{}",
                p.id, p.cloud, p.label, p.account_ref, region, clusters
            ));
        }
        lines.join("\n")
    }
}

//! Identities / access panel — what oscar can reach and whether creds are still valid.

use oscar_identity::{IdentityEntry, IdentityInventory, IdentityKind, Validity};

pub struct IdentitiesPane {
    pub inventory: IdentityInventory,
    pub selected: usize,
    pub scroll: usize,
    pub probing: bool,
    pub flash: Option<String>,
    /// Filter: all | aws | gcp | azure | k8s | llm
    pub filter: FilterCloud,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterCloud {
    All,
    Aws,
    Gcp,
    Azure,
    K8s,
    Llm,
}

impl FilterCloud {
    pub const ALL: [FilterCloud; 6] = [
        FilterCloud::All,
        FilterCloud::Aws,
        FilterCloud::Gcp,
        FilterCloud::Azure,
        FilterCloud::K8s,
        FilterCloud::Llm,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::All => "all",
            Self::Aws => "aws",
            Self::Gcp => "gcp",
            Self::Azure => "azure",
            Self::K8s => "k8s",
            Self::Llm => "llm",
        }
    }

    pub fn matches(self, cloud: &str) -> bool {
        match self {
            Self::All => true,
            Self::Aws => cloud == "aws",
            Self::Gcp => cloud == "gcp",
            Self::Azure => cloud == "azure",
            Self::K8s => cloud == "k8s",
            Self::Llm => cloud == "llm",
        }
    }

    pub fn next(self) -> Self {
        let i = Self::ALL.iter().position(|x| *x == self).unwrap_or(0);
        Self::ALL[(i + 1) % Self::ALL.len()]
    }
}

impl IdentitiesPane {
    pub fn open(inventory: IdentityInventory) -> Self {
        Self {
            inventory,
            selected: 0,
            scroll: 0,
            probing: false,
            flash: Some("r refresh/validate · ←→ filter · Enter detail · Esc close".into()),
            filter: FilterCloud::All,
        }
    }

    pub fn visible(&self) -> Vec<&IdentityEntry> {
        self.inventory
            .entries
            .iter()
            .filter(|e| self.filter.matches(&e.cloud))
            .collect()
    }

    pub fn ensure_bounds(&mut self) {
        let n = self.visible().len();
        if n == 0 {
            self.selected = 0;
            return;
        }
        if self.selected >= n {
            self.selected = n - 1;
        }
    }

    pub fn move_sel(&mut self, delta: i32) {
        let n = self.visible().len() as i32;
        if n == 0 {
            return;
        }
        let mut i = self.selected as i32 + delta;
        if i < 0 {
            i = n - 1;
        } else if i >= n {
            i = 0;
        }
        self.selected = i as usize;
    }

    pub fn apply_inventory(&mut self, inv: IdentityInventory) {
        self.inventory = inv;
        self.probing = false;
        self.flash = Some(self.inventory.summary_line());
        self.ensure_bounds();
    }

    pub fn selected_entry(&self) -> Option<&IdentityEntry> {
        let vis = self.visible();
        vis.get(self.selected).copied()
    }

    pub fn format_row(e: &IdentityEntry, selected: bool) -> String {
        let cur = if selected { "›" } else { " " };
        let kind = match e.kind {
            IdentityKind::Profile => "prof",
            IdentityKind::BinarySession => "bin ",
            IdentityKind::LlmProvider => "llm ",
            IdentityKind::Cluster => "k8s ",
        };
        let exp = e
            .expires_in_secs
            .map(|s| {
                if s <= 0 {
                    " exp!".into()
                } else if s < 3600 {
                    format!(" {}m", s / 60)
                } else {
                    format!(" {}h", s / 3600)
                }
            })
            .unwrap_or_default();
        format!(
            "{cur} [{:>3}] {:4} {:6} {:18} {}{} · {}",
            e.validity.glyph(),
            kind,
            e.cloud,
            truncate(&e.id, 18),
            e.auth_source,
            exp,
            truncate(&e.detail, 48)
        )
    }

    pub fn detail_lines(e: &IdentityEntry) -> Vec<String> {
        let mut lines = vec![
            format!("id:           {}", e.id),
            format!("kind:         {:?}", e.kind),
            format!("cloud:        {}", e.cloud),
            format!("label:        {}", e.label),
            format!(
                "account_ref:  {}",
                e.account_ref.as_deref().unwrap_or("—")
            ),
            format!("region:       {}", e.region.as_deref().unwrap_or("—")),
            format!("auth_source:  {}", e.auth_source),
            format!("validity:     {}", e.validity.as_str()),
            format!("detail:       {}", e.detail),
            format!(
                "secrets:      {}",
                if e.secrets_present.is_empty() {
                    "(none — values never shown)".into()
                } else {
                    format!("{} (names only)", e.secrets_present.join(", "))
                }
            ),
        ];
        if let Some(exp) = e.expires_at_unix {
            lines.push(format!(
                "expires_at:   unix {} ({})",
                exp,
                e.expires_in_secs
                    .map(|s| {
                        if s <= 0 {
                            "EXPIRED".into()
                        } else {
                            format!("in {s}s")
                        }
                    })
                    .unwrap_or_else(|| "?".into())
            ));
        }
        if !e.clusters.is_empty() {
            lines.push("clusters:".into());
            for c in &e.clusters {
                lines.push(format!(
                    "  [{}] {} ctx={} — {}",
                    c.validity.glyph(),
                    c.name,
                    c.context.as_deref().unwrap_or("—"),
                    c.detail
                ));
            }
        }
        lines.push(String::new());
        lines.push("Secrets never leave the OS keychain into this panel.".into());
        lines
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", s.chars().take(n.saturating_sub(1)).collect::<String>())
    }
}

#[allow(dead_code)]
pub fn validity_style_hint(v: Validity) -> &'static str {
    v.as_str()
}

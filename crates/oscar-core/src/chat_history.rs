//! Persistent chat sessions (Grok Build–style history).
//!
//! Layout under `~/.config/oscar/sessions/`:
//! - `index.json` — lightweight list for UI
//! - `<id>.json` — full session (messages + UI transcript)
//! - `current` — active session id (plain text)
//! - `compaction_checkpoints/<session_id>/…` — pre-compact snapshots (Grok parity)

use crate::error::{OscarError, OscarResult};
use crate::messages::Message;
use crate::Paths;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use uuid::Uuid;

const INDEX_FILE: &str = "index.json";
const CURRENT_FILE: &str = "current";
const MAX_INDEX: usize = 200;

/// One line in the TUI transcript (display history).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TranscriptLine {
    /// user | assistant | thinking | tool | system | error
    pub kind: String,
    pub text: String,
}

/// Lightweight row for listing sessions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub provider: String,
    pub model: String,
    pub message_count: usize,
    /// Snippet of last user text for list UI.
    #[serde(default)]
    pub preview: String,
}

/// Full chat session on disk.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChatSession {
    pub id: String,
    pub title: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    #[serde(default)]
    pub provider: String,
    #[serde(default)]
    pub model: String,
    #[serde(default)]
    pub mode: String,
    /// Agent message history (for LLM resume).
    pub messages: Vec<Message>,
    /// TUI scrollback (what the user saw).
    #[serde(default)]
    pub transcript: Vec<TranscriptLine>,
    #[serde(default)]
    pub active_skills: Vec<String>,
}

impl StoredChatSession {
    pub fn new(provider: impl Into<String>, model: impl Into<String>, mode: impl Into<String>) -> Self {
        let now = Utc::now();
        let id = Uuid::new_v4().to_string();
        Self {
            id: id.clone(),
            title: "New chat".into(),
            created_at: now,
            updated_at: now,
            provider: provider.into(),
            model: model.into(),
            mode: mode.into(),
            messages: vec![],
            transcript: vec![TranscriptLine {
                kind: "system".into(),
                text: format!(
                    "oscar session `{id}` — history saved under ~/.config/oscar/sessions/ · /history · /new"
                ),
            }],
            active_skills: vec![],
        }
    }

    pub fn touch(&mut self) {
        self.updated_at = Utc::now();
    }

    /// Derive title from first non-empty user message if still default.
    pub fn maybe_set_title_from_user(&mut self, user_text: &str) {
        if self.title == "New chat" || self.title.is_empty() {
            let t = user_text.trim();
            if !t.is_empty() {
                let mut title = t.chars().take(72).collect::<String>();
                if t.chars().count() > 72 {
                    title.push('…');
                }
                self.title = title;
            }
        }
    }

    pub fn summary(&self) -> SessionSummary {
        let preview = self
            .messages
            .iter()
            .rev()
            .find(|m| m.role == crate::messages::MessageRole::User)
            .map(|m| {
                let t = m.content.trim();
                if t.chars().count() > 80 {
                    format!("{}…", t.chars().take(80).collect::<String>())
                } else {
                    t.to_string()
                }
            })
            .or_else(|| {
                self.transcript
                    .iter()
                    .rev()
                    .find(|l| l.kind == "user")
                    .map(|l| l.text.chars().take(80).collect())
            })
            .unwrap_or_default();
        SessionSummary {
            id: self.id.clone(),
            title: self.title.clone(),
            created_at: self.created_at,
            updated_at: self.updated_at,
            provider: self.provider.clone(),
            model: self.model.clone(),
            message_count: self
                .messages
                .iter()
                .filter(|m| m.role != crate::messages::MessageRole::System)
                .count(),
            preview,
        }
    }
}

fn session_path(dir: &Path, id: &str) -> PathBuf {
    // sanitize id for path
    let safe: String = id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    dir.join(format!("{safe}.json"))
}

fn index_path(dir: &Path) -> PathBuf {
    dir.join(INDEX_FILE)
}

fn current_path(dir: &Path) -> PathBuf {
    dir.join(CURRENT_FILE)
}

/// Save full session + update index + mark current.
pub fn save_session(paths: &Paths, session: &StoredChatSession) -> OscarResult<()> {
    paths.ensure()?;
    let dir = &paths.sessions_dir;
    fs::create_dir_all(dir)?;
    let path = session_path(dir, &session.id);
    let raw = serde_json::to_string_pretty(session)
        .map_err(|e| OscarError::Config(format!("serialize session: {e}")))?;
    fs::write(&path, raw)?;
    set_current_session_id(paths, &session.id)?;
    update_index(paths, &session.summary())?;
    Ok(())
}

/// Pre-compact snapshot (Grok Build `sessions/…/compaction_checkpoints`).
///
/// Best-effort: failures are returned so callers can log and continue compacting.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompactionCheckpoint {
    pub session_id: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub message_count: usize,
    pub messages: Vec<Message>,
}

/// Save a pre-compact checkpoint under
/// `sessions/compaction_checkpoints/<session_id>/<timestamp>_<reason>.json`.
pub fn save_compaction_checkpoint(
    paths: &Paths,
    session_id: &str,
    reason: &str,
    messages: &[Message],
) -> OscarResult<PathBuf> {
    paths.ensure()?;
    let safe_id: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let safe_reason: String = reason
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    let dir = paths
        .sessions_dir
        .join("compaction_checkpoints")
        .join(&safe_id);
    fs::create_dir_all(&dir)?;
    let ts = Utc::now().format("%Y%m%dT%H%M%S%.3fZ");
    let path = dir.join(format!("{ts}_{safe_reason}.json"));
    let cp = CompactionCheckpoint {
        session_id: session_id.to_string(),
        reason: reason.to_string(),
        created_at: Utc::now(),
        message_count: messages.len(),
        messages: messages.to_vec(),
    };
    let raw = serde_json::to_string_pretty(&cp)
        .map_err(|e| OscarError::Config(format!("serialize compaction checkpoint: {e}")))?;
    fs::write(&path, raw)?;
    Ok(path)
}

pub fn load_session(paths: &Paths, id: &str) -> OscarResult<StoredChatSession> {
    let path = session_path(&paths.sessions_dir, id);
    if !path.exists() {
        return Err(OscarError::Config(format!("session not found: {id}")));
    }
    let raw = fs::read_to_string(&path)?;
    let mut s: StoredChatSession = serde_json::from_str(&raw)
        .map_err(|e| OscarError::Config(format!("parse session {id}: {e}")))?;
    // Rewrite pre-rebrand "mind session" banners in UI transcript.
    if rebrand_legacy_mind_transcript(&mut s) {
        // Best-effort persist so the TUI does not keep showing mind branding.
        let _ = save_session(paths, &s);
    }
    Ok(s)
}

/// Replace leftover mind → oscar branding in session UI transcript lines.
/// Returns true if any line was changed.
pub fn rebrand_legacy_mind_transcript(session: &mut StoredChatSession) -> bool {
    let mut changed = false;
    for line in &mut session.transcript {
        let next = rebrand_mind_text(&line.text);
        if next != line.text {
            line.text = next;
            changed = true;
        }
    }
    changed
}

fn rebrand_mind_text(text: &str) -> String {
    text.replace("mind session", "oscar session")
        .replace("Mind session", "oscar session")
        .replace("MIND session", "oscar session")
        .replace("~/.config/mind/sessions", "~/.config/oscar/sessions")
        .replace("~/.config/mind", "~/.config/oscar")
        .replace("/config/mind/", "/config/oscar/")
}

pub fn delete_session(paths: &Paths, id: &str) -> OscarResult<()> {
    let path = session_path(&paths.sessions_dir, id);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    // Remove from index
    let mut index = load_index(paths)?;
    index.retain(|s| s.id != id);
    write_index(paths, &index)?;
    if current_session_id(paths).as_deref() == Some(id) {
        let _ = fs::remove_file(current_path(&paths.sessions_dir));
        if let Some(next) = index.first() {
            let _ = set_current_session_id(paths, &next.id);
        }
    }
    Ok(())
}

pub fn list_sessions(paths: &Paths) -> OscarResult<Vec<SessionSummary>> {
    let mut index = load_index(paths)?;
    // Merge any files missing from index
    if let Ok(rd) = fs::read_dir(&paths.sessions_dir) {
        for ent in rd.flatten() {
            let p = ent.path();
            if p.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            if p.file_name().and_then(|n| n.to_str()) == Some(INDEX_FILE) {
                continue;
            }
            if let Ok(raw) = fs::read_to_string(&p) {
                if let Ok(s) = serde_json::from_str::<StoredChatSession>(&raw) {
                    if !index.iter().any(|i| i.id == s.id) {
                        index.push(s.summary());
                    }
                }
            }
        }
    }
    index.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    Ok(index)
}

pub fn current_session_id(paths: &Paths) -> Option<String> {
    fs::read_to_string(current_path(&paths.sessions_dir))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

pub fn set_current_session_id(paths: &Paths, id: &str) -> OscarResult<()> {
    paths.ensure()?;
    fs::create_dir_all(&paths.sessions_dir)?;
    fs::write(current_path(&paths.sessions_dir), id)?;
    Ok(())
}

/// Load current session, or most recently updated, or None.
pub fn load_current_or_latest(paths: &Paths) -> OscarResult<Option<StoredChatSession>> {
    if let Some(id) = current_session_id(paths) {
        if let Ok(s) = load_session(paths, &id) {
            return Ok(Some(s));
        }
    }
    let list = list_sessions(paths)?;
    if let Some(first) = list.first() {
        return Ok(Some(load_session(paths, &first.id)?));
    }
    Ok(None)
}

fn load_index(paths: &Paths) -> OscarResult<Vec<SessionSummary>> {
    let path = index_path(&paths.sessions_dir);
    if !path.exists() {
        return Ok(vec![]);
    }
    let raw = fs::read_to_string(&path)?;
    let list: Vec<SessionSummary> = serde_json::from_str(&raw).unwrap_or_default();
    Ok(list)
}

fn write_index(paths: &Paths, index: &[SessionSummary]) -> OscarResult<()> {
    paths.ensure()?;
    fs::create_dir_all(&paths.sessions_dir)?;
    let raw = serde_json::to_string_pretty(index)
        .map_err(|e| OscarError::Config(format!("serialize index: {e}")))?;
    fs::write(index_path(&paths.sessions_dir), raw)?;
    Ok(())
}

fn update_index(paths: &Paths, summary: &SessionSummary) -> OscarResult<()> {
    let mut index = load_index(paths)?;
    if let Some(slot) = index.iter_mut().find(|s| s.id == summary.id) {
        *slot = summary.clone();
    } else {
        index.push(summary.clone());
    }
    index.sort_by(|a, b| b.updated_at.cmp(&a.updated_at));
    index.truncate(MAX_INDEX);
    write_index(paths, &index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn test_paths(dir: &Path) -> Paths {
        Paths {
            config_dir: dir.to_path_buf(),
            config_file: dir.join("config.toml"),
            profiles_file: dir.join("profiles.toml"),
            sessions_dir: dir.join("sessions"),
            artifacts_dir: dir.join("artifacts"),
            logs_dir: dir.join("logs"),
            mcp_credentials_file: dir.join("mcp_credentials.json"),
            auth_file: dir.join("auth.json"),
        }
    }

    #[test]
    fn rebrand_mind_session_banner() {
        let mut s = StoredChatSession::new("xai", "grok", "readonly");
        s.transcript[0].text = format!(
            "mind session `{}` — history saved under ~/.config/mind/sessions/ · /history · /new",
            s.id
        );
        assert!(rebrand_legacy_mind_transcript(&mut s));
        assert!(s.transcript[0].text.contains("oscar session"));
        assert!(s.transcript[0].text.contains("~/.config/oscar/sessions"));
        assert!(!s.transcript[0].text.contains("mind session"));
        assert!(!s.transcript[0].text.contains("~/.config/mind"));
    }

    #[test]
    fn save_load_list_roundtrip() {
        let tmp = tempdir().unwrap();
        let paths = test_paths(tmp.path());
        paths.ensure().unwrap();
        let mut s = StoredChatSession::new("xai", "grok", "readonly");
        s.messages.push(Message::user("hello dns path"));
        s.maybe_set_title_from_user("hello dns path");
        s.transcript.push(TranscriptLine {
            kind: "user".into(),
            text: "hello dns path".into(),
        });
        save_session(&paths, &s).unwrap();
        assert_eq!(current_session_id(&paths).as_deref(), Some(s.id.as_str()));
        let loaded = load_session(&paths, &s.id).unwrap();
        assert_eq!(loaded.title, "hello dns path");
        assert_eq!(loaded.messages.len(), 1);
        let list = list_sessions(&paths).unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].id, s.id);
    }

    #[test]
    fn compaction_checkpoint_roundtrip() {
        let tmp = tempdir().unwrap();
        let paths = test_paths(tmp.path());
        paths.ensure().unwrap();
        let msgs = vec![
            Message::system("sys"),
            Message::user("keep me before compact"),
        ];
        let path = save_compaction_checkpoint(&paths, "sess-abc", "auto", &msgs).unwrap();
        assert!(path.exists());
        assert!(path
            .to_string_lossy()
            .contains("compaction_checkpoints/sess-abc"));
        let raw = fs::read_to_string(&path).unwrap();
        let cp: CompactionCheckpoint = serde_json::from_str(&raw).unwrap();
        assert_eq!(cp.session_id, "sess-abc");
        assert_eq!(cp.reason, "auto");
        assert_eq!(cp.messages.len(), 2);
    }
}

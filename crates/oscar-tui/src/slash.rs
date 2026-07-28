//! Slash-command catalog + filtered popup (OpenCode / Grok Build–style).
//!
//! Typing `/` in the input bar **immediately** opens a filterable list of all
//! commands. Further characters narrow the list (`/m` → model, models, mode,
//! mcp, …). Arrow keys move selection; Enter completes/runs; Esc dismisses
//! and keeps the typed text.

/// One built-in slash command.
#[derive(Debug, Clone, Copy)]
pub struct SlashCommand {
    /// Canonical name without leading slash, e.g. `model`.
    pub name: &'static str,
    /// Short usage fragment after the name, e.g. `[list|N|id]`.
    pub usage: &'static str,
    /// One-line description for the popup.
    pub description: &'static str,
}

/// Full catalog shown in the `/` menu (order = default ranking).
pub const SLASH_COMMANDS: &[SlashCommand] = &[
    SlashCommand {
        name: "model",
        usage: "[list|N|id|provider/model]",
        description: "List or switch models across loaded providers",
    },
    SlashCommand {
        name: "models",
        usage: "",
        description: "Alias for /model list",
    },
    SlashCommand {
        name: "connect",
        usage: "[search]",
        description: "List providers to connect (models.dev)",
    },
    SlashCommand {
        name: "provider",
        usage: "",
        description: "Open provider setup (default, keys, URLs)",
    },
    SlashCommand {
        name: "providers",
        usage: "",
        description: "Alias for /provider",
    },
    SlashCommand {
        name: "settings",
        usage: "",
        description: "Open settings (tools, mode, install policy)",
    },
    SlashCommand {
        name: "identities",
        usage: "",
        description: "Cloud / LLM identity status",
    },
    SlashCommand {
        name: "skills",
        usage: "",
        description: "List available skills",
    },
    SlashCommand {
        name: "skill",
        usage: "<name>",
        description: "Activate a skill for this session",
    },
    SlashCommand {
        name: "mcp",
        usage: "[list|enable|disable|reload]",
        description: "Manage MCP servers",
    },
    SlashCommand {
        name: "thinking",
        usage: "[on|off|toggle]",
        description: "Toggle model thinking display",
    },
    SlashCommand {
        name: "context",
        usage: "",
        description: "Show context window usage",
    },
    SlashCommand {
        name: "compact",
        usage: "[keep note…]",
        description: "Compact session context now",
    },
    SlashCommand {
        name: "mode",
        usage: "[readonly|readwrite]",
        description: "Show or set execution mode",
    },
    SlashCommand {
        name: "multiline",
        usage: "[on|off|toggle]",
        description: "Toggle multiline input (Enter=newline; Shift/Alt+Enter=send)",
    },
    SlashCommand {
        name: "history",
        usage: "",
        description: "Browse previous sessions (alias for /resume)",
    },
    SlashCommand {
        name: "sessions",
        usage: "",
        description: "Alias for /resume",
    },
    SlashCommand {
        name: "new",
        usage: "",
        description: "Start a new chat (each launch is already fresh)",
    },
    SlashCommand {
        name: "clear",
        usage: "",
        description: "Alias for /new",
    },
    SlashCommand {
        name: "resume",
        usage: "[id|title]",
        description: "Browse previous sessions, or resume by id/title",
    },
    SlashCommand {
        name: "copy",
        usage: "[N|path]",
        description: "Copy last (or Nth) assistant reply",
    },
    SlashCommand {
        name: "binaries",
        usage: "",
        description: "Show detected CLI binaries",
    },
    SlashCommand {
        name: "help",
        usage: "",
        description: "Show slash command help",
    },
    SlashCommand {
        name: "quit",
        usage: "",
        description: "Exit oscar",
    },
    SlashCommand {
        name: "exit",
        usage: "",
        description: "Alias for /quit",
    },
];

/// Popup state while the user is typing a slash command.
#[derive(Debug, Clone)]
pub struct SlashMenu {
    /// Filtered command indices into [`SLASH_COMMANDS`].
    pub matches: Vec<usize>,
    /// Selected row within `matches`.
    pub selected: usize,
}

impl SlashMenu {
    /// Build menu from current input (must start with `/`).
    ///
    /// - `/` alone → full catalog
    /// - `/m` → names that start with, contain, or fuzzy-match `m` (e.g. model, models, mode, mcp)
    /// - After a space (args), menu hides so free typing works
    pub fn from_input(input: &str) -> Option<Self> {
        Self::from_input_preserving(input, None)
    }

    /// Like [`from_input`] but keeps selection on the same command when still matched.
    pub fn from_input_preserving(input: &str, keep_name: Option<&str>) -> Option<Self> {
        if !input.starts_with('/') {
            return None;
        }
        // After a space, user is typing args — hide the picker.
        if input[1..].contains(' ') {
            return None;
        }
        let query = input[1..].to_ascii_lowercase();
        let mut scored: Vec<(u8, usize)> = SLASH_COMMANDS
            .iter()
            .enumerate()
            .filter_map(|(i, c)| rank_match(&query, c.name).map(|rank| (rank, i)))
            .collect();
        // Lower rank = better; stable name order within rank.
        scored.sort_by(|a, b| {
            a.0.cmp(&b.0)
                .then_with(|| SLASH_COMMANDS[a.1].name.cmp(SLASH_COMMANDS[b.1].name))
        });
        let matches: Vec<usize> = scored.into_iter().map(|(_, i)| i).collect();
        if matches.is_empty() {
            return None;
        }
        let selected = keep_name
            .and_then(|name| {
                matches
                    .iter()
                    .position(|&i| SLASH_COMMANDS[i].name == name)
            })
            .unwrap_or(0);
        Some(Self { matches, selected })
    }

    pub fn selected_cmd(&self) -> Option<&'static SlashCommand> {
        self.matches
            .get(self.selected)
            .map(|&i| &SLASH_COMMANDS[i])
    }

    pub fn move_sel(&mut self, delta: i32) {
        if self.matches.is_empty() {
            return;
        }
        let n = self.matches.len() as i32;
        let mut i = self.selected as i32 + delta;
        if i < 0 {
            i = n - 1;
        } else if i >= n {
            i = 0;
        }
        self.selected = i as usize;
    }

    /// Fill input with `/name` or `/name ` if usage expects args.
    pub fn apply_to_input(&self) -> Option<String> {
        let cmd = self.selected_cmd()?;
        if cmd.usage.is_empty() {
            Some(format!("/{}", cmd.name))
        } else {
            Some(format!("/{} ", cmd.name))
        }
    }
}

/// Rank how well `name` matches `query` (lower is better). `None` = no match.
///
/// 0 = exact, 1 = prefix (`/mod` → model), 2 = substring, 3 = subsequence fuzzy (`/ml` → model).
fn rank_match(query: &str, name: &str) -> Option<u8> {
    if query.is_empty() {
        return Some(0);
    }
    let name = name.to_ascii_lowercase();
    if name == query {
        return Some(0);
    }
    if name.starts_with(query) {
        return Some(1);
    }
    if name.contains(query) {
        return Some(2);
    }
    // Subsequence: every query char appears in order (e.g. "ml" in "model").
    let mut it = name.chars();
    for qc in query.chars() {
        loop {
            match it.next() {
                Some(nc) if nc == qc => break,
                Some(_) => continue,
                None => return None,
            }
        }
    }
    Some(3)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_slash_lists_all() {
        let m = SlashMenu::from_input("/").expect("menu");
        assert_eq!(m.matches.len(), SLASH_COMMANDS.len());
        assert!(m.selected_cmd().is_some());
    }

    #[test]
    fn filter_m_matches_model_family() {
        let m = SlashMenu::from_input("/m").expect("menu");
        let names: Vec<&str> = m
            .matches
            .iter()
            .map(|&i| SLASH_COMMANDS[i].name)
            .collect();
        assert!(names.contains(&"model"), "{names:?}");
        assert!(names.contains(&"models"), "{names:?}");
        assert!(names.contains(&"mode"), "{names:?}");
        assert!(names.contains(&"mcp"), "{names:?}");
        // Prefix ranks first: model before compact (substring m)
        assert_eq!(names[0], "mcp"); // mcp, mode, model, models — alpha among prefix
        assert!(names.iter().any(|n| *n == "model" || *n == "models"));
    }

    #[test]
    fn filter_mod_prefix() {
        let m = SlashMenu::from_input("/mod").expect("menu");
        let names: Vec<&str> = m
            .matches
            .iter()
            .map(|&i| SLASH_COMMANDS[i].name)
            .collect();
        assert!(names.iter().all(|n| n.starts_with("mod") || n.contains("mod")));
        assert!(names.contains(&"model"));
        assert!(names.contains(&"models"));
        assert!(names.contains(&"mode"));
    }

    #[test]
    fn space_hides_menu() {
        assert!(SlashMenu::from_input("/model list").is_none());
    }

    #[test]
    fn preserve_selection() {
        let m1 = SlashMenu::from_input("/m").unwrap();
        // move to models if present
        let keep = "models";
        let m2 = SlashMenu::from_input_preserving("/mo", Some(keep)).unwrap();
        assert_eq!(m2.selected_cmd().map(|c| c.name), Some("models"));
        let _ = m1;
    }
}

/// True if this line is a known slash command (not free chat).
pub fn is_slash_command(line: &str) -> bool {
    let t = line.trim();
    if !t.starts_with('/') {
        return false;
    }
    let name = t[1..]
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    if name.is_empty() {
        return true; // bare `/` — menu only
    }
    SLASH_COMMANDS.iter().any(|c| c.name == name)
        || matches!(
            name.as_str(),
            "config" | "preferences" | "prefs" | "llm" | "api-key" | "apikey" | "identity" | "access" | "whoami" | "session"
        )
}

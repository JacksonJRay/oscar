use crate::app::{App, LineKind, PaneFocus, View};
use crate::identities::IdentitiesPane;
use crate::input::{
    cursor_row_col, input_inner_width, layout_input_rows, InputMode, INPUT_CONT, INPUT_PREFIX,
    INPUT_PREFIX_COLS,
};
use crate::settings::{ItemKind, SettingsCategory, SettingsPane};
use oscar_identity::Validity;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, ListState, Paragraph, Wrap};
use ratatui::Frame;

/// Active provider/model label for the input bar (bottom-right title).
/// Hidden entirely when no LLM credentials are loaded (`provider_ready == false`).
fn input_model_title(app: &App) -> Option<Line<'static>> {
    if !app.config.provider_ready {
        return None;
    }
    let provider = app.config.provider.as_str();
    let model = app.config.model.as_str();
    if provider.is_empty() && (model.is_empty() || model == "—") {
        return None;
    }
    let label = if model.is_empty() || model == "—" {
        format!(" {provider} ")
    } else if provider.is_empty() {
        format!(" {model} ")
    } else {
        format!(" {provider}/{model} ")
    };
    // Truncate very long model ids so the left title still has room.
    let label = if label.chars().count() > 42 {
        let truncated: String = label.chars().take(39).collect();
        format!("{truncated}… ")
    } else {
        label
    };
    Some(
        Line::from(Span::styled(
            label,
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .right_aligned(),
    )
}

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();
    app.last_term_height = area.height;
    // Input pane width ≈ full width; seed before height calc so wrap is accurate.
    app.last_input_width = area.width;
    // Grok-style growing composer: height follows soft-wrapped rows (capped).
    let input_h = match &app.view {
        View::Chat => app.composer_pane_height(),
        // Modals still reserve a short paused input chrome.
        _ => 3,
    };
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(input_h),
        ])
        .split(area);

    // Cache pane rects for mouse hit-testing (controllable panes).
    app.chat_area = Some((chunks[1].x, chunks[1].y, chunks[1].width, chunks[1].height));
    app.input_area = Some((chunks[2].x, chunks[2].y, chunks[2].width, chunks[2].height));
    app.last_input_width = chunks[2].width;
    app.sync_input_scroll();

    draw_status(f, chunks[0], app);
    draw_chat(f, chunks[1], app); // mutably caches chat_inner + chat_row_map for mouse
    draw_input(f, chunks[2], app);
    // Slash menu floats above the input bar (OpenCode / Grok Build–style).
    if matches!(app.view, View::Chat) {
        draw_slash_menu(f, chunks[2], app);
    }

    match &app.view {
        View::Settings(pane) => draw_settings_modal(f, f.area(), pane),
        View::Identities(pane) => draw_identities_modal(f, f.area(), pane, app.identity_detail),
        View::Provider(pane) => draw_provider_modal(f, f.area(), pane),
        View::Sessions(pane) => draw_sessions_modal(f, f.area(), pane),
        View::Chat => {}
    }
}

/// Popup above the input listing filtered slash commands (opens on `/`, filters as you type).
fn draw_slash_menu(f: &mut Frame, input_area: Rect, app: &App) {
    let Some(menu) = app.slash_menu.as_ref() else {
        return;
    };
    if menu.matches.is_empty() {
        return;
    }
    let max_rows = 12usize.min(menu.matches.len());
    // Keep selected row visible in a window of max_rows.
    let mut start = 0usize;
    if menu.selected >= max_rows {
        start = menu.selected + 1 - max_rows;
    }
    // Scroll window when selection is below the first page.
    if menu.selected >= start + max_rows {
        start = menu.selected + 1 - max_rows;
    }
    let end = (start + max_rows).min(menu.matches.len());
    let visible = &menu.matches[start..end];
    let height = (visible.len() as u16).saturating_add(2).max(3);
    let width = input_area.width.min(78).max(36);
    let x = input_area.x;
    let y = input_area.y.saturating_sub(height);
    let area = Rect {
        x,
        y,
        width,
        height,
    };
    f.render_widget(Clear, area);

    let filter = app
        .input
        .strip_prefix('/')
        .unwrap_or("")
        .split_whitespace()
        .next()
        .unwrap_or("");
    let title = if filter.is_empty() {
        format!(" / commands · {} ", menu.matches.len())
    } else {
        format!(" /{filter} · {} match(es) ", menu.matches.len())
    };

    let mut items: Vec<ListItem> = Vec::new();
    for (row_i, &cmd_i) in visible.iter().enumerate() {
        let cmd = &crate::slash::SLASH_COMMANDS[cmd_i];
        let abs = start + row_i;
        let selected = abs == menu.selected;
        let usage = if cmd.usage.is_empty() {
            String::new()
        } else {
            format!(" {}", cmd.usage)
        };
        let line = format!("/{:<12}{usage:<24} {}", cmd.name, cmd.description);
        let style = if selected {
            Style::default()
                .fg(Color::Black)
                .bg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Gray)
        };
        items.push(ListItem::new(line).style(style));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(title)
            .border_style(Style::default().fg(Color::Cyan)),
    );
    f.render_widget(list, area);
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    // Top row: oscar │ mode │ context │ profile │ activity (working / ready)
    // Context color tracks compact risk vs configured threshold (default 85%).
    let thr = app.config.oscar_config.context.threshold * 100.0;
    let ctx_color = app
        .context
        .as_ref()
        .map(|c| {
            if c.percent >= thr {
                Color::Red
            } else if c.percent >= thr * 0.75 {
                Color::Yellow
            } else {
                Color::Green
            }
        })
        .unwrap_or(Color::DarkGray);

    let ctx = app
        .context
        .as_ref()
        .map(|c| c.format_short())
        .unwrap_or_else(|| "— / — (—%)".into());
    let profile = App::format_status_profile(
        app.config
            .active_profile
            .as_deref()
            .filter(|s| !s.is_empty()),
        app.config.profile_count,
    );
    let working = app.turn_busy();
    let activity = app.activity_label().unwrap_or_else(|| {
        if working {
            "working…".into()
        } else {
            "ready".into()
        }
    });
    let act_color = if working {
        Color::Yellow
    } else {
        Color::Green
    };
    let qn = app.prompt_queue.len();
    let queue_span = if qn > 0 {
        Some(Span::styled(
            format!("queue:{qn}"),
            Style::default()
                .fg(Color::Magenta)
                .add_modifier(Modifier::BOLD),
        ))
    } else {
        None
    };

    let sep = Style::default().fg(Color::DarkGray);
    let mut spans = vec![
        Span::styled(
            "oscar",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", sep),
        Span::styled(
            app.config.mode.to_string(),
            Style::default().fg(Color::White),
        ),
        Span::styled(" │ ", sep),
        Span::styled(
            ctx,
            Style::default()
                .fg(ctx_color)
                .add_modifier(Modifier::BOLD),
        ),
        Span::styled(" │ ", sep),
        Span::styled(profile, Style::default().fg(Color::Gray)),
        Span::styled(" │ ", sep),
        Span::styled(
            activity,
            Style::default()
                .fg(act_color)
                .add_modifier(if working {
                    Modifier::BOLD
                } else {
                    Modifier::empty()
                }),
        ),
    ];
    if let Some(qs) = queue_span {
        spans.push(Span::styled(" │ ", sep));
        spans.push(qs);
    }
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Chat content padding (must match `draw_chat` Block padding).
pub const CHAT_PAD_LEFT: u16 = 1;
pub const CHAT_PAD_RIGHT: u16 = 2;
pub const CHAT_PAD_BOTTOM: u16 = 2;
/// Fixed marker gutter so selection caret does not reflow wrap widths (stable mouse map).
/// Wide enough for tool rails (`  ❙  `, `  ┃  `) and user `  ▸❯`.
pub const MARK_GUTTER: usize = 6;

/// One painted content row → transcript line + character span (Grok RangeHit spirit).
#[derive(Debug, Clone)]
pub struct VisualHit {
    pub line_idx: usize,
    /// Char offset into selectable body where this wrap row starts.
    pub char_start: usize,
    /// Body text painted on this visual row (no gutter).
    pub row_text: String,
}

impl VisualHit {
    /// Char offset under screen column `col` (absolute terminal col).
    pub fn char_at_screen_col(&self, col: u16, content_x: u16) -> usize {
        let body_x = content_x.saturating_add(MARK_GUTTER as u16);
        let rel = if col <= body_x {
            0usize
        } else {
            (col - body_x) as usize
        };
        let row_chars = self.row_text.chars().count();
        self.char_start + rel.min(row_chars)
    }
}

fn text_hl_for_line(app: &App, abs_idx: usize) -> Option<(usize, usize)> {
    let sel = app.text_selection?;
    if sel.is_empty() {
        return None;
    }
    let (a, b) = sel.normalized();
    if abs_idx < a.line_idx || abs_idx > b.line_idx {
        return None;
    }
    let body_len = selectable_body_len(app, abs_idx);
    let start = if abs_idx == a.line_idx {
        a.char_off
    } else {
        0
    };
    let end = if abs_idx == b.line_idx {
        b.char_off
    } else {
        body_len
    };
    if start >= end {
        // Caret-only: highlight one char if possible
        if start < body_len {
            Some((start, start + 1))
        } else {
            None
        }
    } else {
        Some((start, end))
    }
}

fn selectable_body_len(app: &App, abs_idx: usize) -> usize {
    let Some(l) = app.lines.get(abs_idx) else {
        return 0;
    };
    let width = app.viewport_cols();
    let body_w = width.saturating_sub(MARK_GUTTER).max(8);
    match l.kind {
        LineKind::Assistant => format_markdown_display(&l.text, body_w).chars().count(),
        LineKind::Thinking => {
            let raw = l
                .text
                .trim_start_matches('│')
                .trim_start_matches('┃')
                .trim_start_matches('✧')
                .trim_start_matches('◆')
                .trim_start();
            raw.chars().count()
        }
        LineKind::Tool => {
            let t = l.text.as_str();
            if t.starts_with("  ") || t.starts_with("args:") {
                t.trim_start().chars().count()
            } else {
                let name = t.trim_start_matches('⚙').trim_start_matches('◆').trim();
                format!("◆ {name}").chars().count()
            }
        }
        _ => l.text.chars().count(),
    }
}

/// Selectable body string for a line (must match paint). Used for text-selection copy.
pub fn selectable_body_text(app: &App, abs_idx: usize) -> String {
    let Some(l) = app.lines.get(abs_idx) else {
        return String::new();
    };
    let width = app.viewport_cols();
    let body_w = width.saturating_sub(MARK_GUTTER).max(8);
    match l.kind {
        LineKind::Assistant => format_markdown_display(&l.text, body_w),
        LineKind::Thinking => l
            .text
            .trim_start_matches('│')
            .trim_start_matches('┃')
            .trim_start_matches('✧')
            .trim_start_matches('◆')
            .trim_start()
            .to_string(),
        LineKind::Tool => {
            let t = l.text.as_str();
            if t.starts_with('✓') || t.starts_with('✗') {
                t.to_string()
            } else if t.starts_with("  ") || t.starts_with("args:") {
                t.trim_start().to_string()
            } else {
                let name = t.trim_start_matches('⚙').trim_start_matches('◆').trim();
                format!("◆ {name}")
            }
        }
        _ => l.text.clone(),
    }
}

/// Count total visual rows in the transcript at `width` (for max scroll).
pub fn count_chat_visual_rows(app: &App, width: usize) -> usize {
    let indices = app.visible_line_indices();
    let focus_scroll = app.pane_focus == PaneFocus::Scrollback;
    let mut total = 0usize;
    for &abs_idx in &indices {
        let l = &app.lines[abs_idx];
        // Entry highlight only when no active text selection (Grok separates modes).
        let selected = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.contains(abs_idx))
                .unwrap_or(false);
        let is_cursor = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.cursor == abs_idx)
                .unwrap_or(false)
            && focus_scroll;
        let hl = text_hl_for_line(app, abs_idx);
        total += render_chat_rows(l, width, selected, is_cursor, hl).len();
    }
    total
}

/// How many visual rows sit below `line_idx` (from that line's bottom edge to transcript end).
pub fn visual_rows_from_bottom_to_line(app: &App, width: usize, line_idx: usize) -> usize {
    let indices = app.visible_line_indices();
    let focus_scroll = app.pane_focus == PaneFocus::Scrollback;
    let mut below = 0usize;
    let mut found = false;
    for &abs_idx in indices.iter().rev() {
        let l = &app.lines[abs_idx];
        let selected = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.contains(abs_idx))
                .unwrap_or(false);
        let is_cursor = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.cursor == abs_idx)
                .unwrap_or(false)
            && focus_scroll;
        let hl = text_hl_for_line(app, abs_idx);
        let n = render_chat_rows(l, width, selected, is_cursor, hl).len();
        if abs_idx == line_idx {
            found = true;
            break;
        }
        below += n;
    }
    if found {
        below
    } else {
        0
    }
}

/// Build visual rows + maps for the viewport (Grok continuous visual scroll).
/// Returns (lines, line_idx_map, hit_map).
pub fn build_chat_visual(
    app: &App,
    width: usize,
    height: usize,
) -> (
    Vec<Line<'static>>,
    Vec<Option<usize>>,
    Vec<Option<VisualHit>>,
) {
    let indices = app.visible_line_indices();
    let scroll = app.chat_scroll;
    let focus_scroll = app.pane_focus == PaneFocus::Scrollback;
    let need = height.saturating_add(scroll);
    let mut from_bottom: Vec<(usize, PaintedRow)> = Vec::with_capacity(need.min(512));

    for &abs_idx in indices.iter().rev() {
        let l = &app.lines[abs_idx];
        let selected = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.contains(abs_idx))
                .unwrap_or(false);
        let is_cursor = app.text_selection.is_none()
            && app
                .selection
                .map(|s| s.cursor == abs_idx)
                .unwrap_or(false)
            && focus_scroll;
        let hl = text_hl_for_line(app, abs_idx);
        let rows = render_chat_rows(l, width, selected, is_cursor, hl);
        for row in rows.into_iter().rev() {
            from_bottom.push((abs_idx, row));
            if from_bottom.len() >= need {
                break;
            }
        }
        if from_bottom.len() >= need {
            break;
        }
    }

    let slice: Vec<(usize, PaintedRow)> = from_bottom
        .into_iter()
        .skip(scroll)
        .take(height)
        .collect();
    let ordered: Vec<(usize, PaintedRow)> = slice.into_iter().rev().collect();
    let pad = height.saturating_sub(ordered.len());
    let mut lines: Vec<Line> = (0..pad).map(|_| Line::from("")).collect();
    let mut map: Vec<Option<usize>> = (0..pad).map(|_| None).collect();
    let mut hits: Vec<Option<VisualHit>> = (0..pad).map(|_| None).collect();
    for (abs, painted) in ordered {
        lines.push(painted.line);
        map.push(Some(abs));
        hits.push(painted.hit.map(|(cstart, text)| VisualHit {
            line_idx: abs,
            char_start: cstart,
            row_text: text,
        }));
    }
    map.resize(height, None);
    hits.resize(height, None);
    lines.resize(height, Line::from(""));
    (lines, map, hits)
}

/// Visual row → absolute transcript index (fallback).
pub fn chat_visual_row_map(app: &App, width: usize, height: usize) -> Vec<Option<usize>> {
    build_chat_visual(app, width, height).1
}

fn draw_chat(f: &mut Frame, area: Rect, app: &mut App) {
    // Grok Build–style chat: soft left margin, tool rail, manual wrap so body
    // never folds under the role/marker column (Paragraph::wrap alone does that).
    let border = if app.pane_focus == PaneFocus::Scrollback {
        Style::default().fg(Color::Cyan)
    } else if app.chat_scroll == 0 {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Yellow)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" chat ")
        .border_style(border)
        .padding(ratatui::widgets::Padding {
            left: CHAT_PAD_LEFT,
            right: CHAT_PAD_RIGHT,
            top: 0,
            bottom: CHAT_PAD_BOTTOM,
        });
    // Exact content rect (borders + padding) — mouse uses this, not a hand-rolled guess.
    let inner = block.inner(area);
    app.chat_inner = Some((inner.x, inner.y, inner.width, inner.height));
    let height = (inner.height as usize).max(1);
    let width = (inner.width as usize).max(8);

    let (lines, map, hits) = build_chat_visual(app, width, height);
    app.chat_row_map = map;
    app.chat_hit_map = hits;

    // No Paragraph wrap — rows are already width-fitted.
    let para = Paragraph::new(lines).block(block);
    f.render_widget(para, area);
}

/// Soft left margin matching Grok Build transcript indent.
const MARGIN: &str = "  ";

fn sel_style(base: Style, selected: bool, cursor: bool) -> Style {
    if cursor {
        base.fg(Color::Black).bg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else if selected {
        base.bg(Color::Rgb(40, 60, 80))
    } else {
        base
    }
}

/// Turn raw markdown into clean TUI text: GFM tables → aligned columns, headers,
/// bullets, strip emphasis markers, pretty code fences. Readable without dumping `|---|`.
fn format_markdown_display(text: &str, max_width: usize) -> String {
    let lines: Vec<&str> = text.lines().collect();
    let mut out: Vec<String> = Vec::new();
    let mut i = 0usize;
    let mut in_code = false;
    let mut code_lang = String::from("code");
    let mut code_buf: Vec<String> = Vec::new();
    while i < lines.len() {
        let line = lines[i];
        let trimmed = line.trim();
        // Fenced code (``` or ~~~)
        if is_fence_open(trimmed) {
            if in_code {
                // Closing fence (same marker while open)
                out.extend(render_code_fence(&code_lang, &code_buf, max_width));
                code_buf.clear();
                in_code = false;
            } else {
                code_lang = fence_lang_label(trimmed);
                code_buf.clear();
                in_code = true;
            }
            i += 1;
            continue;
        }
        if in_code {
            // Preserve original indentation inside the fence (don't trim).
            code_buf.push(line.to_string());
            i += 1;
            continue;
        }
        // Markdown table block: header | sep | rows
        if trimmed.contains('|') && looks_like_table_row(trimmed) {
            let mut block = Vec::new();
            while i < lines.len() {
                let t = lines[i].trim();
                if t.contains('|') && (looks_like_table_row(t) || is_table_sep(t)) {
                    block.push(t);
                    i += 1;
                } else {
                    break;
                }
            }
            out.extend(render_md_table(&block, max_width));
            continue;
        }
        // ATX headers
        if let Some(rest) = trimmed.strip_prefix("### ") {
            out.push(format!("▸ {}", strip_inline_md(rest)));
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("## ") {
            out.push(format!("▸ {}", strip_inline_md(rest)));
            i += 1;
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("# ") {
            out.push(format!("▸ {}", strip_inline_md(rest)));
            i += 1;
            continue;
        }
        // Unordered list
        if let Some(rest) = trimmed
            .strip_prefix("- ")
            .or_else(|| trimmed.strip_prefix("* "))
        {
            out.push(format!("  • {}", strip_inline_md(rest)));
            i += 1;
            continue;
        }
        // Numbered list
        if let Some(pos) = trimmed.find(". ") {
            let (n, rest) = trimmed.split_at(pos);
            if n.chars().all(|c| c.is_ascii_digit()) && !n.is_empty() {
                out.push(format!("  {n}. {}", strip_inline_md(&rest[2..])));
                i += 1;
                continue;
            }
        }
        if trimmed == "---" || trimmed == "***" || trimmed == "___" {
            out.push("  ────────────".into());
            i += 1;
            continue;
        }
        // Indented code block (4 spaces / tab) — common for shell snippets
        if is_indented_code_line(line) {
            let mut block = Vec::new();
            while i < lines.len() && (is_indented_code_line(lines[i]) || lines[i].trim().is_empty())
            {
                // Stop if empty line followed by non-indented content
                if lines[i].trim().is_empty() {
                    let next_is_code = lines
                        .get(i + 1)
                        .map(|n| is_indented_code_line(n))
                        .unwrap_or(false);
                    if !next_is_code {
                        break;
                    }
                    block.push(String::new());
                } else {
                    block.push(dedent_code_line(lines[i]));
                }
                i += 1;
            }
            out.extend(render_code_fence("code", &block, max_width));
            continue;
        }
        out.push(strip_inline_md(line));
        i += 1;
    }
    // Unclosed fence — still render what we have
    if in_code {
        out.extend(render_code_fence(&code_lang, &code_buf, max_width));
    }
    out.join("\n")
}

fn is_fence_open(trimmed: &str) -> bool {
    trimmed.starts_with("```") || trimmed.starts_with("~~~")
}

fn fence_lang_label(fence_line: &str) -> String {
    let rest = fence_line
        .trim()
        .trim_start_matches('`')
        .trim_start_matches('~')
        .trim();
    let raw = rest
        .split(|c: char| c.is_whitespace() || c == '{' || c == ':')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match raw.as_str() {
        "" => "code".into(),
        "sh" | "shell" | "zsh" | "fish" | "console" | "terminal" | "bash" | "shellsession" => {
            "bash".into()
        }
        "js" | "javascript" | "jsx" => "javascript".into(),
        "ts" | "typescript" | "tsx" => "typescript".into(),
        "py" | "python" | "python3" => "python".into(),
        "rs" | "rust" => "rust".into(),
        "yml" | "yaml" => "yaml".into(),
        "tf" | "hcl" | "terraform" => "hcl".into(),
        "rb" | "ruby" => "ruby".into(),
        "go" | "golang" => "go".into(),
        "cs" | "csharp" => "csharp".into(),
        "c++" | "cpp" | "cxx" => "cpp".into(),
        "kt" | "kotlin" => "kotlin".into(),
        "md" | "markdown" => "markdown".into(),
        "txt" | "text" | "plain" => "text".into(),
        other => other.to_string(),
    }
}

fn is_indented_code_line(line: &str) -> bool {
    if line.trim().is_empty() {
        return false;
    }
    line.starts_with("    ") || line.starts_with('\t')
}

fn dedent_code_line(line: &str) -> String {
    if let Some(rest) = line.strip_prefix('\t') {
        return rest.to_string();
    }
    if let Some(rest) = line.strip_prefix("    ") {
        return rest.to_string();
    }
    line.to_string()
}

/// Pretty fenced block: header bar + rail-prefixed body (pre-wrapped) + footer.
/// Body lines use `│ ` so paint can style rail vs content separately.
fn render_code_fence(lang: &str, body: &[String], max_width: usize) -> Vec<String> {
    let w = max_width.max(12);
    let mut out = Vec::new();
    out.push(code_fence_header(lang, w));
    if body.is_empty() {
        out.push("│ ".into());
    } else {
        let content_w = w.saturating_sub(2).max(8); // room for "│ "
        for line in body {
            // Preserve empty lines inside the fence
            if line.is_empty() {
                out.push("│ ".into());
                continue;
            }
            for piece in wrap_code_content(line, content_w) {
                out.push(format!("│ {piece}"));
            }
        }
    }
    out.push(code_fence_footer(w));
    out
}

fn code_fence_header(lang: &str, max_width: usize) -> String {
    // ┌─ bash ────────────────────────
    let label = format!("─ {lang} ");
    let used = 1 + label.chars().count(); // ┌ + label
    let rest = max_width.saturating_sub(used).clamp(2, 48);
    format!("┌{label}{}", "─".repeat(rest))
}

fn code_fence_footer(max_width: usize) -> String {
    let rest = max_width.saturating_sub(1).clamp(4, 50);
    format!("└{}", "─".repeat(rest))
}

/// Wrap a single source code line to `width` columns.
/// Prefer whitespace, then shell/JSON-friendly break chars, else hard-break.
fn wrap_code_content(line: &str, width: usize) -> Vec<String> {
    let width = width.max(1);
    let chars: Vec<char> = line.chars().collect();
    if chars.is_empty() {
        return vec![String::new()];
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < chars.len() {
        let end = (i + width).min(chars.len());
        let mut take = end;
        if end < chars.len() {
            let window = &chars[i..end];
            // 1) last whitespace (keep progress)
            if let Some(rel) = window.iter().rposition(|c| c.is_whitespace()) {
                if rel > 0 {
                    take = i + rel;
                }
            } else if let Some(rel) = window.iter().rposition(|c| {
                // 2) break *after* punctuation common in CLI / JSON / JMESPath
                matches!(*c, ',' | ';' | '|' | '&' | '=' | ':' | '(' | '[' | '{' | '/')
            }) {
                if rel + 1 < window.len() && rel > 0 {
                    take = i + rel + 1; // include the punct on this row
                }
            }
        }
        if take == i {
            take = end;
        }
        let piece: String = chars[i..take].iter().collect();
        out.push(piece.trim_end().to_string());
        i = take;
        while i < chars.len() && chars[i].is_whitespace() {
            i += 1;
        }
    }
    if out.is_empty() {
        out.push(String::new());
    }
    out
}

fn looks_like_table_row(s: &str) -> bool {
    let t = s.trim();
    t.contains('|') && !is_table_sep(t)
}

fn is_table_sep(s: &str) -> bool {
    let t = s.trim().trim_matches('|');
    !t.is_empty()
        && t.chars()
            .all(|c| c == '-' || c == ':' || c == '|' || c.is_whitespace())
}

fn split_md_cells(row: &str) -> Vec<String> {
    let mut s = row.trim();
    if s.starts_with('|') {
        s = &s[1..];
    }
    if s.ends_with('|') {
        s = &s[..s.len() - 1];
    }
    s.split('|')
        .map(|c| strip_inline_md(c.trim()))
        .collect()
}

fn render_md_table(block: &[&str], max_width: usize) -> Vec<String> {
    let rows: Vec<Vec<String>> = block
        .iter()
        .filter(|r| !is_table_sep(r))
        .map(|r| split_md_cells(r))
        .filter(|r| !r.is_empty())
        .collect();
    if rows.is_empty() {
        return Vec::new();
    }
    let cols = rows.iter().map(|r| r.len()).max().unwrap_or(0);
    if cols == 0 {
        return Vec::new();
    }
    let mut widths = vec![0usize; cols];
    for r in &rows {
        for (i, c) in r.iter().enumerate() {
            widths[i] = widths[i].max(c.chars().count()).min(36);
        }
    }
    // Fit table into max_width with " │ " separators.
    let sep_w = 3 * cols.saturating_sub(1);
    let mut total = widths.iter().sum::<usize>() + sep_w;
    while total > max_width && widths.iter().any(|&w| w > 6) {
        if let Some((i, _)) = widths
            .iter()
            .enumerate()
            .filter(|(_, w)| **w > 6)
            .max_by_key(|(_, w)| *w)
        {
            widths[i] -= 1;
            total = widths.iter().sum::<usize>() + sep_w;
        } else {
            break;
        }
    }
    let mut out = Vec::new();
    for (ri, r) in rows.iter().enumerate() {
        let mut cells = Vec::new();
        for (ci, w) in widths.iter().enumerate() {
            let raw = r.get(ci).map(|s| s.as_str()).unwrap_or("");
            let mut cell: String = raw.chars().take(*w).collect();
            while cell.chars().count() < *w {
                cell.push(' ');
            }
            cells.push(cell);
        }
        out.push(cells.join(" │ "));
        if ri == 0 {
            // Header underline
            let rule: Vec<String> = widths.iter().map(|w| "─".repeat(*w)).collect();
            out.push(rule.join("─┼─"));
        }
    }
    out
}

fn strip_inline_md(s: &str) -> String {
    let mut out = s.to_string();
    // **bold** / __bold__
    while let Some(a) = out.find("**") {
        if let Some(rel) = out[a + 2..].find("**") {
            let b = a + 2 + rel;
            out.replace_range(b..b + 2, "");
            out.replace_range(a..a + 2, "");
        } else {
            break;
        }
    }
    // __bold__
    while let Some(a) = out.find("__") {
        if let Some(rel) = out[a + 2..].find("__") {
            let b = a + 2 + rel;
            out.replace_range(b..b + 2, "");
            out.replace_range(a..a + 2, "");
        } else {
            break;
        }
    }
    // Keep single `inline code` backticks so commands stay visually distinct.
    // [text](url) → text
    while let Some(a) = out.find('[') {
        if let Some(mid) = out[a..].find("](") {
            let mid = a + mid;
            if let Some(end_rel) = out[mid + 2..].find(')') {
                let end = mid + 2 + end_rel;
                let label = out[a + 1..mid].to_string();
                out.replace_range(a..=end, &label);
            } else {
                break;
            }
        } else {
            break;
        }
    }
    out
}

/// Soft cyan for shell / code body (readable on dark terminals).
const CODE_BODY_FG: Color = Color::Rgb(170, 220, 255);
const CODE_HEAD_FG: Color = Color::Rgb(120, 200, 255);
const CODE_RAIL_FG: Color = Color::Rgb(80, 100, 120);

fn assistant_chunk_style(chunk: &str, selected: bool, cursor: bool) -> Style {
    let base = if chunk.starts_with('▸') {
        Style::default()
            .fg(Color::Cyan)
            .add_modifier(Modifier::BOLD)
    } else if chunk.starts_with('┌') {
        // Code fence language header
        Style::default()
            .fg(CODE_HEAD_FG)
            .add_modifier(Modifier::BOLD)
    } else if chunk.starts_with('└') {
        Style::default().fg(CODE_RAIL_FG)
    } else if chunk.starts_with("│ ") || chunk == "│" {
        // Full-line fallback when not multi-span painted
        Style::default().fg(CODE_BODY_FG)
    } else if chunk.contains('│')
        && (chunk.contains('┼')
            || chunk
                .chars()
                .all(|c| " ─│┼".contains(c) || c.is_whitespace()))
    {
        // Table rule / separator row
        Style::default().fg(Color::DarkGray)
    } else if chunk.contains('│') && !chunk.starts_with('│') {
        // Table data row
        Style::default().fg(Color::White)
    } else if chunk.starts_with("  •") || (chunk.starts_with("  ") && chunk.contains(". ")) {
        Style::default().fg(Color::White)
    } else if chunk.contains('`') {
        // Prose with inline code — slightly brighter
        Style::default().fg(Color::Rgb(230, 230, 235))
    } else {
        Style::default().fg(Color::White)
    };
    sel_style(base, selected, cursor)
}

/// Paint an assistant display chunk; code-rail lines get split chrome vs body colors.
fn paint_assistant_chunk(
    mark: String,
    chunk: String,
    cstart: usize,
    selected: bool,
    cursor: bool,
) -> PaintedRow {
    let mark_span = Span::styled(mark, sel_style(Style::default(), selected, cursor));
    if let Some(code) = chunk.strip_prefix("│ ") {
        let rail = Span::styled(
            "│ ".to_string(),
            sel_style(Style::default().fg(CODE_RAIL_FG), selected, cursor),
        );
        let body = Span::styled(
            code.to_string(),
            sel_style(Style::default().fg(CODE_BODY_FG), selected, cursor),
        );
        PaintedRow {
            line: Line::from(vec![mark_span, rail, body]),
            hit: Some((cstart, chunk)),
        }
    } else if chunk == "│" {
        let rail = Span::styled(
            "│".to_string(),
            sel_style(Style::default().fg(CODE_RAIL_FG), selected, cursor),
        );
        PaintedRow {
            line: Line::from(vec![mark_span, rail]),
            hit: Some((cstart, chunk)),
        }
    } else {
        let style = assistant_chunk_style(&chunk, selected, cursor);
        PaintedRow {
            line: line2(mark_span, Span::styled(chunk.clone(), style)),
            hit: Some((cstart, chunk)),
        }
    }
}

#[cfg(test)]
mod md_tests {
    use super::*;

    #[test]
    fn table_renders_without_raw_pipes_sep() {
        let md = "\
| name | score |
|------|------:|
| a | 1 |
| **b** | 2 |
";
        let out = format_markdown_display(md, 40);
        assert!(out.contains('│'), "{out}");
        assert!(out.contains("name"), "{out}");
        assert!(!out.contains("|---"), "{out}");
        assert!(out.contains('b'), "{out}"); // bold stripped
        assert!(!out.contains("**"), "{out}");
    }

    #[test]
    fn header_and_bullet() {
        let out = format_markdown_display("## Findings\n- ravix.example", 40);
        assert!(out.contains("▸ Findings"), "{out}");
        assert!(out.contains("• ravix"), "{out}");
    }

    #[test]
    fn bash_fence_is_clean_box_with_rail() {
        let md = "\
Run this:

```bash
aws ec2 describe-security-groups --region us-east-1 \\
  --query 'SecurityGroups[?contains(GroupName, `test`)].GroupId' \\
  --output table
```
";
        let out = format_markdown_display(md, 56);
        assert!(out.contains("┌─ bash "), "header: {out}");
        assert!(out.contains("└"), "footer: {out}");
        assert!(
            out.lines().any(|l| l.starts_with("│ ") && l.contains("aws ec2")),
            "rail+command: {out}"
        );
        assert!(
            !out.contains("```"),
            "raw fence markers must be stripped: {out}"
        );
        // Language normalized, not raw "```bash"
        assert!(out.contains("bash"), "{out}");
        // Body lines keep rail after wrap
        for l in out.lines() {
            if l.contains("describe-security") || l.contains("--query") || l.contains("--output") {
                assert!(
                    l.starts_with("│ "),
                    "code line must keep │ rail: {l:?}\nfull:\n{out}"
                );
            }
        }
    }

    #[test]
    fn shell_alias_normalizes_to_bash() {
        let out = format_markdown_display("```sh\necho hi\n```", 40);
        assert!(out.contains("┌─ bash "), "{out}");
        assert!(out.contains("│ echo hi"), "{out}");
    }

    #[test]
    fn json_fence_and_inline_backticks_kept() {
        let md = "Use `profile_id` then:\n\n```json\n{\"a\": 1}\n```\n";
        let out = format_markdown_display(md, 40);
        assert!(out.contains("`profile_id`"), "inline code kept: {out}");
        assert!(out.contains("┌─ json "), "{out}");
        assert!(out.contains("│ {\"a\": 1}"), "{out}");
    }

    #[test]
    fn indented_code_block_renders_as_fence() {
        let md = "Example:\n\n    aws sts get-caller-identity\n    aws ec2 describe-vpcs\n";
        let out = format_markdown_display(md, 48);
        assert!(out.contains("│ aws sts get-caller-identity"), "{out}");
        assert!(out.contains("┌─ code "), "{out}");
    }

    #[test]
    fn visual_map_length_matches_height() {
        use crate::app::{App, AppConfig, LineKind};
        let mut app = App::new(AppConfig {
            provider: "xai".into(),
            model: "t".into(),
            mode: oscar_core::ExecutionMode::ReadOnly,
            show_thinking: false,
            profile_count: 0,
            active_profile: None,
            oscar_config: oscar_core::OscarConfig::default(),
            tool_catalog: vec![],
            profiles_path: std::path::PathBuf::from("/tmp/oscar-tui-test-profiles.toml"),
            provider_ready: true,
        });
        app.lines.clear();
        for i in 0..20 {
            app.push_line(LineKind::Assistant, format!("line {i} with some longer text so it may wrap in narrow width"));
        }
        let height = 12usize;
        let width = 40usize;
        let (rows, map, hits) = build_chat_visual(&app, width, height);
        assert_eq!(rows.len(), height, "draw rows fill viewport height");
        assert_eq!(map.len(), height, "mouse map same length as draw rows");
        assert_eq!(hits.len(), height, "hit map same length");
        assert!(map.iter().any(|x| x.is_some()), "some rows map to content");
    }

    #[test]
    fn visual_scroll_one_row_shifts_content() {
        use crate::app::{App, AppConfig, LineKind};
        let mut app = App::new(AppConfig {
            provider: "xai".into(),
            model: "t".into(),
            mode: oscar_core::ExecutionMode::ReadOnly,
            show_thinking: false,
            profile_count: 0,
            active_profile: None,
            oscar_config: oscar_core::OscarConfig::default(),
            tool_catalog: vec![],
            profiles_path: std::path::PathBuf::from("/tmp/oscar-tui-test-profiles.toml"),
            provider_ready: true,
        });
        app.lines.clear();
        for i in 0..40 {
            app.push_line(LineKind::Notice, format!("row-{i:02}"));
        }
        let height = 10usize;
        let width = 60usize;
        app.chat_scroll = 0;
        let (_r0, map0, _) = build_chat_visual(&app, width, height);
        app.chat_scroll = 1;
        let (_r1, map1, _) = build_chat_visual(&app, width, height);
        assert_ne!(map0, map1, "one visual row of scroll must change the viewport");
        let total = count_chat_visual_rows(&app, width);
        assert!(total >= 40, "one row per notice line");
        assert!(total.saturating_sub(height) >= 1);
    }
}

/// Split `text` into chunks that fit `width` (char-based; good enough for TUI).
fn wrap_text(text: &str, width: usize) -> Vec<String> {
    wrap_text_with_offsets(text, width)
        .into_iter()
        .map(|(_, s)| s)
        .collect()
}

/// Like [`wrap_text`], but each chunk includes its starting Unicode offset in `text`.
///
/// Code-rail paragraphs (`│ …`) re-prefix the rail on every visual wrap row so
/// multi-line commands never lose the box edge mid-command.
fn wrap_text_with_offsets(text: &str, width: usize) -> Vec<(usize, String)> {
    let width = width.max(1);
    if text.is_empty() {
        return vec![(0, String::new())];
    }
    let mut out = Vec::new();
    // Global char offset across paragraphs (including newlines as one char each).
    let mut global = 0usize;
    let paras: Vec<&str> = text.split('\n').collect();
    for (pi, para) in paras.iter().enumerate() {
        if para.is_empty() {
            out.push((global, String::new()));
            if pi + 1 < paras.len() {
                global += 1; // newline
            }
            continue;
        }
        // Code body: wrap content only, re-apply "│ " on each visual row.
        if let Some(code) = para.strip_prefix("│ ") {
            let rail_w = 2usize;
            let content_w = width.saturating_sub(rail_w).max(1);
            let pieces = wrap_code_content(code, content_w);
            let mut off = 0usize;
            for (idx, piece) in pieces.into_iter().enumerate() {
                // Offset points into the full "│ …" paragraph string.
                let abs = if idx == 0 {
                    global
                } else {
                    // Approximate: after "│ " + prior content
                    global + rail_w + off.min(code.chars().count())
                };
                out.push((abs, format!("│ {piece}")));
                off = off.saturating_add(piece.chars().count().saturating_add(1));
            }
            global += para.chars().count();
            if pi + 1 < paras.len() {
                global += 1;
            }
            continue;
        }
        let chars: Vec<char> = para.chars().collect();
        let mut i = 0usize;
        while i < chars.len() {
            let end = (i + width).min(chars.len());
            let mut take = end;
            if end < chars.len() {
                if let Some(rel) = chars[i..end].iter().rposition(|c| c.is_whitespace()) {
                    if rel > 0 {
                        take = i + rel;
                    }
                }
            }
            if take == i {
                take = end;
            }
            let chunk: String = chars[i..take].iter().collect();
            let trimmed = chunk.trim_end().to_string();
            out.push((global + i, trimmed));
            i = take;
            while i < chars.len() && chars[i].is_whitespace() {
                i += 1;
            }
        }
        global += chars.len();
        if pi + 1 < paras.len() {
            global += 1; // newline between paras
        }
    }
    if out.is_empty() {
        out.push((0, String::new()));
    }
    out
}

fn line2(marker: Span<'static>, body: Span<'static>) -> Line<'static> {
    Line::from(vec![marker, body])
}

/// Pad/truncate marker to fixed gutter so wrap width never depends on selection/caret.
fn mark_pad(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() >= MARK_GUTTER {
        return chars.into_iter().take(MARK_GUTTER).collect();
    }
    let mut out: String = chars.into_iter().collect();
    while out.chars().count() < MARK_GUTTER {
        out.push(' ');
    }
    out
}

struct PaintedRow {
    line: Line<'static>,
    /// Selectable body start offset + text for this wrap (None for empty chrome).
    hit: Option<(usize, String)>,
}

fn paint_body_rows(
    mark0: String,
    cont: String,
    mark_style: Style,
    body_style: Style,
    chunks: Vec<(usize, String)>,
    selected: bool,
    cursor: bool,
    // Optional per-char highlight range (start, end) in body text for this line.
    text_hl: Option<(usize, usize)>,
) -> Vec<PaintedRow> {
    chunks
        .into_iter()
        .enumerate()
        .map(|(i, (cstart, chunk))| {
            let m = if i == 0 {
                mark0.clone()
            } else {
                cont.clone()
            };
            let cend = cstart + chunk.chars().count();
            let body_spans = if let Some((hs, he)) = text_hl {
                // Split chunk into unselected / selected / unselected spans.
                let lo = hs.max(cstart);
                let hi = he.min(cend);
                if lo >= hi {
                    vec![Span::styled(chunk.clone(), sel_style(body_style, selected, cursor))]
                } else {
                    let mut spans = Vec::new();
                    let chars: Vec<char> = chunk.chars().collect();
                    let rel_lo = lo - cstart;
                    let rel_hi = hi - cstart;
                    if rel_lo > 0 {
                        let s: String = chars[..rel_lo].iter().collect();
                        spans.push(Span::styled(s, sel_style(body_style, selected, cursor)));
                    }
                    let s: String = chars[rel_lo..rel_hi].iter().collect();
                    spans.push(Span::styled(
                        s,
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD),
                    ));
                    if rel_hi < chars.len() {
                        let s: String = chars[rel_hi..].iter().collect();
                        spans.push(Span::styled(s, sel_style(body_style, selected, cursor)));
                    }
                    spans
                }
            } else {
                vec![Span::styled(chunk.clone(), sel_style(body_style, selected, cursor))]
            };
            let mut spans = vec![Span::styled(m, sel_style(mark_style, selected, cursor))];
            spans.extend(body_spans);
            PaintedRow {
                line: Line::from(spans),
                hit: Some((cstart, chunk)),
            }
        })
        .collect()
}

/// Grok Build–style multi-row render for one chat line (manual wrap + rail).
fn render_chat_rows(
    l: &crate::app::ChatLine,
    width: usize,
    selected: bool,
    cursor: bool,
    text_hl: Option<(usize, usize)>,
) -> Vec<PaintedRow> {
    // Fixed gutter width: selection/caret must not change wrap (stable mouse hit-test).
    let body_w = width.saturating_sub(MARK_GUTTER).max(8);
    let caret = if cursor {
        "▸"
    } else if selected {
        "·"
    } else {
        " "
    };

    match l.kind {
        LineKind::User => {
            let mark0 = mark_pad(&format!("{MARGIN}{caret}❯"));
            let cont = mark_pad(&format!("{MARGIN}{caret} "));
            let chunks = wrap_text_with_offsets(&l.text, body_w);
            paint_body_rows(
                mark0,
                cont,
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
                Style::default().fg(Color::Green),
                chunks,
                selected,
                cursor,
                text_hl,
            )
        }
        LineKind::Assistant => {
            let mark = mark_pad(&format!("{MARGIN}{caret}"));
            // format_markdown_display already width-fits code fences; wrap only residual.
            let display = format_markdown_display(&l.text, body_w);
            let chunks = wrap_text_with_offsets(&display, body_w);
            // Char text-selection: single body style (still readable).
            // Normal path: multi-span code rails + language headers.
            if text_hl.is_some() {
                paint_body_rows(
                    mark.clone(),
                    mark,
                    Style::default(),
                    Style::default().fg(CODE_BODY_FG),
                    chunks,
                    selected,
                    cursor,
                    text_hl,
                )
            } else {
                chunks
                    .into_iter()
                    .map(|(cstart, chunk)| {
                        paint_assistant_chunk(mark.clone(), chunk, cstart, selected, cursor)
                    })
                    .collect()
            }
        }
        LineKind::Thinking => {
            let is_body = l.text.starts_with('│') || l.text.starts_with('┃');
            if is_body {
                let raw = l
                    .text
                    .trim_start_matches('│')
                    .trim_start_matches('┃')
                    .trim_start();
                let mark = mark_pad(&format!(" ┃{caret}"));
                paint_body_rows(
                    mark.clone(),
                    mark,
                    Style::default().fg(Color::DarkGray),
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                    wrap_text_with_offsets(raw, body_w),
                    selected,
                    cursor,
                    text_hl,
                )
            } else {
                let mark = mark_pad(&format!("{MARGIN}{caret}◆"));
                let cont = mark_pad(&format!("{MARGIN}{caret} "));
                let text = l
                    .text
                    .trim_start_matches('✧')
                    .trim_start_matches('◆')
                    .trim_start();
                paint_body_rows(
                    mark,
                    cont,
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::BOLD),
                    Style::default()
                        .fg(Color::Magenta)
                        .add_modifier(Modifier::ITALIC),
                    wrap_text_with_offsets(text, body_w),
                    selected,
                    cursor,
                    text_hl,
                )
            }
        }
        LineKind::Tool => {
            let t = l.text.as_str();
            let (rail, color, body) = if t.starts_with('✓') || t.starts_with('✗') {
                let ok = t.starts_with('✓');
                (
                    format!(" ❙{caret}"),
                    if ok { Color::Green } else { Color::Red },
                    t.to_string(),
                )
            } else if t.starts_with("  ") || t.starts_with("args:") {
                (
                    format!(" ┃{caret} "),
                    Color::DarkGray,
                    t.trim_start().to_string(),
                )
            } else {
                let name = t.trim_start_matches('⚙').trim_start_matches('◆').trim();
                (
                    format!(" ┃{caret} "),
                    Color::Yellow,
                    format!("◆ {name}"),
                )
            };
            let mark = mark_pad(&rail);
            let cont = mark_pad(&format!(" ┃{caret} "));
            paint_body_rows(
                mark,
                cont,
                Style::default().fg(color),
                Style::default().fg(color),
                wrap_text_with_offsets(&body, body_w),
                selected,
                cursor,
                text_hl,
            )
        }
        LineKind::System => {
            let mark = mark_pad(&format!("{MARGIN}{caret}"));
            vec![PaintedRow {
                line: line2(
                    Span::styled(
                        mark,
                        sel_style(Style::default().fg(Color::DarkGray), selected, cursor),
                    ),
                    Span::styled(
                        l.text.clone(),
                        sel_style(Style::default().fg(Color::DarkGray), selected, cursor),
                    ),
                ),
                hit: Some((0, l.text.clone())),
            }]
        }
        LineKind::Notice => {
            let mark = mark_pad(&format!("{MARGIN}{caret}"));
            paint_body_rows(
                mark.clone(),
                mark,
                Style::default().fg(Color::DarkGray),
                Style::default().fg(Color::DarkGray),
                wrap_text_with_offsets(&l.text, body_w),
                selected,
                cursor,
                text_hl,
            )
        }
        LineKind::Error => {
            let mark = mark_pad(&format!("{MARGIN}{caret}✗"));
            let cont = mark_pad(&format!("{MARGIN}{caret} "));
            paint_body_rows(
                mark,
                cont,
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
                Style::default().fg(Color::Red),
                wrap_text_with_offsets(&l.text, body_w),
                selected,
                cursor,
                text_hl,
            )
        }
    }
}

fn draw_input(f: &mut Frame, area: Rect, app: &App) {
    if matches!(app.view, View::Settings(_)) {
        let para = Paragraph::new(" settings · ↑↓ move · → open · ← back · Esc close ")
            .style(Style::default().fg(Color::Yellow))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" input (paused) ")
                    .border_style(Style::default().fg(Color::Yellow)),
            );
        f.render_widget(para, area);
        return;
    }
    if let View::Provider(pane) = &app.view {
        if let Some((buf, cur, field)) = pane.edit_display() {
            let line = format!("> {buf}");
            let para = Paragraph::new(line)
                .style(Style::default().fg(Color::Cyan))
                .block(
                    Block::default()
                        .borders(Borders::ALL)
                        .title(format!(" edit {field} · Enter save · Esc cancel "))
                        .border_style(Style::default().fg(Color::Cyan)),
                );
            f.render_widget(para, area);
            let col = 2u16.saturating_add(cur.min(u16::MAX as usize) as u16);
            let x = area.x.saturating_add(1).saturating_add(col.min(area.width.saturating_sub(2)));
            let y = area.y.saturating_add(1);
            f.set_cursor_position((x, y));
            return;
        }
        let hint = pane
            .flash
            .clone()
            .unwrap_or_else(|| "↑↓ · → actions · Enter · Esc close".into());
        let para = Paragraph::new(hint)
            .style(Style::default().fg(Color::Magenta))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" providers ")
                    .border_style(Style::default().fg(Color::Magenta)),
            );
        f.render_widget(para, area);
        return;
    }
    if matches!(app.view, View::Identities(_)) {
        let para = Paragraph::new(
            " identities · r re-validate · ←→ filter cloud · Enter detail · Esc close ",
        )
        .style(Style::default().fg(Color::Green))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" input (paused) ")
                .border_style(Style::default().fg(Color::Green)),
        );
        f.render_widget(para, area);
        return;
    }

    let prompt_focused = app.pane_focus == PaneFocus::Prompt
        || matches!(app.input_mode, InputMode::Secure { .. });

    let title = match &app.input_mode {
        InputMode::Normal => {
            let mut t = if app.streaming {
                " input · Esc to cancel ".to_string()
            } else {
                " input ".to_string()
            };
            if app.multiline_mode {
                t = if app.streaming {
                    " input · multiline · Esc cancel ".into()
                } else {
                    " input · multiline ".into()
                };
            }
            t
        }
        InputMode::Secure { auth, .. } => {
            // Keep the chrome short — long titles overflow the input border.
            if auth
                .profile_hint
                .as_deref()
                .is_some_and(|h| h.starts_with("provider:"))
            {
                " Enter API Key ".to_string()
            } else {
                " Secret · paste export AWS_* block or one field ".to_string()
            }
        }
    };

    let model_title = input_model_title(app);

    let (text_style, border_fg, show_cursor) = match &app.input_mode {
        InputMode::Normal if app.show_idle_input_hint() && prompt_focused => {
            // Grok Build–style: dim cycling tooltip inside the empty input field
            let hint = app.idle_hint.current();
            let line = Line::from(vec![
                Span::styled("> ", Style::default().fg(Color::DarkGray)),
                Span::styled(
                    hint,
                    Style::default()
                        .fg(Color::DarkGray)
                        .add_modifier(Modifier::ITALIC),
                ),
            ]);
            let idle_title = if let Some(flash) = app.copy_flash.as_ref() {
                format!("{title}· {flash} ")
            } else {
                title
            };
            let mut block = Block::default()
                .borders(Borders::ALL)
                .title_top(idle_title)
                .border_style(Style::default().fg(Color::White));
            if let Some(mt) = model_title {
                block = block.title_bottom(mt);
            }
            let para = Paragraph::new(line).block(block);
            f.render_widget(para, area);
            return;
        }
        InputMode::Normal if !prompt_focused => {
            (Style::default().fg(Color::DarkGray), Color::DarkGray, false)
        }
        InputMode::Normal => (Style::default().fg(Color::White), Color::White, true),
        InputMode::Secure { .. } => (Style::default().fg(Color::Yellow), Color::Yellow, true),
    };

    // Soft-wrap + multi-row composer (Grok parity): long text grows the bar.
    let raw = match &app.input_mode {
        InputMode::Secure { buffer, .. } => "•".repeat(buffer.chars().count()),
        InputMode::Normal => app.input.clone(),
    };
    let inner_w = input_inner_width(area.width);
    let rows = layout_input_rows(&raw, inner_w);
    let visible_h = area.height.saturating_sub(2).max(1) as usize;
    let scroll = app.input_scroll.min(rows.len().saturating_sub(1));
    let end = (scroll + visible_h).min(rows.len());
    let mut lines: Vec<Line> = Vec::with_capacity(end.saturating_sub(scroll).max(1));
    for (i, row) in rows.iter().enumerate().take(end).skip(scroll) {
        let prefix = if i == 0 { INPUT_PREFIX } else { INPUT_CONT };
        lines.push(Line::from(vec![
            Span::styled(
                prefix,
                Style::default().fg(if show_cursor {
                    Color::DarkGray
                } else {
                    Color::DarkGray
                }),
            ),
            Span::styled(row.text.clone(), text_style),
        ]));
    }
    if lines.is_empty() {
        lines.push(Line::from(vec![
            Span::styled(INPUT_PREFIX, Style::default().fg(Color::DarkGray)),
            Span::styled("", text_style),
        ]));
    }

    // Flash (e.g. copy result) only — keep the left title as plain "input".
    let full_title = if let Some(flash) = app.copy_flash.as_ref() {
        format!("{title}· {flash} ")
    } else {
        title
    };
    let mut block = Block::default()
        .borders(Borders::ALL)
        .title_top(full_title)
        .border_style(Style::default().fg(border_fg));
    if let Some(mt) = model_title {
        block = block.title_bottom(mt);
    }
    let para = Paragraph::new(lines).style(text_style).block(block);
    f.render_widget(para, area);

    // Place terminal cursor on the correct visual row/col (after prefix).
    if show_cursor && area.width > 3 && area.height > 2 {
        let text_len = raw.chars().count();
        let (crow, ccol) = cursor_row_col(&rows, app.input_cursor.min(text_len), text_len);
        let vis_row = crow.saturating_sub(scroll);
        let max_vis = area.height.saturating_sub(2) as usize;
        if vis_row < max_vis {
            let col = (INPUT_PREFIX_COLS + ccol) as u16;
            let max_col = area.width.saturating_sub(2);
            let x = area.x.saturating_add(1).saturating_add(col.min(max_col));
            let y = area.y.saturating_add(1).saturating_add(vis_row as u16);
            f.set_cursor_position((x, y));
        }
    }
}

/// Centered modal: category sidebar + item list (Grok Build–style).
fn draw_settings_modal(f: &mut Frame, area: Rect, pane: &SettingsPane) {
    let modal = centered_rect(88, 82, area);
    f.render_widget(Clear, modal);

    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Cyan))
        .title(Span::styled(
            " oscar settings ",
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            if pane.dirty {
                " ● unsaved · Esc save & close · /settings "
            } else {
                " Esc close · Enter/Space toggle · ←→ category · ↑↓ item "
            },
            Style::default().fg(Color::DarkGray),
        ));
    let inner = outer.inner(modal);
    f.render_widget(outer, modal);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(5),
            Constraint::Length(2),
        ])
        .split(inner);

    // Header flash / category hint
    let header = format!(
        " {}  —  {}{}",
        pane.category().title(),
        pane.category().hint(),
        pane.flash
            .as_ref()
            .map(|s| format!("  ·  {s}"))
            .unwrap_or_default()
    );
    f.render_widget(
        Paragraph::new(header).style(Style::default().fg(Color::White)),
        body[0],
    );

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Length(22), Constraint::Min(20)])
        .split(body[1]);

    draw_categories(f, cols[0], pane);
    if pane.category() == SettingsCategory::RawConfig {
        draw_raw_config(f, cols[1], pane);
    } else {
        draw_items(f, cols[1], pane);
    }

    // Footer legend
    let legend = match pane.category() {
        SettingsCategory::Clouds => {
            " ↑↓ move · → open · ← back · Clouds: off hides CSP from tools_search "
        }
        SettingsCategory::Tools => {
            " ↑↓ move · → open · ← back · disabled tools never appear in tools_search "
        }
        SettingsCategory::Install => {
            " ↑↓ · → open · Install: off|recommend|ask-admin|install-all "
        }
        SettingsCategory::Agent => " ↑↓ · → open · mode gate + compaction (readonly default) ",
        SettingsCategory::RawConfig => {
            " Raw config: → focus · ↑↓ scroll · y/Ctrl+Y copy TOML · secrets stay in keychain "
        }
        _ => " ↑↓ move · →/Enter open · ← back · Esc close · ~/.config/oscar/config.toml ",
    };
    f.render_widget(
        Paragraph::new(legend).style(Style::default().fg(Color::DarkGray)),
        body[2],
    );
}

fn draw_categories(f: &mut Frame, area: Rect, pane: &SettingsPane) {
    use crate::settings::SettingsFocus;
    let focus_here = pane.focus == SettingsFocus::Categories;
    let items: Vec<ListItem> = SettingsCategory::ALL
        .iter()
        .enumerate()
        .map(|(i, c)| {
            let selected = i == pane.category_idx;
            let prefix = if selected {
                if focus_here {
                    "▸ "
                } else {
                    "· "
                }
            } else {
                "  "
            };
            let style = if selected && focus_here {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(format!("{prefix}{}", c.title())).style(style)
        })
        .collect();

    let border = if focus_here { Color::Cyan } else { Color::DarkGray };
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(if focus_here {
                " categories · focused "
            } else {
                " categories "
            })
            .border_style(Style::default().fg(border)),
    );
    f.render_widget(list, area);
}

fn draw_items(f: &mut Frame, area: Rect, pane: &SettingsPane) {
    use crate::settings::SettingsFocus;
    let focus_here = pane.focus == SettingsFocus::Items;
    let items = pane.items();
    let height = area.height.saturating_sub(2) as usize;
    let mut scroll = pane.item_scroll;
    if pane.item_idx >= scroll + height {
        scroll = pane.item_idx + 1 - height;
    }
    if pane.item_idx < scroll {
        scroll = pane.item_idx;
    }

    let mut lines: Vec<ListItem> = Vec::new();
    for (i, item) in items.iter().enumerate() {
        if i < scroll {
            continue;
        }
        if lines.len() >= height {
            break;
        }
        let selected = i == pane.item_idx;
        let row = format_item_row(item, selected && focus_here);
        let style = match (&item.kind, selected, focus_here) {
            (ItemKind::Header, _, _) => Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            (_, true, true) => Style::default()
                .fg(Color::Black)
                .bg(Color::White)
                .add_modifier(Modifier::BOLD),
            (_, true, false) => Style::default().fg(Color::White),
            (ItemKind::Toggle { on: true }, false, _) => Style::default().fg(Color::Green),
            (ItemKind::Toggle { on: false }, false, _) => Style::default().fg(Color::Red),
            _ => Style::default().fg(Color::Gray),
        };
        lines.push(ListItem::new(row).style(style));
    }

    let border = if focus_here { Color::White } else { Color::DarkGray };
    let list = List::new(lines).block(
        Block::default()
            .borders(Borders::ALL)
            .title(if focus_here {
                format!(" {} · focused · ← back ", pane.category().title())
            } else {
                format!(" {} · → open ", pane.category().title())
            })
            .border_style(Style::default().fg(border)),
    );
    f.render_widget(list, area);
}

/// Full TOML dump of effective config (no secrets — those stay in the keychain).
fn draw_raw_config(f: &mut Frame, area: Rect, pane: &SettingsPane) {
    use crate::settings::SettingsFocus;
    let focus_here = pane.focus == SettingsFocus::Items;
    let border = if focus_here {
        Color::White
    } else {
        Color::DarkGray
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(3)])
        .split(area);

    let status = pane.raw_status_line();
    let total_lines = pane.raw_toml().lines().count().max(1);
    let body_h = chunks[1].height.saturating_sub(2) as usize;
    let max_scroll = total_lines.saturating_sub(body_h.max(1));
    let scroll = pane.raw_scroll.min(max_scroll);
    let end = (scroll + body_h).min(total_lines);
    let title = if focus_here {
        format!(" raw TOML · focused · lines {}–{end}/{total_lines} · ← back ", scroll + 1)
    } else {
        format!(" raw TOML · → focus · lines {}–{end}/{total_lines} ", scroll + 1)
    };

    f.render_widget(
        Paragraph::new(status)
            .style(Style::default().fg(Color::DarkGray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" path / status ")
                    .border_style(Style::default().fg(border)),
            )
            .wrap(Wrap { trim: true }),
        chunks[0],
    );

    let raw = pane.raw_toml();
    let mut text_lines: Vec<Line> = Vec::new();
    for (i, line) in raw.lines().enumerate() {
        if i < scroll {
            continue;
        }
        if text_lines.len() >= body_h {
            break;
        }
        let ln = i + 1;
        let is_comment = line.trim_start().starts_with('#');
        let is_header = line.trim_start().starts_with('[') && line.contains(']');
        let num_style = Style::default().fg(Color::DarkGray);
        let line_style = if is_header {
            Style::default()
                .fg(Color::Cyan)
                .add_modifier(Modifier::BOLD)
        } else if is_comment {
            Style::default().fg(Color::DarkGray)
        } else if focus_here {
            Style::default().fg(Color::White)
        } else {
            Style::default().fg(Color::Gray)
        };
        text_lines.push(Line::from(vec![
            Span::styled(format!("{ln:>4} │ "), num_style),
            Span::styled(line.to_string(), line_style),
        ]));
    }
    if text_lines.is_empty() {
        text_lines.push(Line::from(Span::styled(
            "(empty config — defaults will be written on save)",
            Style::default().fg(Color::DarkGray),
        )));
    }

    f.render_widget(
        Paragraph::new(text_lines).block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(border)),
        ),
        chunks[1],
    );
}

fn format_item_row(item: &crate::settings::SettingsItem, selected: bool) -> String {
    let cursor = if selected { "› " } else { "  " };
    match &item.kind {
        ItemKind::Header => format!("── {} ", item.label),
        ItemKind::Info { value } => {
            if value.is_empty() {
                format!("{cursor}{}", item.label)
            } else {
                format!("{cursor}{:<28}  {}", item.label, value)
            }
        }
        ItemKind::Toggle { on } => {
            let box_ = if *on { "[● on ]" } else { "[○ off]" };
            format!("{cursor}{box_}  {:<22}  {}", item.label, item.description)
        }
        ItemKind::Enum { options, index } => {
            let cur = options.get(*index).copied().unwrap_or("?");
            let shown: String = options
                .iter()
                .enumerate()
                .map(|(i, o)| {
                    if i == *index {
                        format!("‹{o}›")
                    } else {
                        (*o).to_string()
                    }
                })
                .collect::<Vec<_>>()
                .join(" ");
            format!("{cursor}{:<22}  {shown}   ({cur})", item.label)
        }
    }
}

fn draw_identities_modal(f: &mut Frame, area: Rect, pane: &IdentitiesPane, detail: bool) {
    let modal = centered_rect(92, 86, area);
    f.render_widget(Clear, modal);

    let title = if pane.probing {
        " identities / access · validating… "
    } else {
        " identities / access "
    };
    let outer = Block::default()
        .borders(Borders::ALL)
        .border_style(Style::default().fg(Color::Green))
        .title(Span::styled(
            title,
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        ))
        .title_bottom(Span::styled(
            format!(
                " {} · filter:{} · r refresh · Esc close ",
                pane.inventory.summary_line(),
                pane.filter.label()
            ),
            Style::default().fg(Color::DarkGray),
        ));
    let inner = outer.inner(modal);
    f.render_widget(outer, modal);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(4),
            Constraint::Length(if detail { 10 } else { 3 }),
        ])
        .split(inner);

    let flash = pane.flash.as_deref().unwrap_or(
        "Profiles, ambient CLI sessions, LLM keys, k8s contexts — secrets never shown",
    );
    f.render_widget(
        Paragraph::new(flash).style(Style::default().fg(Color::White)),
        body[0],
    );

    let visible = pane.visible();
    let height = body[1].height.saturating_sub(2) as usize;
    let mut scroll = pane.scroll;
    if pane.selected >= scroll + height.max(1) {
        scroll = pane.selected + 1 - height.max(1);
    }
    if pane.selected < scroll {
        scroll = pane.selected;
    }

    let mut items = Vec::new();
    for (i, e) in visible.iter().enumerate() {
        if i < scroll {
            continue;
        }
        if items.len() >= height {
            break;
        }
        let selected = i == pane.selected;
        let row = IdentitiesPane::format_row(e, selected);
        let style = validity_style(e.validity, selected);
        items.push(ListItem::new(row).style(style));
    }
    if items.is_empty() {
        items.push(ListItem::new("(no identities for this filter)").style(
            Style::default().fg(Color::DarkGray),
        ));
    }

    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" [status] kind cloud id · source · detail ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_widget(list, body[1]);

    // Detail / notes footer
    let detail_text = if detail {
        if let Some(e) = pane.selected_entry() {
            IdentitiesPane::detail_lines(e).join("\n")
        } else {
            String::new()
        }
    } else {
        let mut notes = pane.inventory.notes.clone();
        notes.push("Enter: expand selected · oscar identities check (CLI)".into());
        notes.join(" · ")
    };
    f.render_widget(
        Paragraph::new(detail_text)
            .wrap(Wrap { trim: true })
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(if detail { " detail " } else { " notes " }),
            )
            .style(Style::default().fg(Color::Gray)),
        body[2],
    );
}

fn validity_style(v: Validity, selected: bool) -> Style {
    if selected {
        return Style::default()
            .fg(Color::Black)
            .bg(Color::White)
            .add_modifier(Modifier::BOLD);
    }
    match v {
        Validity::Valid => Style::default().fg(Color::Green),
        Validity::Expired => Style::default().fg(Color::Yellow),
        Validity::Invalid => Style::default().fg(Color::Red),
        Validity::Missing => Style::default().fg(Color::DarkGray),
        Validity::Unknown => Style::default().fg(Color::Cyan),
    }
}

fn draw_provider_modal(f: &mut Frame, area: Rect, pane: &crate::provider_pane::ProviderPane) {
    use crate::provider_pane::{ProviderFocus, ProviderPane};

    let area = centered_rect(88, 78, area);
    f.render_widget(Clear, area);
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" Provider ")
        .border_style(Style::default().fg(Color::Magenta));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(6),
            Constraint::Length(3),
        ])
        .split(inner);

    let def = &pane.config.provider.id;
    let ready = ProviderPane::has_key(def);
    let header = format!(
        " Default: `{def}`  ·  ready={}  ·  model={}  ·  base={}",
        if ready { "yes" } else { "NO" },
        pane.config
            .provider
            .model
            .as_deref()
            .unwrap_or("(provider default)"),
        pane.config
            .provider
            .base_url
            .as_deref()
            .unwrap_or("(provider default)"),
    );
    f.render_widget(
        Paragraph::new(header).style(Style::default().fg(Color::White)),
        body[0],
    );

    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(42), Constraint::Percentage(58)])
        .split(body[1]);

    // Left: provider list (stateful — auto-scrolls so selection stays visible)
    let list_focus = pane.focus == ProviderFocus::List;
    let list_items: Vec<ListItem> = pane
        .rows
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let selected = i == pane.list_idx;
            let is_def = pane.is_default(&r.id);
            let has = if r.id == "__add_custom__" {
                false
            } else {
                ProviderPane::has_key(&r.id)
            };
            let mark = if r.id == "__add_custom__" {
                "  "
            } else if has {
                "● "
            } else {
                "○ "
            };
            let def_mark = if is_def { " ★DEFAULT" } else { "" };
            let prefix = if selected && list_focus {
                "▸ "
            } else if selected {
                "· "
            } else {
                "  "
            };
            let line = format!("{prefix}{mark}{:<16}{def_mark}", r.name);
            let style = if selected && list_focus {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::Magenta)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(Color::Magenta)
            } else if has {
                Style::default().fg(Color::Green)
            } else {
                Style::default().fg(Color::Gray)
            };
            ListItem::new(line).style(style)
        })
        .collect();
    let list = List::new(list_items).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if list_focus {
                Color::Magenta
            } else {
                Color::DarkGray
            })),
    );
    let mut list_state = ListState::default();
    if !pane.rows.is_empty() {
        list_state.select(Some(pane.list_idx.min(pane.rows.len() - 1)));
    }
    f.render_stateful_widget(list, cols[0], &mut list_state);

    // Right: actions + details (also scroll if action list is long)
    let act_focus = pane.focus == ProviderFocus::Actions;
    let mut action_lines: Vec<ListItem> = Vec::new();
    let mut action_select_idx: Option<usize> = None;
    if let Some(row) = pane.selected() {
        action_lines.push(
            ListItem::new(format!("── {} ({}) ", row.name, row.id)).style(
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::BOLD),
            ),
        );
        action_lines.push(
            ListItem::new(format!("  {}", row.auth_hint)).style(Style::default().fg(Color::Gray)),
        );
        action_lines.push(ListItem::new("").style(Style::default()));
        let header_rows = action_lines.len();
        let actions = pane.actions_for_selected();
        for (i, a) in actions.iter().enumerate() {
            let has = ProviderPane::has_key(&row.id);
            let is_def = pane.is_default(&row.id);
            let label = a.label(has, is_def, row.needs_account);
            let selected = i == pane.action_idx;
            if selected {
                action_select_idx = Some(header_rows + i);
            }
            let prefix = if selected && act_focus { "› " } else { "  " };
            let style = if selected && act_focus {
                Style::default()
                    .fg(Color::Black)
                    .bg(Color::White)
                    .add_modifier(Modifier::BOLD)
            } else if selected {
                Style::default().fg(Color::White)
            } else {
                Style::default().fg(Color::Gray)
            };
            action_lines.push(ListItem::new(format!("{prefix}{label}")).style(style));
        }
        action_lines.push(ListItem::new("").style(Style::default()));
        let model = if pane.is_default(&row.id) {
            pane.config
                .provider
                .model
                .clone()
                .unwrap_or_else(|| row.default_model.clone())
        } else {
            row.default_model.clone()
        };
        let base = if pane.is_default(&row.id) {
            pane.config
                .provider
                .base_url
                .clone()
                .unwrap_or_else(|| row.default_base.clone())
        } else {
            row.default_base.clone()
        };
        action_lines.push(
            ListItem::new(format!("  model: {model}")).style(Style::default().fg(Color::Cyan)),
        );
        action_lines.push(
            ListItem::new(format!("  url:   {base}")).style(Style::default().fg(Color::Cyan)),
        );
    }
    let actions_list = List::new(action_lines).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if act_focus {
                Color::White
            } else {
                Color::DarkGray
            })),
    );
    let mut action_state = ListState::default();
    if let Some(i) = action_select_idx {
        action_state.select(Some(i));
    }
    f.render_stateful_widget(actions_list, cols[1], &mut action_state);

    let footer = pane.flash.clone().unwrap_or_else(|| {
        "↑↓ scroll providers · → actions · Enter run · Esc close · paste key securely"
            .into()
    });
    f.render_widget(
        Paragraph::new(footer)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::DarkGray)),
        body[2],
    );
}

fn draw_sessions_modal(f: &mut Frame, area: Rect, pane: &crate::sessions_pane::SessionsPane) {
    let area = centered_rect(82, 72, area);
    f.render_widget(Clear, area);
    let outer = Block::default()
        .borders(Borders::ALL)
        .title(" Resume session ")
        .border_style(Style::default().fg(Color::Cyan));
    let inner = outer.inner(area);
    f.render_widget(outer, area);

    let body = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(2),
            Constraint::Min(6),
            Constraint::Length(2),
            Constraint::Length(2),
        ])
        .split(inner);

    let header = format!(
        " {} saved · filter: {}  ·  current: {}",
        pane.all.len(),
        if pane.filter.is_empty() {
            "(type to search)".into()
        } else {
            format!("«{}»", pane.filter)
        },
        if pane.current_id.is_empty() {
            "—".into()
        } else {
            pane.current_id.chars().take(8).collect::<String>()
        }
    );
    f.render_widget(
        Paragraph::new(header).style(Style::default().fg(Color::White)),
        body[0],
    );

    let items: Vec<ListItem> = if pane.filtered.is_empty() {
        vec![ListItem::new(if pane.all.is_empty() {
            "  (no previous sessions yet — chat first, then /resume)"
        } else {
            "  (no matches for filter)"
        })
        .style(Style::default().fg(Color::DarkGray))]
    } else {
        pane.filtered
            .iter()
            .enumerate()
            .map(|(row, &ai)| {
                let s = &pane.all[ai];
                let selected = row == pane.list_idx;
                let cur = if s.id == pane.current_id { "*" } else { " " };
                let id_short: String = s.id.chars().take(8).collect();
                let title = if s.title.chars().count() > 48 {
                    format!("{}…", s.title.chars().take(47).collect::<String>())
                } else {
                    s.title.clone()
                };
                let preview = if s.preview.is_empty() {
                    String::new()
                } else {
                    let p: String = s.preview.chars().take(56).collect();
                    format!("\n    {p}")
                };
                let line = format!(
                    "{cur} {id_short}  {}  msgs={:<3}  {title}{preview}",
                    s.updated_at.format("%Y-%m-%d %H:%M"),
                    s.message_count,
                );
                let style = if selected {
                    Style::default()
                        .fg(Color::Black)
                        .bg(Color::Cyan)
                        .add_modifier(Modifier::BOLD)
                } else {
                    Style::default().fg(Color::Gray)
                };
                ListItem::new(line).style(style)
            })
            .collect()
    };

    let mut state = ListState::default();
    if !pane.filtered.is_empty() {
        state.select(Some(pane.list_idx));
    }
    let list = List::new(items).block(
        Block::default()
            .borders(Borders::ALL)
            .title(" previous chats ")
            .border_style(Style::default().fg(Color::DarkGray)),
    );
    f.render_stateful_widget(list, body[1], &mut state);

    let detail = pane
        .selected()
        .map(|s| {
            format!(
                " {} / {}  ·  created {}  ·  id {}",
                s.provider,
                s.model,
                s.created_at.format("%Y-%m-%d %H:%M"),
                s.id
            )
        })
        .unwrap_or_else(|| " — ".into());
    f.render_widget(
        Paragraph::new(detail).style(Style::default().fg(Color::DarkGray)),
        body[2],
    );

    let footer = pane.flash.clone().unwrap_or_else(|| {
        "↑↓ select · Enter resume · type filter · Ctrl+U clear filter · Esc close".into()
    });
    f.render_widget(
        Paragraph::new(footer).style(Style::default().fg(Color::DarkGray)),
        body[3],
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, r: Rect) -> Rect {
    let popup_layout = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(r);

    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(popup_layout[1])[1]
}

use crate::app::{App, LineKind, View};
use crate::identities::IdentitiesPane;
use crate::input::InputMode;
use crate::settings::{ItemKind, SettingsCategory, SettingsPane};
use oscar_identity::Validity;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph, Wrap};
use ratatui::Frame;

pub fn draw(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(f.area());

    draw_status(f, chunks[0], app);
    draw_chat(f, chunks[1], app);
    draw_input(f, chunks[2], app);

    match &app.view {
        View::Settings(pane) => draw_settings_modal(f, f.area(), pane),
        View::Identities(pane) => draw_identities_modal(f, f.area(), pane, app.identity_detail),
        View::Provider(pane) => draw_provider_modal(f, f.area(), pane),
        View::Chat => {}
    }
}

fn draw_status(f: &mut Frame, area: Rect, app: &App) {
    // Color tracks compact risk vs configured threshold (Grok default 85% of window):
    // green < ~65% of trip, yellow approaching, red at/over auto-compact threshold.
    let thr = app.config.oscar_config.context.threshold * 100.0;
    let meter_color = app
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
        .unwrap_or(Color::Gray);

    let (bar, usage_label) = context_meter(app);
    let settings_hint = match &app.view {
        View::Settings(_) => "  │ SETTINGS ",
        View::Identities(_) => "  │ IDENTITIES ",
        View::Provider(_) => "  │ PROVIDERS ",
        View::Chat => "  │ /settings /provider /mcp ",
    };
    let mut spans = vec![
        Span::styled(
            app.status.clone(),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        ),
        Span::raw("  "),
        Span::styled(bar, Style::default().fg(meter_color)),
        Span::raw(" "),
        Span::styled(
            usage_label,
            Style::default()
                .fg(meter_color)
                .add_modifier(Modifier::BOLD),
        ),
    ];
    if let Some(act) = app.activity_label() {
        let act_color = match &app.activity {
            crate::app::AgentActivity::Thinking => Color::Magenta,
            crate::app::AgentActivity::Tool { .. } => Color::Yellow,
            crate::app::AgentActivity::Answering => Color::Green,
            crate::app::AgentActivity::Idle => Color::DarkGray,
        };
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            act,
            Style::default()
                .fg(act_color)
                .add_modifier(Modifier::BOLD),
        ));
    }
    spans.push(Span::styled(
        settings_hint,
        Style::default().fg(Color::DarkGray),
    ));
    f.render_widget(Paragraph::new(Line::from(spans)), area);
}

/// Visual bar + `current/max (pct%)` label for the status row.
fn context_meter(app: &App) -> (String, String) {
    let width = 14usize;
    let (pct, label) = match app.context.as_ref() {
        Some(c) => (c.percent, format!(" {}", c.format_short())),
        None => (0.0, " — / — (—%)".into()),
    };
    let filled = ((pct / 100.0) * width as f32).round() as usize;
    let filled = filled.min(width);
    let empty = width - filled;
    let bar = format!("[{}{}]", "█".repeat(filled), "░".repeat(empty));
    (bar, label)
}

fn draw_chat(f: &mut Frame, area: Rect, app: &App) {
    // Render newest-at-bottom: viewport is taken from the end of `app.lines`, then
    // shifted back by `chat_scroll` (0 = pinned to newest). Scroll has a hard cap.
    let height = area.height.saturating_sub(2) as usize;
    let height = height.max(1);
    let total = app.lines.len();
    let max_scroll = app.max_chat_scroll();
    let scroll = app.chat_scroll.min(max_scroll);

    // End of the visible window relative to buffer end
    let end = total.saturating_sub(scroll);
    let start = end.saturating_sub(height);
    let slice = if start < end {
        &app.lines[start..end]
    } else {
        &app.lines[0..0]
    };

    // Pad top so short history still sits at the bottom of the pane (fill backwards)
    let pad = height.saturating_sub(slice.len());
    let mut visible: Vec<Line> = (0..pad)
        .map(|_| Line::from(Span::raw("")))
        .collect();

    for l in slice {
        visible.push(format_chat_line(l));
    }

    let title = if scroll == 0 {
        format!(" chat · newest · {} lines ", total)
    } else {
        format!(
            " chat · ↑{scroll} back (max {max_scroll}) · PgUp/PgDn · End=bottom "
        )
    };
    let border = if scroll == 0 {
        Style::default().fg(Color::DarkGray)
    } else {
        Style::default().fg(Color::Yellow)
    };

    let para = Paragraph::new(visible)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border),
        )
        .wrap(Wrap { trim: false });
    f.render_widget(para, area);
}

/// Grok Build–style line chrome: thinking blocks dim, tools as cards, clear roles.
fn format_chat_line(l: &crate::app::ChatLine) -> Line<'static> {
    match l.kind {
        LineKind::User => Line::from(vec![
            Span::styled(
                "you  │ ",
                Style::default()
                    .fg(Color::Green)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(l.text.clone(), Style::default().fg(Color::Green)),
        ]),
        LineKind::Assistant => Line::from(vec![
            Span::styled(
                "oscar │ ",
                Style::default()
                    .fg(Color::Cyan)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(l.text.clone(), Style::default().fg(Color::White)),
        ]),
        LineKind::Thinking => {
            // Header vs body (│ …)
            let is_body = l.text.starts_with('│');
            if is_body {
                Line::from(vec![
                    Span::styled("      ", Style::default()),
                    Span::styled(
                        l.text.clone(),
                        Style::default()
                            .fg(Color::DarkGray)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        "think│ ",
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(
                        l.text.clone(),
                        Style::default()
                            .fg(Color::Magenta)
                            .add_modifier(Modifier::ITALIC),
                    ),
                ])
            }
        }
        LineKind::Tool => {
            let is_detail = l.text.starts_with("  ") || l.text.starts_with("args:");
            let (mark, color) = if l.text.starts_with('✓') {
                ("tool │ ", Color::Green)
            } else if l.text.starts_with('✗') {
                ("tool │ ", Color::Red)
            } else if l.text.starts_with('⚙') {
                ("tool │ ", Color::Yellow)
            } else {
                ("tool │ ", Color::Magenta)
            };
            if is_detail {
                Line::from(vec![
                    Span::styled("      ", Style::default()),
                    Span::styled(l.text.clone(), Style::default().fg(Color::DarkGray)),
                ])
            } else {
                Line::from(vec![
                    Span::styled(
                        mark,
                        Style::default().fg(color).add_modifier(Modifier::BOLD),
                    ),
                    Span::styled(l.text.clone(), Style::default().fg(color)),
                ])
            }
        }
        LineKind::System => Line::from(vec![
            Span::styled(
                "sys  │ ",
                Style::default()
                    .fg(Color::Blue)
                    .add_modifier(Modifier::BOLD),
            ),
            Span::styled(l.text.clone(), Style::default().fg(Color::Blue)),
        ]),
        LineKind::Error => Line::from(vec![
            Span::styled(
                "err  │ ",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::styled(l.text.clone(), Style::default().fg(Color::Red)),
        ]),
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

    let title = match &app.input_mode {
        InputMode::Normal => {
            if app.streaming {
                " input (streaming — Esc to cancel) ".to_string()
            } else if app.show_idle_input_hint() {
                " input · tip ".to_string()
            } else {
                " input ".to_string()
            }
        }
        InputMode::Secure {
            auth, kind_index, ..
        } => {
            let kind = auth
                .kinds
                .get(*kind_index)
                .map(|k| format!("{k:?}"))
                .unwrap_or_else(|| "secret".into());
            format!(" SECURE · enter {kind} · {} · Esc cancel ", auth.cloud)
        }
    };

    let (text_style, border_fg, show_cursor) = match &app.input_mode {
        InputMode::Normal if app.show_idle_input_hint() => {
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
            let para = Paragraph::new(line).block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(Style::default().fg(Color::DarkGray)),
            );
            f.render_widget(para, area);
            return;
        }
        InputMode::Normal => (Style::default().fg(Color::White), Color::White, true),
        InputMode::Secure { .. } => (Style::default().fg(Color::Yellow), Color::Yellow, true),
    };

    let display = match &app.input_mode {
        InputMode::Secure { buffer, .. } => format!("> {}", "•".repeat(buffer.chars().count())),
        InputMode::Normal => format!("> {}", app.input),
    };
    let title_extra = if show_cursor {
        " · ^A start ^E end ^U clear "
    } else {
        ""
    };
    let full_title = format!("{title}{title_extra}");
    let para = Paragraph::new(display)
        .style(text_style)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(full_title)
                .border_style(Style::default().fg(border_fg)),
        );
    f.render_widget(para, area);

    // Place terminal cursor in the input bar (after "> " + cursor chars).
    if show_cursor && area.width > 3 && area.height > 0 {
        let col = 2u16.saturating_add(app.input_cursor.min(u16::MAX as usize) as u16);
        // Stay inside the inner border
        let max_col = area.width.saturating_sub(2);
        let x = area.x.saturating_add(1).saturating_add(col.min(max_col));
        let y = area.y.saturating_add(1);
        f.set_cursor_position((x, y));
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
    draw_items(f, cols[1], pane);

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
        SettingsCategory::Provider => {
            " Provider: xAI/OpenCode = browser sign-in · OpenAI/Claude = API key · chat blocked until ready "
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
        .title(" LLM providers · set default · open console · paste key · custom URL ")
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

    // Left: provider list
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
            .title(if list_focus {
                " providers · focused "
            } else {
                " providers "
            })
            .border_style(Style::default().fg(if list_focus {
                Color::Magenta
            } else {
                Color::DarkGray
            })),
    );
    f.render_widget(list, cols[0]);

    // Right: actions + details
    let act_focus = pane.focus == ProviderFocus::Actions;
    let mut action_lines: Vec<ListItem> = Vec::new();
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
        let actions = pane.actions_for_selected();
        for (i, a) in actions.iter().enumerate() {
            let has = ProviderPane::has_key(&row.id);
            let is_def = pane.is_default(&row.id);
            let label = a.label(has, is_def, row.needs_account);
            let selected = i == pane.action_idx;
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
            .title(if act_focus {
                " actions · focused · ← back "
            } else {
                " actions · → open "
            })
            .border_style(Style::default().fg(if act_focus {
                Color::White
            } else {
                Color::DarkGray
            })),
    );
    f.render_widget(actions_list, cols[1]);

    let footer = pane.flash.clone().unwrap_or_else(|| {
        "xAI/OpenCode: open console → sign in → copy key → paste · OpenAI/Claude: paste API key"
            .into()
    });
    f.render_widget(
        Paragraph::new(footer)
            .wrap(Wrap { trim: true })
            .style(Style::default().fg(Color::DarkGray)),
        body[2],
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

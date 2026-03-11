use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, BorderType, Clear, List, ListItem, ListState, Padding, Paragraph, Wrap};

use super::app::{App, Filter, Mode};

const GREEN: Color = Color::Green;
const YELLOW: Color = Color::Yellow;
const RED: Color = Color::Red;
const CYAN: Color = Color::Cyan;
const DIM: Color = Color::DarkGray;
const TEXT: Color = Color::Reset; // uses terminal's default foreground

pub fn draw(f: &mut Frame, app: &mut App) {
    let area = f.area();

    let has_search_bar = app.mode == Mode::Search || !app.search_query.is_empty();

    let constraints = if has_search_bar {
        vec![
            Constraint::Length(1), // header
            Constraint::Min(5),   // feed
            Constraint::Length(1), // search bar
            Constraint::Length(1), // status bar
        ]
    } else {
        vec![
            Constraint::Length(1), // header
            Constraint::Min(5),   // feed
            Constraint::Length(1), // status bar
        ]
    };

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints(constraints)
        .split(area);

    draw_header(f, app, chunks[0]);
    draw_feed(f, app, chunks[1]);

    if has_search_bar {
        draw_search_bar(f, app, chunks[2]);
        draw_status_bar(f, app, chunks[3]);
    } else {
        draw_status_bar(f, app, chunks[2]);
    }

    if app.show_help {
        draw_help_overlay(f, area);
    }
}

fn draw_header(f: &mut Frame, app: &App, area: Rect) {
    let elapsed = app.start_time.elapsed();
    let mins = elapsed.as_secs() / 60;
    let secs = elapsed.as_secs() % 60;

    let filter_text = match app.filter {
        Filter::All => "",
        Filter::Blocks => " [blocks]",
        Filter::Approvals => " [approvals]",
    };

    let session_info = if let Some(ref pinned) = app.pinned_session {
        format!(" session {} \u{2500}\u{2500}", App::short_session(pinned))
    } else {
        format!(" {} sessions \u{2500}\u{2500}", app.session_count)
    };

    let header = Line::from(vec![
        Span::styled(" railyard", Style::default().fg(TEXT).bold()),
        Span::styled(
            format!(
                " \u{2500}\u{2500}{} {} calls \u{2500}\u{2500} {}m {:02}s{}",
                session_info,
                app.entries.len(),
                mins,
                secs,
                filter_text,
            ),
            Style::default().fg(DIM),
        ),
    ]);

    f.render_widget(Paragraph::new(header), area);
}

fn draw_feed(f: &mut Frame, app: &mut App, area: Rect) {
    let feed_block = Block::default()
        .borders(Borders::TOP | Borders::BOTTOM)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(DIM));

    let inner = feed_block.inner(area);
    f.render_widget(feed_block, area);

    if app.filtered_indices.is_empty() {
        let msg = if !app.search_query.is_empty() {
            format!("  No results for \"{}\"", app.search_query)
        } else {
            "  Waiting for tool calls...".to_string()
        };
        let empty = Paragraph::new(Span::styled(msg, Style::default().fg(DIM)));
        f.render_widget(empty, inner);
        return;
    }

    let show_session = app.pinned_session.is_none() && app.session_count > 1;

    // Build list items
    let mut items: Vec<ListItem> = Vec::new();

    for (display_idx, &entry_idx) in app.filtered_indices.iter().enumerate() {
        let entry = &app.entries[entry_idx];

        let (icon, icon_color) = match entry.decision.as_str() {
            "allow" | "completed" => ("\u{2713}", GREEN),
            "approve" | "warn" => ("\u{25cf}", YELLOW),
            "block" => ("\u{2717}", RED),
            _ => ("?", DIM),
        };

        let decision_label = match entry.decision.as_str() {
            "allow" | "completed" => "allow  ",
            "approve" => "approve",
            "warn" => "warn   ",
            "block" => "block  ",
            _ => "???    ",
        };

        let tool_display = format!("{:<6}", if entry.tool.len() > 6 {
            &entry.tool[..6]
        } else {
            &entry.tool
        });

        // Session tag (last 4 chars)
        let session_tag = if show_session {
            format!("{} ", App::short_session(&entry.session_id))
        } else {
            String::new()
        };

        // Truncate input summary to fit
        let overhead = 30 + session_tag.len();
        let max_input_len = (inner.width as usize).saturating_sub(overhead);
        let input = if entry.input_summary.len() > max_input_len {
            format!("{}...", &entry.input_summary[..max_input_len.saturating_sub(3)])
        } else {
            entry.input_summary.clone()
        };

        let time = extract_time(&entry.timestamp);

        let rule_suffix = if entry.decision == "block" {
            entry.rule.as_deref().map(|r| format!(" \u{2500} {}", r)).unwrap_or_default()
        } else {
            String::new()
        };

        let mut spans = vec![
            Span::styled(format!("  {} ", icon), Style::default().fg(icon_color).bold()),
            Span::styled(format!("{} ", decision_label), Style::default().fg(icon_color)),
        ];

        if show_session {
            spans.push(Span::styled(
                session_tag,
                Style::default().fg(Color::Magenta),
            ));
        }

        spans.push(Span::styled(format!("{} ", tool_display), Style::default().fg(CYAN)));
        spans.push(Span::styled(input, Style::default().fg(TEXT)));
        spans.push(Span::styled(rule_suffix, Style::default().fg(DIM)));
        spans.push(Span::styled(format!("  {}", time), Style::default().fg(DIM)));

        let line = Line::from(spans);
        items.push(ListItem::new(line));

        // Expanded detail view
        if app.expanded == Some(display_idx) {
            let detail_lines = build_detail_lines(entry);
            for dl in detail_lines {
                items.push(dl);
            }
        }
    }

    let list = List::new(items)
        .highlight_style(Style::default().bg(Color::Rgb(30, 30, 40)));
    let mut list_state = ListState::default();
    list_state.select(Some(app.selected));

    f.render_stateful_widget(list, inner, &mut list_state);
}

fn build_detail_lines<'a>(entry: &crate::types::TraceEntry) -> Vec<ListItem<'a>> {
    let mut lines = Vec::new();
    let prefix = Span::styled("    \u{250a} ", Style::default().fg(DIM));

    lines.push(ListItem::new(Line::from(vec![
        prefix.clone(),
        Span::styled(
            format!("session: {}", entry.session_id),
            Style::default().fg(DIM),
        ),
    ])));

    lines.push(ListItem::new(Line::from(vec![
        prefix.clone(),
        Span::styled(format!("event: {}", entry.event), Style::default().fg(DIM)),
    ])));

    lines.push(ListItem::new(Line::from(vec![
        prefix.clone(),
        Span::styled(
            format!("input: {}", entry.input_summary),
            Style::default().fg(DIM),
        ),
    ])));

    if let Some(ref rule) = entry.rule {
        lines.push(ListItem::new(Line::from(vec![
            prefix.clone(),
            Span::styled(format!("rule: {}", rule), Style::default().fg(DIM)),
        ])));
    }

    lines.push(ListItem::new(Line::from(vec![
        prefix.clone(),
        Span::styled(
            format!("latency: {}ms", entry.duration_ms),
            Style::default().fg(DIM),
        ),
    ])));

    lines.push(ListItem::new(Line::from(vec![Span::raw("")])));

    lines
}

fn draw_search_bar(f: &mut Frame, app: &App, area: Rect) {
    let cursor = if app.mode == Mode::Search { "_" } else { "" };
    let match_count = app.filtered_indices.len();

    let search = Line::from(vec![
        Span::styled("  / ", Style::default().fg(YELLOW).bold()),
        Span::styled(
            format!("{}{}", app.search_query, cursor),
            Style::default().fg(TEXT),
        ),
        Span::styled(
            format!("  {} matches", match_count),
            Style::default().fg(DIM),
        ),
    ]);

    f.render_widget(Paragraph::new(search), area);
}

fn draw_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let total = app.entries.len();
    let allowed = app.count_by_decision("allow") + app.count_by_decision("completed");
    let approved = app.count_by_decision("approve") + app.count_by_decision("warn");
    let blocked = app.count_by_decision("block");

    let threat_text = if let Some(state) = app.worst_threat_state() {
        if state.terminated {
            let reason = state.termination_reason.as_deref().unwrap_or("unknown");
            format!(
                "\u{2717} TERMINATED ({}) \u{2500} {}",
                App::short_session(&state.session_id),
                reason
            )
        } else if state.is_in_heightened_state() {
            let remaining = state
                .heightened_until_call
                .map(|u| u.saturating_sub(state.tool_call_count))
                .unwrap_or(0);
            format!("\u{26a0} heightened (watching {} more calls)", remaining)
        } else if state.suspicion_level > 0 {
            format!("warned ({})", state.warning_count)
        } else {
            "normal".to_string()
        }
    } else {
        "normal".to_string()
    };

    let is_terminated = app
        .worst_threat_state()
        .map_or(false, |s| s.terminated);

    let bar_style = if is_terminated {
        Style::default().bg(Color::Red).fg(TEXT).bold()
    } else {
        Style::default().fg(DIM)
    };

    let status = Line::from(vec![
        Span::styled(format!("  {} total", total), bar_style),
        Span::styled("   ", bar_style),
        Span::styled(
            format!("{}", allowed),
            Style::default().fg(GREEN).patch(bar_style),
        ),
        Span::styled(" \u{2713} allowed", bar_style),
        Span::styled("   ", bar_style),
        Span::styled(
            format!("{}", approved),
            Style::default().fg(YELLOW).patch(bar_style),
        ),
        Span::styled(" \u{25cf} approved", bar_style),
        Span::styled("   ", bar_style),
        Span::styled(
            format!("{}", blocked),
            Style::default().fg(RED).patch(bar_style),
        ),
        Span::styled(" \u{2717} blocked", bar_style),
        Span::styled(
            format!("   threat: {}", threat_text),
            if is_terminated {
                Style::default().bg(Color::Red).fg(TEXT).bold()
            } else {
                Style::default().fg(DIM)
            },
        ),
    ]);

    f.render_widget(Paragraph::new(status), area);
}

fn draw_help_overlay(f: &mut Frame, area: Rect) {
    let help_width = 42u16;
    let help_height = 16u16;
    let x = area.width.saturating_sub(help_width) / 2;
    let y = area.height.saturating_sub(help_height) / 2;
    let help_area = Rect::new(x, y, help_width.min(area.width), help_height.min(area.height));

    f.render_widget(Clear, help_area);

    let help_text = vec![
        Line::from(""),
        Line::from(vec![
            Span::styled("  j/\u{2191}    ", Style::default().fg(CYAN)),
            Span::raw("scroll up"),
        ]),
        Line::from(vec![
            Span::styled("  k/\u{2193}    ", Style::default().fg(CYAN)),
            Span::raw("scroll down"),
        ]),
        Line::from(vec![
            Span::styled("  G       ", Style::default().fg(CYAN)),
            Span::raw("jump to latest (tail)"),
        ]),
        Line::from(vec![
            Span::styled("  g       ", Style::default().fg(CYAN)),
            Span::raw("jump to start"),
        ]),
        Line::from(vec![
            Span::styled("  Enter   ", Style::default().fg(CYAN)),
            Span::raw("expand/collapse detail"),
        ]),
        Line::from(vec![
            Span::styled("  f       ", Style::default().fg(CYAN)),
            Span::raw("cycle filter"),
        ]),
        Line::from(vec![
            Span::styled("  /       ", Style::default().fg(CYAN)),
            Span::raw("search"),
        ]),
        Line::from(vec![
            Span::styled("  Esc     ", Style::default().fg(CYAN)),
            Span::raw("clear search/filter/collapse"),
        ]),
        Line::from(vec![
            Span::styled("  ?       ", Style::default().fg(CYAN)),
            Span::raw("toggle this help"),
        ]),
        Line::from(vec![
            Span::styled("  q       ", Style::default().fg(CYAN)),
            Span::raw("quit"),
        ]),
        Line::from(""),
    ];

    let help = Paragraph::new(help_text)
        .block(
            Block::default()
                .title(" keybindings ")
                .title_style(Style::default().fg(TEXT).bold())
                .borders(Borders::ALL)
                .border_type(BorderType::Rounded)
                .border_style(Style::default().fg(DIM))
                .padding(Padding::horizontal(1)),
        )
        .wrap(Wrap { trim: false });

    f.render_widget(help, help_area);
}

fn extract_time(timestamp: &str) -> String {
    if let Some(t_pos) = timestamp.find('T') {
        let after_t = &timestamp[t_pos + 1..];
        if after_t.len() >= 8 {
            return after_t[..8].to_string();
        }
    }
    if timestamp.len() >= 8 {
        timestamp[timestamp.len() - 8..].to_string()
    } else {
        timestamp.to_string()
    }
}

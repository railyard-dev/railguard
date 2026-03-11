mod app;
mod ui;

use std::io::{self, Write as _};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use ratatui::prelude::*;

use crate::{trace, threat::state::SessionState};
use app::{App, Filter, Mode};

/// Run the dashboard TUI.
pub fn run(session: Option<String>) -> i32 {
    let cwd = std::env::current_dir().unwrap_or_default();
    let trace_dir = trace::logger::global_trace_dir();
    let state_dir = cwd.join(".railyard/state");

    match run_tui(session, &trace_dir, &state_dir) {
        Ok(_) => 0,
        Err(e) => {
            eprintln!("Dashboard error: {}", e);
            1
        }
    }
}

/// Run a simple streaming dashboard (no TUI).
pub fn run_stream(session: Option<String>, history: bool) -> i32 {
    let trace_dir = trace::logger::global_trace_dir();

    eprintln!("railyard dashboard — watching {}", trace_dir.display());
    eprintln!("Press Ctrl+C to stop.\n");

    // Load existing entries to get initial count (skip history)
    let initial_count = {
        let sessions = if let Some(ref pinned) = session {
            vec![pinned.clone()]
        } else {
            trace::logger::list_sessions(&trace_dir).unwrap_or_default()
        };
        let mut count = 0;
        for session_id in &sessions {
            if let Ok(entries) = trace::logger::read_traces(&trace_dir, session_id) {
                count += entries.len();
            }
        }
        if !history {
            eprintln!("{} historical entries (use --history to show them)\n", count);
        }
        if history { 0 } else { count }
    };

    let mut seen_count: usize = initial_count;

    loop {
        let sessions = if let Some(ref pinned) = session {
            vec![pinned.clone()]
        } else {
            trace::logger::list_sessions(&trace_dir).unwrap_or_default()
        };

        let mut all_entries = Vec::new();
        for session_id in &sessions {
            if let Ok(entries) = trace::logger::read_traces(&trace_dir, session_id) {
                all_entries.extend(entries);
            }
        }

        all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

        // Print only new entries
        if all_entries.len() > seen_count {
            for entry in &all_entries[seen_count..] {
                let icon = match entry.decision.as_str() {
                    "allow" | "completed" => "\x1b[32m✓\x1b[0m",
                    "approve" | "warn" => "\x1b[33m●\x1b[0m",
                    "block" => "\x1b[31m✗\x1b[0m",
                    _ => "?",
                };

                let time = extract_time(&entry.timestamp);
                let rule_info = entry.rule.as_deref()
                    .map(|r| format!(" ({})", r))
                    .unwrap_or_default();

                let session_short = if entry.session_id.len() > 4 {
                    &entry.session_id[entry.session_id.len() - 4..]
                } else {
                    &entry.session_id
                };

                println!(
                    "{} {:<8} \x1b[36m{:<6}\x1b[0m \x1b[35m{}\x1b[0m {}{}  \x1b[90m{}\x1b[0m",
                    icon,
                    entry.decision,
                    truncate(&entry.tool, 6),
                    session_short,
                    truncate(&entry.input_summary, 80),
                    rule_info,
                    time,
                );
            }
            seen_count = all_entries.len();
            io::stdout().flush().ok();
        }

        std::thread::sleep(Duration::from_millis(500));
    }
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
}

fn extract_time(timestamp: &str) -> String {
    if let Some(t_pos) = timestamp.find('T') {
        let after_t = &timestamp[t_pos + 1..];
        if after_t.len() >= 8 {
            return after_t[..8].to_string();
        }
    }
    timestamp.to_string()
}

fn run_tui(session: Option<String>, trace_dir: &Path, state_dir: &Path) -> io::Result<()> {
    // Restore terminal on panic
    let original_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let _ = disable_raw_mode();
        let _ = execute!(io::stdout(), LeaveAlternateScreen);
        original_hook(info);
    }));

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut app = App::new(session);
    let tick_rate = Duration::from_millis(500);
    let mut last_poll = Instant::now();
    let trace_dir = trace_dir.to_path_buf();
    let state_dir = state_dir.to_path_buf();

    // Initial load
    reload_data(&mut app, &trace_dir, &state_dir);

    loop {
        terminal.draw(|f| ui::draw(f, &mut app))?;

        let timeout = tick_rate.saturating_sub(last_poll.elapsed());
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    // Search mode: capture keystrokes into search query
                    if app.mode == Mode::Search {
                        match key.code {
                            KeyCode::Esc => {
                                app.mode = Mode::Normal;
                                app.search_query.clear();
                                app.update_filtered();
                            }
                            KeyCode::Enter => {
                                app.mode = Mode::Normal;
                                // Keep the filter active
                            }
                            KeyCode::Backspace => {
                                app.search_query.pop();
                                app.update_filtered();
                            }
                            KeyCode::Char(c) => {
                                app.search_query.push(c);
                                app.update_filtered();
                            }
                            _ => {}
                        }
                    } else {
                        match key.code {
                            KeyCode::Char('q') => break,
                            KeyCode::Char('c') if key.modifiers.contains(KeyModifiers::CONTROL) => break,
                            KeyCode::Up | KeyCode::Char('k') => {
                                app.scroll_up();
                                app.tailing = false;
                            }
                            KeyCode::Down | KeyCode::Char('j') => {
                                app.scroll_down();
                            }
                            KeyCode::Char('G') => {
                                app.jump_to_end();
                                app.tailing = true;
                            }
                            KeyCode::Char('g') => {
                                app.jump_to_start();
                                app.tailing = false;
                            }
                            KeyCode::Enter => {
                                app.toggle_expand();
                            }
                            KeyCode::Esc => {
                                if app.expanded.is_some() {
                                    app.expanded = None;
                                } else if !app.search_query.is_empty() {
                                    app.search_query.clear();
                                    app.update_filtered();
                                } else if app.filter != Filter::All {
                                    app.filter = Filter::All;
                                    app.update_filtered();
                                }
                            }
                            KeyCode::Char('f') => {
                                app.cycle_filter();
                            }
                            KeyCode::Char('/') => {
                                app.mode = Mode::Search;
                            }
                            KeyCode::Char('?') => {
                                app.show_help = !app.show_help;
                            }
                            _ => {}
                        }
                    }
                }
                Event::Resize(_, _) => {}
                _ => {}
            }
        }

        if last_poll.elapsed() >= tick_rate {
            reload_data(&mut app, &trace_dir, &state_dir);
            last_poll = Instant::now();
        }
    }

    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    Ok(())
}

fn reload_data(app: &mut App, trace_dir: &std::path::PathBuf, state_dir: &std::path::PathBuf) {
    // Load traces from all sessions (or pinned session)
    let sessions = if let Some(ref pinned) = app.pinned_session {
        vec![pinned.clone()]
    } else {
        trace::logger::list_sessions(trace_dir).unwrap_or_default()
    };

    let mut all_entries = Vec::new();
    let mut states = Vec::new();

    for session_id in &sessions {
        if let Ok(entries) = trace::logger::read_traces(trace_dir, session_id) {
            all_entries.extend(entries);
        }
        if state_dir.exists() {
            let state = SessionState::load(state_dir, session_id);
            states.push(state);
        }
    }

    // Sort all entries by timestamp
    all_entries.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));

    let was_at_end = app.tailing;
    let old_len = app.entries.len();
    app.entries = all_entries;
    app.session_states = states;
    app.session_count = sessions.len();
    app.update_filtered();

    // Auto-scroll if we were tailing and new entries arrived
    if was_at_end && app.entries.len() > old_len {
        app.jump_to_end();
    }

    app.last_update = Instant::now();
}

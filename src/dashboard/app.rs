use std::time::Instant;

use crate::threat::state::SessionState;
use crate::types::TraceEntry;

#[derive(Debug, Clone, PartialEq)]
pub enum Filter {
    All,
    Blocks,
    Approvals,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Mode {
    Normal,
    Search,
}

pub struct App {
    pub pinned_session: Option<String>, // Some if --session was passed
    pub entries: Vec<TraceEntry>,
    pub filtered_indices: Vec<usize>,
    pub selected: usize,
    pub filter: Filter,
    pub mode: Mode,
    pub search_query: String,
    pub expanded: Option<usize>,
    pub session_states: Vec<SessionState>,
    pub session_count: usize,
    pub tailing: bool,
    pub show_help: bool,
    pub last_update: Instant,
    pub start_time: Instant,
}

impl App {
    pub fn new(pinned_session: Option<String>) -> Self {
        App {
            pinned_session,
            entries: Vec::new(),
            filtered_indices: Vec::new(),
            selected: 0,
            filter: Filter::All,
            mode: Mode::Normal,
            search_query: String::new(),
            expanded: None,
            session_states: Vec::new(),
            session_count: 0,
            tailing: true,
            show_help: false,
            last_update: Instant::now(),
            start_time: Instant::now(),
        }
    }

    pub fn update_filtered(&mut self) {
        let query = self.search_query.to_lowercase();
        self.filtered_indices = self
            .entries
            .iter()
            .enumerate()
            .filter(|(_, e)| match self.filter {
                Filter::All => true,
                Filter::Blocks => e.decision == "block",
                Filter::Approvals => e.decision == "approve",
            })
            .filter(|(_, e)| {
                if query.is_empty() {
                    return true;
                }
                // Search across tool, input, decision, rule, and session_id
                e.tool.to_lowercase().contains(&query)
                    || e.input_summary.to_lowercase().contains(&query)
                    || e.decision.to_lowercase().contains(&query)
                    || e.rule.as_deref().unwrap_or("").to_lowercase().contains(&query)
                    || e.session_id.to_lowercase().contains(&query)
            })
            .map(|(i, _)| i)
            .collect();
    }

    pub fn scroll_up(&mut self) {
        if self.selected > 0 {
            self.selected -= 1;
        }
    }

    pub fn scroll_down(&mut self) {
        let max = self.filtered_indices.len().saturating_sub(1);
        if self.selected < max {
            self.selected += 1;
        }
        if self.selected == max {
            self.tailing = true;
        }
    }

    pub fn jump_to_end(&mut self) {
        self.selected = self.filtered_indices.len().saturating_sub(1);
        self.tailing = true;
    }

    pub fn jump_to_start(&mut self) {
        self.selected = 0;
    }

    pub fn toggle_expand(&mut self) {
        if self.expanded == Some(self.selected) {
            self.expanded = None;
        } else {
            self.expanded = Some(self.selected);
        }
    }

    pub fn cycle_filter(&mut self) {
        self.filter = match self.filter {
            Filter::All => Filter::Blocks,
            Filter::Blocks => Filter::Approvals,
            Filter::Approvals => Filter::All,
        };
        self.update_filtered();
        self.selected = self.filtered_indices.len().saturating_sub(1);
        self.expanded = None;
    }

    /// Short session ID (last 4 chars) for display in the feed.
    pub fn short_session(session_id: &str) -> &str {
        if session_id.len() > 4 {
            &session_id[session_id.len() - 4..]
        } else {
            session_id
        }
    }

    pub fn count_by_decision(&self, decision: &str) -> usize {
        self.entries.iter().filter(|e| e.decision == decision).count()
    }

    /// Get the most concerning threat state across all sessions.
    pub fn worst_threat_state(&self) -> Option<&SessionState> {
        self.session_states
            .iter()
            .max_by_key(|s| {
                if s.terminated { 3 }
                else if s.is_in_heightened_state() { 2 }
                else if s.suspicion_level > 0 { 1 }
                else { 0 }
            })
    }
}

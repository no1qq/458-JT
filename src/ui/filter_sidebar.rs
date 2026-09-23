use std::collections::HashSet;

use egui::{ScrollArea, TextEdit, Ui};

use crate::core::usn_record::{
    ALL_REASONS, USN_REASON_BASIC_INFO_CHANGE, USN_REASON_FILE_CREATE, USN_REASON_FILE_DELETE,
    USN_REASON_RENAME_NEW_NAME,
};

#[derive(Clone, Debug)]
pub struct FilterState {
    pub reason_query: String,
    pub enabled_reasons: HashSet<u32>,
}

impl Default for FilterState {
    fn default() -> Self {
        let mut set = HashSet::with_capacity(24);
        for (flag, _) in ALL_REASONS {
            set.insert(*flag);
        }
        Self {
            reason_query: String::new(),
            enabled_reasons: set,
        }
    }
}

impl FilterState {
    pub fn is_reason_allowed(&self, reason: u32) -> bool {
        if self.enabled_reasons.is_empty() {
            return false;
        }
        if self.enabled_reasons.len() == 24 {
            return true;
        }
        for flag in &self.enabled_reasons {
            if (reason & *flag) != 0 {
                return true;
            }
        }
        false
    }

    pub fn select_all(&mut self) {
        for (flag, _) in ALL_REASONS {
            self.enabled_reasons.insert(*flag);
        }
    }

    pub fn deselect_all(&mut self) {
        self.enabled_reasons.clear();
    }

    pub fn invert_selection(&mut self) {
        let mut inverted = HashSet::with_capacity(24);
        for (flag, _) in ALL_REASONS {
            if !self.enabled_reasons.contains(flag) {
                inverted.insert(*flag);
            }
        }
        self.enabled_reasons = inverted;
    }

    pub fn apply_pc_check_preset(&mut self) {
        self.enabled_reasons.clear();
        self.enabled_reasons.insert(USN_REASON_FILE_CREATE);
        self.enabled_reasons.insert(USN_REASON_FILE_DELETE);
        self.enabled_reasons.insert(USN_REASON_RENAME_NEW_NAME);
        self.enabled_reasons.insert(USN_REASON_BASIC_INFO_CHANGE);
    }
}

pub fn render_filter_sidebar(ui: &mut Ui, state: &mut FilterState) -> bool {
    let mut changed = false;

    ui.heading("Filter Reasons");
    ui.add_space(6.0);

    let edit_resp = ui.add(
        TextEdit::singleline(&mut state.reason_query)
            .hint_text("Filter reasons...")
            .desired_width(f32::INFINITY),
    );
    if edit_resp.changed() {
        changed = true;
    }

    ui.add_space(8.0);

    ui.horizontal(|ui| {
        if ui.button("Select All").clicked() {
            state.select_all();
            changed = true;
        }
        if ui.button("Deselect All").clicked() {
            state.deselect_all();
            changed = true;
        }
        if ui.button("Invert").clicked() {
            state.invert_selection();
            changed = true;
        }
    });

    ui.add_space(4.0);

    if ui
        .button("PC Check Filter")
        .on_hover_text("Created + Deleted + Rename New + Basic Info")
        .clicked()
    {
        state.apply_pc_check_preset();
        changed = true;
    }

    ui.separator();
    ui.add_space(4.0);

    let query_lower = state.reason_query.trim().to_ascii_lowercase();

    ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
        for (flag, name) in ALL_REASONS {
            if !query_lower.is_empty() && !name.to_ascii_lowercase().contains(&query_lower) {
                continue;
            }

            let mut is_checked = state.enabled_reasons.contains(flag);
            if ui.checkbox(&mut is_checked, *name).changed() {
                if is_checked {
                    state.enabled_reasons.insert(*flag);
                } else {
                    state.enabled_reasons.remove(flag);
                }
                changed = true;
            }
        }
    });

    changed
}

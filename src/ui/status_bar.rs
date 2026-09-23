use egui::{ProgressBar, Ui};

use crate::core::worker::ScanStats;

pub fn render_status_bar(
    ui: &mut Ui,
    stats: &ScanStats,
    status_message: &str,
    progress: Option<f32>,
) {
    ui.horizontal(|ui| {
        ui.label(format!("Oldest entry (local): {}", stats.oldest_timestamp_formatted));
        ui.separator();
        ui.label(format!("Quantity of entries: {}", stats.total_entries));
        ui.separator();
        ui.label(format!("Files: {}", stats.file_count));
        ui.separator();
        ui.label(format!("Directories: {}", stats.dir_count));

        if let Some(p) = progress {
            ui.separator();
            ui.add(ProgressBar::new(p).desired_width(140.0));
        }

        if !status_message.is_empty() {
            ui.separator();
            ui.label(status_message);
        }
    });
}

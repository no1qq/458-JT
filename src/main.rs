#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod antiforensics;
mod app;
mod core;
mod reporting;
mod ui;

use app::App;
use core::volume::{enable_privileges, is_process_elevated};

fn main() -> eframe::Result<()> {
    let target_drive = std::env::var("SystemDrive")
        .ok()
        .and_then(|s| s.chars().next())
        .unwrap_or('C');

    let privilege_error = if !is_process_elevated() {
        Some("458 JT was launched without Administrator privileges. Raw volume access will be restricted.".to_string())
    } else {
        if let Err(e) = enable_privileges() {
            Some(format!("Could not acquire all forensic privileges: {}", e))
        } else {
            None
        }
    };

    let native_options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_inner_size([1280.0, 780.0])
            .with_min_inner_size([960.0, 560.0])
            .with_title("458 JT - Forensic USN Journal & Anti-Forensics Inspector"),
        ..Default::default()
    };

    eframe::run_native(
        "458 JT",
        native_options,
        Box::new(move |_cc| Ok(Box::new(App::new(target_drive, privilege_error)))),
    )
}

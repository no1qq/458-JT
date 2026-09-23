#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

mod antiforensics;
mod app;
mod core;
mod reporting;
mod ui;

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;

use app::App;
use core::volume::{enable_privileges, is_process_elevated};

fn relaunch_as_admin() -> bool {
    if let Ok(exe_path) = std::env::current_exe() {
        let exe_wide: Vec<u16> = exe_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();
        let verb_wide: Vec<u16> = OsStr::new("runas")
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        let args: Vec<String> = std::env::args().skip(1).collect();
        let args_joined = args.join(" ");
        let args_wide: Vec<u16> = OsStr::new(&args_joined)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        unsafe {
            let res = windows_sys::Win32::UI::Shell::ShellExecuteW(
                0,
                verb_wide.as_ptr(),
                exe_wide.as_ptr(),
                if args.is_empty() {
                    std::ptr::null()
                } else {
                    args_wide.as_ptr()
                },
                std::ptr::null(),
                windows_sys::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL,
            );
            (res as usize) > 32
        }
    } else {
        false
    }
}

fn main() -> eframe::Result<()> {
    if !is_process_elevated() && relaunch_as_admin() {
        return Ok(());
    }

    let target_drive = std::env::var("SystemDrive")
        .ok()
        .and_then(|s| s.chars().next())
        .unwrap_or('C');

    let privilege_error = if !is_process_elevated() {
        Some("458 JT was launched without Administrator privileges. Raw volume access will be restricted.".to_string())
    } else if let Err(e) = enable_privileges() {
        Some(format!("Could not acquire all forensic privileges: {}", e))
    } else {
        None
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

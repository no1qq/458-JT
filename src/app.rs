use std::sync::atomic::Ordering;

use egui::{Context, TopBottomPanel, SidePanel, CentralPanel};
use rayon::prelude::*;
use regex::Regex;

use crate::antiforensics::AntiForensicsReport;
use crate::core::usn_record::UsnRecord;
use crate::core::worker::{ScanStats, WorkerEvent, WorkerHandle};
use crate::reporting::csv::export_records_to_csv;
use crate::reporting::json::export_state_to_json;
use crate::ui::bypass_modal::{render_bypass_modal, BypassModalAction};
use crate::ui::detail_view::render_detail_view;
use crate::ui::filter_sidebar::{render_filter_sidebar, FilterState};
use crate::ui::status_bar::render_status_bar;
use crate::ui::table_view::render_table_view;
use crate::ui::theme::apply_theme;
use crate::ui::top_bar::{render_top_bar, JournalSource, TopBarAction};

pub struct App {
    pub records: Vec<UsnRecord>,
    pub filtered_indices: Vec<usize>,
    pub search_query: String,
    pub regex_filter: Option<Regex>,
    pub filter_state: FilterState,
    pub selected_record_id: Option<usize>,
    pub current_source: JournalSource,
    pub dark_mode: bool,
    pub bypass_modal_open: bool,
    pub detail_modal_open: bool,
    pub worker: WorkerHandle,
    pub scan_stats: ScanStats,
    pub antiforensics_report: AntiForensicsReport,
    pub status_message: String,
    pub current_progress: Option<f32>,
    pub target_drive: char,
    pub privilege_error: Option<String>,
}

impl App {
    pub fn new(target_drive: char, privilege_error: Option<String>) -> Self {
        let worker = WorkerHandle::new();
        if privilege_error.is_none() {
            worker.start_scan(target_drive);
        }

        Self {
            records: Vec::with_capacity(300_000),
            filtered_indices: Vec::new(),
            search_query: String::new(),
            regex_filter: None,
            filter_state: FilterState::default(),
            selected_record_id: None,
            current_source: JournalSource::ActiveJournal,
            dark_mode: true,
            bypass_modal_open: false,
            detail_modal_open: false,
            worker,
            scan_stats: ScanStats::default(),
            antiforensics_report: AntiForensicsReport::default(),
            status_message: "Initializing...".to_string(),
            current_progress: Some(0.0),
            target_drive,
            privilege_error,
        }
    }

    pub fn recompute_filter(&mut self) {
        let query = self.search_query.trim();
        let is_regex = query.starts_with("r/") && query.len() > 2;

        self.regex_filter = if is_regex {
            let pattern = if query.ends_with('/') && query.len() > 3 {
                &query[2..query.len() - 1]
            } else {
                &query[2..]
            };
            Regex::new(pattern).ok()
        } else {
            None
        };

        let query_lower = query.to_ascii_lowercase();
        let filter_state = &self.filter_state;
        let regex_opt = &self.regex_filter;

        self.filtered_indices = self
            .records
            .par_iter()
            .enumerate()
            .filter_map(|(idx, r)| {
                if !filter_state.is_reason_allowed(r.reason) {
                    return None;
                }

                if query.is_empty() {
                    return Some(idx);
                }

                if let Some(re) = regex_opt {
                    if re.is_match(&r.full_path) || re.is_match(&r.file_name) {
                        return Some(idx);
                    }
                } else if let Some(stripped) = query_lower.strip_prefix('#') {
                    if let Ok(target_usn) = stripped.parse::<i64>() {
                        if r.usn == target_usn {
                            return Some(idx);
                        }
                    }
                } else if r.full_path.to_ascii_lowercase().contains(&query_lower)
                    || r.file_name.to_ascii_lowercase().contains(&query_lower)
                {
                    return Some(idx);
                }

                None
            })
            .collect();
    }

    fn drain_worker_events(&mut self) {
        let mut new_records_received = false;

        while let Ok(event) = self.worker.event_receiver.try_recv() {
            match event {
                WorkerEvent::Status(msg) => {
                    self.status_message = msg;
                }
                WorkerEvent::Progress { percent, message } => {
                    self.current_progress = Some(percent);
                    self.status_message = message;
                }
                WorkerEvent::BatchRecords(batch) => {
                    self.records.extend(batch);
                    new_records_received = true;
                }
                WorkerEvent::ScanFinished { stats } => {
                    self.scan_stats = stats;
                    self.current_progress = None;
                    self.status_message = format!("Scan complete. Loaded {} entries.", self.records.len());
                    new_records_received = true;
                }
                WorkerEvent::BypassReport(report) => {
                    self.antiforensics_report = report;
                }
                WorkerEvent::Error(err) => {
                    self.status_message = format!("Error: {}", err);
                    self.current_progress = None;
                }
            }
        }

        if new_records_received {
            self.recompute_filter();
        }
    }
}

impl eframe::App for App {
    fn update(&mut self, ctx: &Context, _frame: &mut eframe::Frame) {
        self.drain_worker_events();
        apply_theme(ctx, self.dark_mode);

        let mut dismiss_privilege_error = false;
        if let Some(err) = &self.privilege_error {
            egui::Window::new("Administrator Privileges Required")
                .collapsible(false)
                .resizable(false)
                .anchor(egui::Align2::CENTER_CENTER, [0.0, 0.0])
                .show(ctx, |ui| {
                    ui.label(egui::RichText::new("[!] Elevation Error").color(egui::Color32::from_rgb(239, 68, 68)).strong().size(16.0));
                    ui.add_space(8.0);
                    ui.label(err);
                    ui.add_space(8.0);
                    ui.label("458 JT requires direct raw volume sector access (SeBackupPrivilege) to parse the NTFS USN Journal and MFT.");
                    ui.add_space(8.0);
                    if ui.button("Dismiss").clicked() {
                        dismiss_privilege_error = true;
                    }
                });
        }
        if dismiss_privilege_error {
            self.privilege_error = None;
        }

        let is_scanning = self.worker.is_scanning.load(Ordering::SeqCst);

        TopBottomPanel::top("top_control_bar").show(ctx, |ui| {
            let action = render_top_bar(
                ui,
                &mut self.search_query,
                &mut self.current_source,
                &self.antiforensics_report.overall_risk,
                self.dark_mode,
                is_scanning,
            );

            match action {
                TopBarAction::SearchChanged => {
                    self.recompute_filter();
                }
                TopBarAction::SourceChanged(source) => {
                    self.current_source = source;
                    self.records.clear();
                    self.filtered_indices.clear();
                    match source {
                        JournalSource::ActiveJournal => {
                            self.worker.start_scan(self.target_drive);
                        }
                        JournalSource::ShadowCopies => {
                            self.status_message = "VSS shadow snapshot parser active.".to_string();
                            self.worker.start_scan(self.target_drive);
                        }
                        JournalSource::CarvedSlack => {
                            self.worker.start_carve(self.target_drive);
                        }
                    }
                }
                TopBarAction::OpenBypassModal => {
                    self.bypass_modal_open = true;
                }
                TopBarAction::ToggleTheme => {
                    self.dark_mode = !self.dark_mode;
                }
                TopBarAction::Refresh => {
                    self.records.clear();
                    self.filtered_indices.clear();
                    self.worker.start_scan(self.target_drive);
                }
                TopBarAction::ExportCsv => {
                    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
                    let filename = format!("458_jt_export_{}.csv", ts);
                    match export_records_to_csv(&filename, &self.records, &self.filtered_indices) {
                        Ok(cnt) => {
                            self.status_message = format!("Exported {} records to {}", cnt, filename);
                        }
                        Err(e) => {
                            self.status_message = format!("Export failed: {}", e);
                        }
                    }
                }
                TopBarAction::ExportJson => {
                    let ts = chrono::Local::now().format("%Y%m%d_%H%M%S");
                    let filename = format!("458_jt_report_{}.json", ts);
                    match export_state_to_json(
                        &filename,
                        &self.records,
                        &self.filtered_indices,
                        &self.antiforensics_report,
                        &self.scan_stats,
                    ) {
                        Ok(cnt) => {
                            self.status_message = format!("Exported report with {} records to {}", cnt, filename);
                        }
                        Err(e) => {
                            self.status_message = format!("Export failed: {}", e);
                        }
                    }
                }
                TopBarAction::None => {}
            }
        });

        TopBottomPanel::bottom("bottom_status_bar").show(ctx, |ui| {
            render_status_bar(
                ui,
                &self.scan_stats,
                &self.status_message,
                self.current_progress,
            );
        });

        SidePanel::right("right_filter_sidebar")
            .resizable(true)
            .default_width(260.0)
            .show(ctx, |ui| {
                if render_filter_sidebar(ui, &mut self.filter_state) {
                    self.recompute_filter();
                }
            });

        CentralPanel::default().show(ctx, |ui| {
            let prev_selected = self.selected_record_id;
            render_table_view(
                ui,
                &self.filtered_indices,
                &self.records,
                &mut self.selected_record_id,
            );
            if self.selected_record_id.is_some() && self.selected_record_id != prev_selected {
                self.detail_modal_open = true;
            }
        });

        let bypass_action = render_bypass_modal(
            ctx,
            &mut self.bypass_modal_open,
            &self.antiforensics_report,
        );

        if let BypassModalAction::JumpToUsn(target_usn) = bypass_action {
            self.search_query = format!("#{}", target_usn);
            self.recompute_filter();
            self.bypass_modal_open = false;
        }

        if let Some(rec_id) = self.selected_record_id {
            if let Some(record) = self.records.iter().find(|r| r.id == rec_id) {
                render_detail_view(ctx, record, &mut self.detail_modal_open);
            }
        }

        if is_scanning {
            ctx.request_repaint();
        }
    }
}

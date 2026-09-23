use egui::{Color32, RichText, TextEdit, Ui};

use crate::antiforensics::OverallRisk;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum JournalSource {
    ActiveJournal,
    ShadowCopies,
    CarvedSlack,
}

impl JournalSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            JournalSource::ActiveJournal => "Active $UsnJrnl:$J",
            JournalSource::ShadowCopies => "Volume Shadow Copies",
            JournalSource::CarvedSlack => "Unallocated Carved Slack",
        }
    }
}

pub enum TopBarAction {
    None,
    SearchChanged,
    SourceChanged(JournalSource),
    OpenBypassModal,
    ToggleTheme,
    Refresh,
    ExportCsv,
    ExportJson,
}

pub fn render_top_bar(
    ui: &mut Ui,
    search_query: &mut String,
    current_source: &mut JournalSource,
    overall_risk: &OverallRisk,
    dark_mode: bool,
    is_scanning: bool,
) -> TopBarAction {
    let mut action = TopBarAction::None;

    ui.horizontal(|ui| {
        ui.heading("458 JT");
        ui.separator();

        let search_response = ui.add(
            TextEdit::singleline(search_query)
                .hint_text("Search file paths... (e.g. Temp\\loader.exe, r/\\.dll$/)")
                .desired_width(ui.available_width() - 560.0),
        );
        if search_response.changed() {
            action = TopBarAction::SearchChanged;
        }

        ui.separator();

        egui::ComboBox::from_id_source("journal_source_select")
            .selected_text(current_source.as_str())
            .show_ui(ui, |ui| {
                if ui
                    .selectable_value(current_source, JournalSource::ActiveJournal, "Active $UsnJrnl:$J")
                    .clicked()
                {
                    action = TopBarAction::SourceChanged(JournalSource::ActiveJournal);
                }
                if ui
                    .selectable_value(
                        current_source,
                        JournalSource::ShadowCopies,
                        "Volume Shadow Copies",
                    )
                    .clicked()
                {
                    action = TopBarAction::SourceChanged(JournalSource::ShadowCopies);
                }
                if ui
                    .selectable_value(
                        current_source,
                        JournalSource::CarvedSlack,
                        "Unallocated Carved Slack",
                    )
                    .clicked()
                {
                    action = TopBarAction::SourceChanged(JournalSource::CarvedSlack);
                }
            });

        ui.separator();

        let (badge_color, badge_text) = match overall_risk {
            OverallRisk::Clean => (Color32::from_rgb(16, 185, 129), "USN Bypass Checks [CLEAN]"),
            OverallRisk::Suspicious => (
                Color32::from_rgb(245, 158, 11),
                "USN Bypass Checks [SUSPICIOUS]",
            ),
            OverallRisk::CriticalTampering => (
                Color32::from_rgb(239, 68, 68),
                "USN Bypass Checks [CRITICAL]",
            ),
        };

        if ui
            .button(RichText::new(badge_text).color(badge_color).strong())
            .clicked()
        {
            action = TopBarAction::OpenBypassModal;
        }

        ui.separator();

        let theme_label = if dark_mode { "Light Mode" } else { "Dark Mode" };
        if ui.button(theme_label).clicked() {
            action = TopBarAction::ToggleTheme;
        }

        if is_scanning {
            ui.add(egui::Spinner::new());
        } else if ui.button("Refresh").clicked() {
            action = TopBarAction::Refresh;
        }

        ui.separator();

        egui::ComboBox::from_id_source("export_select")
            .selected_text("Export")
            .show_ui(ui, |ui| {
                if ui.button("Export CSV").clicked() {
                    action = TopBarAction::ExportCsv;
                }
                if ui.button("Export JSON").clicked() {
                    action = TopBarAction::ExportJson;
                }
            });
    });

    action
}

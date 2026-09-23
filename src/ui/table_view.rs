use egui::{Color32, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

use crate::core::usn_record::UsnRecord;

pub fn render_table_view(
    ui: &mut Ui,
    filtered_indices: &[usize],
    records: &[UsnRecord],
    selected_record_id: &mut Option<usize>,
) {
    let row_height = 20.0;
    let total_rows = filtered_indices.len();

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .cell_layout(egui::Layout::left_to_right(egui::Align::Center))
        .column(Column::exact(165.0))
        .column(Column::remainder().clip(true))
        .column(Column::initial(280.0).at_least(200.0))
        .header(22.0, |mut header| {
            header.col(|ui| {
                ui.strong("Timestamp (local)");
            });
            header.col(|ui| {
                ui.strong("Path");
            });
            header.col(|ui| {
                ui.strong("Reason");
            });
        })
        .body(|body| {
            body.rows(row_height, total_rows, |mut row| {
                let idx = row.index();
                if idx >= filtered_indices.len() {
                    return;
                }
                let rec_idx = filtered_indices[idx];
                if rec_idx >= records.len() {
                    return;
                }
                let rec = &records[rec_idx];

                let is_selected = *selected_record_id == Some(rec.id);
                row.set_selected(is_selected);

                row.col(|ui| {
                    let mut text = RichText::new(&rec.timestamp_formatted);
                    if rec.is_ghost {
                        text = text.color(Color32::from_rgb(245, 158, 11));
                    }
                    if ui.add(egui::Label::new(text).sense(Sense::click())).clicked() {
                        *selected_record_id = Some(rec.id);
                    }
                });

                row.col(|ui| {
                    ui.horizontal(|ui| {
                        if rec.is_ghost {
                            ui.label(
                                RichText::new("[GHOST]")
                                    .color(Color32::from_rgb(245, 158, 11))
                                    .strong(),
                            );
                        }
                        if ui.add(egui::Label::new(&rec.full_path).sense(Sense::click())).clicked() {
                            *selected_record_id = Some(rec.id);
                        }
                    });
                });

                row.col(|ui| {
                    if ui.add(egui::Label::new(&rec.reason_str).sense(Sense::click())).clicked() {
                        *selected_record_id = Some(rec.id);
                    }
                });
            });
        });
}

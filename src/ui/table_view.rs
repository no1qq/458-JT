use egui::{Color32, RichText, Sense, Ui};
use egui_extras::{Column, TableBuilder};

use crate::core::usn_record::UsnRecord;

pub fn render_table_view(
    ui: &mut Ui,
    filtered_indices: &[usize],
    records: &[UsnRecord],
    selected_record_id: &mut Option<usize>,
    detail_modal_open: &mut bool,
) {
    ui.style_mut().interaction.selectable_labels = false;

    let wheel_delta = ui.input(|i| i.smooth_scroll_delta.y);
    if wheel_delta != 0.0 && ui.rect_contains_pointer(ui.max_rect()) {
        ui.ctx().input_mut(|i| {
            i.smooth_scroll_delta.y *= 6.0;
        });
    }

    let row_height = 20.0;
    let total_rows = filtered_indices.len();
    let available_height = ui.available_height();

    TableBuilder::new(ui)
        .striped(true)
        .resizable(true)
        .sense(Sense::click())
        .auto_shrink([false, false])
        .min_scrolled_height(available_height)
        .max_scroll_height(f32::INFINITY)
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

                let mut row_clicked = false;

                row.col(|ui| {
                    let mut text = RichText::new(&rec.timestamp_formatted);
                    if rec.is_ghost {
                        text = text.color(Color32::from_rgb(245, 158, 11));
                    }
                    let resp = ui.add(
                        egui::Label::new(text)
                            .selectable(false)
                            .sense(Sense::click()),
                    );
                    if resp.clicked() {
                        row_clicked = true;
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
                        let resp = ui.add(
                            egui::Label::new(&rec.full_path)
                                .selectable(false)
                                .sense(Sense::click())
                                .truncate(),
                        );
                        if resp.clicked() {
                            row_clicked = true;
                        }
                    });
                });

                row.col(|ui| {
                    let resp = ui.add(
                        egui::Label::new(&rec.reason_str)
                            .selectable(false)
                            .sense(Sense::click())
                            .truncate(),
                    );
                    if resp.clicked() {
                        row_clicked = true;
                    }
                });

                if row_clicked || row.response().clicked() {
                    *selected_record_id = Some(rec.id);
                    *detail_modal_open = true;
                }
            });
        });
}

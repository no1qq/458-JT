use egui::{Context, Grid, ScrollArea, Window};

use crate::core::usn_record::UsnRecord;

pub fn render_detail_view(
    ctx: &Context,
    record: &UsnRecord,
    is_open: &mut bool,
) {
    if !*is_open {
        return;
    }

    Window::new(format!("Record Inspector: {}", record.file_name))
        .open(is_open)
        .resizable(true)
        .default_size([580.0, 420.0])
        .show(ctx, |ui| {
            ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                Grid::new("record_detail_grid")
                    .num_columns(2)
                    .spacing([20.0, 6.0])
                    .striped(true)
                    .show(ui, |ui| {
                        ui.strong("USN Offset:");
                        ui.label(format!("0x{:016X} ({})", record.usn, record.usn));
                        ui.end_row();

                        ui.strong("Timestamp (local):");
                        ui.label(&record.timestamp_formatted);
                        ui.end_row();

                        ui.strong("Timestamp (FILETIME):");
                        ui.label(format!("0x{:016X} ({})", record.timestamp_raw, record.timestamp_raw));
                        ui.end_row();

                        ui.strong("File Name:");
                        ui.label(&record.file_name);
                        ui.end_row();

                        ui.strong("Reconstructed Path:");
                        ui.label(&record.full_path);
                        ui.end_row();

                        ui.strong("Reason Flags:");
                        ui.label(format!("0x{:08X} ({})", record.reason, record.reason_str));
                        ui.end_row();

                        ui.strong("File Reference:");
                        ui.label(format!("Index: {}, Seq: {}", record.file_ref_number, record.file_ref_seq));
                        ui.end_row();

                        ui.strong("Parent Reference:");
                        ui.label(format!("Index: {}, Seq: {}", record.parent_file_ref_number, record.parent_file_ref_seq));
                        ui.end_row();

                        ui.strong("File Attributes:");
                        ui.label(format!("0x{:08X}", record.file_attributes));
                        ui.end_row();

                        ui.strong("Security ID:");
                        ui.label(format!("0x{:08X}", record.security_id));
                        ui.end_row();

                        ui.strong("Source Info:");
                        ui.label(format!("0x{:08X}", record.source_info));
                        ui.end_row();

                        ui.strong("Record Version:");
                        ui.label(format!("V{}.{}", record.major_version, record.minor_version));
                        ui.end_row();

                        ui.strong("Carved / Ghost Record:");
                        ui.label(if record.is_ghost { "Yes (Orphan Cluster)" } else { "No (Active Journal)" });
                        ui.end_row();
                    });
            });
        });
}

use egui::{Color32, Context, RichText, ScrollArea, Window};

use crate::antiforensics::journal_tamper::TamperSeverity;
use crate::antiforensics::{AntiForensicsReport, OverallRisk};

pub enum BypassModalAction {
    None,
    JumpToUsn(i64),
}

pub fn render_bypass_modal(
    ctx: &Context,
    is_open: &mut bool,
    report: &AntiForensicsReport,
) -> BypassModalAction {
    let mut action = BypassModalAction::None;

    if !*is_open {
        return action;
    }

    Window::new("Anti-Forensics & USN Bypass Audit")
        .open(is_open)
        .resizable(true)
        .default_size([720.0, 520.0])
        .show(ctx, |ui| {
            ui.horizontal(|ui| {
                ui.label(RichText::new("Overall Risk Assessment:").strong());

                let (risk_color, risk_text) = match report.overall_risk {
                    OverallRisk::Clean => (Color32::from_rgb(16, 185, 129), "[CLEAN]"),
                    OverallRisk::Suspicious => {
                        (Color32::from_rgb(245, 158, 11), "[SUSPICIOUS]")
                    }
                    OverallRisk::CriticalTampering => (
                        Color32::from_rgb(239, 68, 68),
                        "[CRITICAL TAMPERING DETECTED]",
                    ),
                };

                ui.label(RichText::new(risk_text).color(risk_color).strong().size(16.0));
            });

            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.label(format!("Critical Findings: {}", report.critical_count));
                ui.separator();
                ui.label(format!("Suspicious Findings: {}", report.suspicious_count));
            });

            ui.separator();
            ui.add_space(4.0);

            ui.heading("Tamper Checklist");
            ui.add_space(4.0);

            let checks = [
                ("Journal Deletion / Recreation", "Audits USN cursor resets, tiny journal allocations, and deletion artifacts."),
                ("USN Gap & Discontinuity Analysis", "Scans for non-contiguous USN jumps and zero-stomped sectors."),
                ("Timestomping Analysis", "Verifies nanosecond zeroing and $STANDARD_INFORMATION vs $FILE_NAME deltas."),
                ("Rapid Deletion Bursts", "Detects automated trace scrubbing (>5 deletes within 3 seconds)."),
                ("Prefetch Wiping", "Audits deleted prefetch files for game executables and forensic tools."),
            ];

            for (title, desc) in checks {
                let matching = report.findings.iter().find(|f| f.title.contains(title) || title.contains(&f.title));
                ui.horizontal(|ui| {
                    if let Some(finding) = matching {
                        let icon = match finding.severity {
                            TamperSeverity::Critical => RichText::new("[!]").color(Color32::from_rgb(239, 68, 68)).strong(),
                            TamperSeverity::Suspicious => RichText::new("[?]").color(Color32::from_rgb(245, 158, 11)).strong(),
                            TamperSeverity::Clean => RichText::new("[v]").color(Color32::from_rgb(16, 185, 129)).strong(),
                        };
                        ui.label(icon);
                        ui.label(RichText::new(title).strong());
                    } else {
                        ui.label(RichText::new("[v]").color(Color32::from_rgb(16, 185, 129)).strong());
                        ui.label(RichText::new(title).strong());
                    }
                    ui.label(RichText::new(desc).color(Color32::from_rgb(148, 163, 184)));
                });
            }

            ui.separator();
            ui.add_space(4.0);

            ui.heading("Findings & Evidence List");
            ui.add_space(4.0);

            ScrollArea::vertical().auto_shrink([false; 2]).show(ui, |ui| {
                if report.findings.is_empty() {
                    ui.label(RichText::new("No suspicious anti-forensic indicators or bypasses identified.").color(Color32::from_rgb(16, 185, 129)));
                } else {
                    for finding in &report.findings {
                        let (sev_color, sev_tag) = match finding.severity {
                            TamperSeverity::Critical => (Color32::from_rgb(239, 68, 68), "[CRITICAL]"),
                            TamperSeverity::Suspicious => (Color32::from_rgb(245, 158, 11), "[SUSPICIOUS]"),
                            TamperSeverity::Clean => (Color32::from_rgb(16, 185, 129), "[INFO]"),
                        };

                        ui.group(|ui| {
                            ui.horizontal(|ui| {
                                ui.label(RichText::new(sev_tag).color(sev_color).strong());
                                ui.label(RichText::new(&finding.title).strong());
                            });
                            ui.label(&finding.description);

                            if !finding.evidence.is_empty() {
                                ui.add_space(2.0);
                                ui.horizontal_wrapped(|ui| {
                                    ui.label("Linked USNs:");
                                    for usn in finding.evidence.iter().take(8) {
                                        if ui.button(format!("#{}", usn)).clicked() {
                                            action = BypassModalAction::JumpToUsn(*usn);
                                        }
                                    }
                                    if finding.evidence.len() > 8 {
                                        ui.label(format!("+{} more", finding.evidence.len() - 8));
                                    }
                                });
                            }
                        });
                        ui.add_space(4.0);
                    }
                }
            });
        });

    action
}

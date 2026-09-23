use std::fs::File;
use std::io::BufWriter;
use std::path::Path;

use serde::Serialize;

use crate::antiforensics::AntiForensicsReport;
use crate::core::usn_record::UsnRecord;
use crate::core::worker::ScanStats;

#[derive(Serialize)]
pub struct FullForensicExport<'a> {
    pub exported_at: String,
    pub total_records_exported: usize,
    pub risk_assessment: String,
    pub critical_count: usize,
    pub suspicious_count: usize,
    pub stats: &'a ScanStats,
    pub records: Vec<&'a UsnRecord>,
}

pub fn export_state_to_json<P: AsRef<Path>>(
    path: P,
    records: &[UsnRecord],
    indices: &[usize],
    report: &AntiForensicsReport,
    stats: &ScanStats,
) -> Result<usize, std::io::Error> {
    let mut selected_records = Vec::with_capacity(indices.len());
    for &idx in indices {
        if idx < records.len() {
            selected_records.push(&records[idx]);
        }
    }

    let export = FullForensicExport {
        exported_at: chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string(),
        total_records_exported: selected_records.len(),
        risk_assessment: report.overall_risk.as_str().to_string(),
        critical_count: report.critical_count,
        suspicious_count: report.suspicious_count,
        stats,
        records: selected_records,
    };

    let file = File::create(path)?;
    let writer = BufWriter::new(file);
    serde_json::to_writer_pretty(writer, &export)
        .map_err(|e| std::io::Error::other(e.to_string()))?;

    Ok(export.total_records_exported)
}

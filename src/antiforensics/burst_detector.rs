use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_FILE_DELETE};

pub fn detect_deletion_bursts(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut delete_events = Vec::new();

    let sensitive_folders = ["\\temp\\", "\\appdata\\", "\\desktop\\", "\\downloads\\", "\\prefetch\\"];

    for r in records {
        if (r.reason & USN_REASON_FILE_DELETE) != 0 && r.timestamp_raw > 0 {
            let lower_path = r.full_path.to_ascii_lowercase();
            let is_sensitive = sensitive_folders.iter().any(|f| lower_path.contains(f));
            if is_sensitive {
                delete_events.push((r.timestamp_raw, r.usn, r.full_path.clone()));
            }
        }
    }

    if delete_events.is_empty() {
        return findings;
    }

    delete_events.sort_by_key(|e| e.0);

    let window_ticks = 30_000_000i64;
    let mut burst_clusters: Vec<Vec<i64>> = Vec::new();
    let mut current_cluster: Vec<i64> = Vec::new();
    let mut window_start = 0i64;

    for (ts, usn, _) in &delete_events {
        if current_cluster.is_empty() {
            window_start = *ts;
            current_cluster.push(*usn);
        } else if *ts - window_start <= window_ticks {
            current_cluster.push(*usn);
        } else {
            if current_cluster.len() >= 5 {
                burst_clusters.push(current_cluster.clone());
            }
            current_cluster.clear();
            window_start = *ts;
            current_cluster.push(*usn);
        }
    }

    if current_cluster.len() >= 5 {
        burst_clusters.push(current_cluster);
    }

    if !burst_clusters.is_empty() {
        let total_burst_files: usize = burst_clusters.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = burst_clusters
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Rapid Mass File Deletion Bursts Detected".to_string(),
            description: format!(
                "Detected {} panic deletion bursts (totaling {} deleted files) within 3-second windows in sensitive user directories (Temp/AppData/Desktop). Indicates automated trace wiping.",
                burst_clusters.len(),
                total_burst_files
            ),
            evidence: sample_usns,
        });
    }

    findings
}

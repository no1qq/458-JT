use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_FILE_DELETE};

pub fn detect_deletion_bursts(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut delete_events = Vec::new();

    let sensitive_folders = [
        "\\temp\\",
        "\\appdata\\",
        "\\desktop\\",
        "\\downloads\\",
        "\\windows\\prefetch\\",
    ];

    let cache_paths = [
        "\\cache",
        "\\code cache",
        "\\gpucache",
        "\\service worker",
        "\\indexeddb",
        "\\crashpad",
        "\\shadercache",
        "\\thumbnails",
        "\\google\\chrome",
        "\\microsoft\\edge",
        "\\mozilla\\firefox",
        "\\bravebrowser",
        "\\discord\\",
        "\\spotify\\",
        "\\node_modules",
        "\\target\\",
        "\\cargo\\",
    ];

    let high_risk_exts = [
        ".exe", ".dll", ".sys", ".bat", ".ps1", ".cmd", ".vbs", ".jar", ".asi", ".pf",
    ];

    for r in records {
        if (r.reason & USN_REASON_FILE_DELETE) != 0 && r.timestamp_raw > 0 {
            let lower_path = r.full_path.to_ascii_lowercase();

            if cache_paths.iter().any(|c| lower_path.contains(c)) {
                continue;
            }

            let in_sensitive_folder = sensitive_folders.iter().any(|f| lower_path.contains(f));
            if !in_sensitive_folder {
                continue;
            }

            let is_high_risk_ext = high_risk_exts.iter().any(|ext| lower_path.ends_with(ext));
            delete_events.push((r.timestamp_raw, r.usn, is_high_risk_ext));
        }
    }

    if delete_events.is_empty() {
        return findings;
    }

    delete_events.sort_by_key(|e| e.0);

    let window_ticks = 30_000_000i64;
    let mut high_risk_bursts: Vec<Vec<i64>> = Vec::new();
    let mut general_bursts: Vec<Vec<i64>> = Vec::new();

    let mut current_cluster: Vec<(i64, bool)> = Vec::new();
    let mut window_start = 0i64;

    for (ts, usn, is_high_risk) in &delete_events {
        if current_cluster.is_empty() {
            window_start = *ts;
            current_cluster.push((*usn, *is_high_risk));
        } else if *ts - window_start <= window_ticks {
            current_cluster.push((*usn, *is_high_risk));
        } else {
            let high_risk_count = current_cluster.iter().filter(|(_, hr)| *hr).count();
            if high_risk_count >= 3 {
                high_risk_bursts.push(current_cluster.iter().map(|(u, _)| *u).collect());
            } else if current_cluster.len() >= 25 {
                general_bursts.push(current_cluster.iter().map(|(u, _)| *u).collect());
            }

            current_cluster.clear();
            window_start = *ts;
            current_cluster.push((*usn, *is_high_risk));
        }
    }

    if !current_cluster.is_empty() {
        let high_risk_count = current_cluster.iter().filter(|(_, hr)| *hr).count();
        if high_risk_count >= 3 {
            high_risk_bursts.push(current_cluster.iter().map(|(u, _)| *u).collect());
        } else if current_cluster.len() >= 25 {
            general_bursts.push(current_cluster.iter().map(|(u, _)| *u).collect());
        }
    }

    if !high_risk_bursts.is_empty() {
        let total_files: usize = high_risk_bursts.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = high_risk_bursts
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Rapid Executable or Prefetch Deletion Bursts".to_string(),
            description: format!(
                "Detected {} rapid deletion bursts targeting executables, scripts, or prefetch files (totaling {} files) within 3-second windows in sensitive locations.",
                high_risk_bursts.len(),
                total_files
            ),
            evidence: sample_usns,
        });
    }

    if !general_bursts.is_empty() {
        let total_files: usize = general_bursts.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = general_bursts
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Mass User File Deletion Bursts".to_string(),
            description: format!(
                "Detected {} mass deletion bursts (totaling {} non-cache files) within 3-second windows in user folders.",
                general_bursts.len(),
                total_files
            ),
            evidence: sample_usns,
        });
    }

    findings
}

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

    let executable_exts = [
        ".exe", ".sys", ".bat", ".ps1", ".cmd", ".vbs", ".jar", ".asi",
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

            let is_exec = executable_exts.iter().any(|ext| lower_path.ends_with(ext));
            let is_root_dll = lower_path.ends_with(".dll")
                && (lower_path.starts_with("c:\\users\\") && lower_path.matches('\\').count() <= 5);

            if is_exec || is_root_dll {
                delete_events.push((r.timestamp_raw, r.usn));
            }
        }
    }

    if delete_events.is_empty() {
        return findings;
    }

    delete_events.sort_by_key(|e| e.0);

    let window_ticks = 30_000_000i64;
    let mut panic_bursts: Vec<Vec<i64>> = Vec::new();
    let mut current_cluster: Vec<i64> = Vec::new();
    let mut window_start = 0i64;

    for (ts, usn) in &delete_events {
        if current_cluster.is_empty() {
            window_start = *ts;
            current_cluster.push(*usn);
        } else if *ts - window_start <= window_ticks {
            current_cluster.push(*usn);
        } else {
            if current_cluster.len() >= 3 {
                panic_bursts.push(current_cluster.clone());
            }

            current_cluster.clear();
            window_start = *ts;
            current_cluster.push(*usn);
        }
    }

    if current_cluster.len() >= 3 {
        panic_bursts.push(current_cluster);
    }

    if !panic_bursts.is_empty() {
        let total_files: usize = panic_bursts.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = panic_bursts
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Rapid Executable Deletion Bursts".to_string(),
            description: format!(
                "Detected {} rapid deletion bursts targeting executables, drivers, or scripts (totaling {} files) within 3-second windows in sensitive locations.",
                panic_bursts.len(),
                total_files
            ),
            evidence: sample_usns,
        });
    }

    findings
}

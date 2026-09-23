use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_BASIC_INFO_CHANGE};

pub fn audit_signature_changes(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut masking_usns = Vec::new();
    let mut rapid_basic_info_events = Vec::new();

    let user_paths = ["\\temp\\", "\\appdata\\", "\\desktop\\", "\\downloads\\"];
    let dev_paths = [
        "\\target\\",
        "\\cargo\\",
        "\\.cargo\\",
        "\\.rustup\\",
        "\\node_modules\\",
        "\\.git\\",
        "\\pip\\cache\\",
        "\\npm-cache\\",
        "\\nuget\\",
        "\\microsoft\\visualstudio\\",
    ];
    let exec_exts = [".exe", ".dll", ".sys", ".bat", ".ps1", ".jar", ".asi"];

    for r in records {
        let lower_path = r.full_path.to_ascii_lowercase();
        let in_user_path = user_paths.iter().any(|p| lower_path.contains(p));
        if !in_user_path {
            continue;
        }

        let in_dev_path = dev_paths.iter().any(|p| lower_path.contains(p));
        if in_dev_path {
            continue;
        }

        let is_exec = exec_exts.iter().any(|ext| r.file_name.to_ascii_lowercase().ends_with(ext));
        if !is_exec {
            continue;
        }

        if (r.file_attributes & 0x06) == 0x06 {
            masking_usns.push(r.usn);
        }

        if (r.reason & USN_REASON_BASIC_INFO_CHANGE) != 0 && (r.reason & 0x0000_0007) == 0 {
            rapid_basic_info_events.push((r.timestamp_raw, r.usn));
        }
    }

    if !masking_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Super-Hidden (System+Hidden) Executable Attribute Masking".to_string(),
            description: format!(
                "Discovered {} executable files with both Hidden and System attributes applied in user directories. High-confidence technique to evade manual inspection.",
                masking_usns.len()
            ),
            evidence: masking_usns.iter().take(20).copied().collect(),
        });
    }

    rapid_basic_info_events.sort_by_key(|e| e.0);
    let window_ticks = 30_000_000i64;
    let mut stomping_bursts: Vec<Vec<i64>> = Vec::new();
    let mut current_cluster: Vec<i64> = Vec::new();
    let mut window_start = 0i64;

    for (ts, usn) in &rapid_basic_info_events {
        if current_cluster.is_empty() {
            window_start = *ts;
            current_cluster.push(*usn);
        } else if *ts - window_start <= window_ticks {
            current_cluster.push(*usn);
        } else {
            if current_cluster.len() >= 8 {
                stomping_bursts.push(current_cluster.clone());
            }
            current_cluster.clear();
            window_start = *ts;
            current_cluster.push(*usn);
        }
    }

    if current_cluster.len() >= 8 {
        stomping_bursts.push(current_cluster);
    }

    if !stomping_bursts.is_empty() {
        let total_events: usize = stomping_bursts.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = stomping_bursts
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Rapid Automated Timestamp / Attribute Stomping Bursts".to_string(),
            description: format!(
                "Detected {} bursts of isolated Basic Info Changes on executables within 3-second windows (totaling {} events). Characteristic of batch timestomping scripts.",
                stomping_bursts.len(),
                total_events
            ),
            evidence: sample_usns,
        });
    }

    findings
}

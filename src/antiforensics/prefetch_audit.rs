use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_FILE_DELETE};

pub fn audit_prefetch_tampering(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut deleted_pf_events = Vec::new();
    let mut deleted_game_pf_usns = Vec::new();
    let mut deleted_cleaner_pf_usns = Vec::new();

    let competitive_game_prefixes = [
        "javaw.exe-",
        "minecraft.exe-",
        "cs2.exe-",
        "csgo.exe-",
        "valorant.exe-",
        "fortniteclient",
        "robloxplayer",
        "r5apex.exe-",
        "fivem.exe-",
        "fivem_",
    ];

    let cleaner_prefixes = [
        "bleachbit.exe-",
        "ccleaner.exe-",
        "privazer.exe-",
        "fsutil.exe-",
        "srumutil.exe-",
        "usndelete.exe-",
    ];

    for r in records {
        if (r.reason & USN_REASON_FILE_DELETE) != 0 && r.timestamp_raw > 0 {
            let lower_name = r.file_name.to_ascii_lowercase();
            if lower_name.ends_with(".pf") {
                let is_cleaner = cleaner_prefixes.iter().any(|c| lower_name.starts_with(c));
                if is_cleaner {
                    deleted_cleaner_pf_usns.push(r.usn);
                    continue;
                }

                let is_game = competitive_game_prefixes.iter().any(|g| lower_name.starts_with(g));
                if is_game {
                    deleted_game_pf_usns.push(r.usn);
                } else {
                    deleted_pf_events.push((r.timestamp_raw, r.usn));
                }
            }
        }
    }

    if !deleted_cleaner_pf_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Anti-Forensic Cleaner Prefetch Deletion Detected".to_string(),
            description: format!(
                "Discovered {} deleted prefetch (.pf) files matching anti-forensic cleaning tools.",
                deleted_cleaner_pf_usns.len()
            ),
            evidence: deleted_cleaner_pf_usns.iter().take(20).copied().collect(),
        });
    }

    if deleted_game_pf_usns.len() >= 20 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Competitive Game Prefetch Wiping Detected".to_string(),
            description: format!(
                "Discovered {} deleted prefetch (.pf) files matching competitive game binaries.",
                deleted_game_pf_usns.len()
            ),
            evidence: deleted_game_pf_usns.iter().take(20).copied().collect(),
        });
    } else if deleted_game_pf_usns.len() >= 5 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Selective Game Prefetch Deletion".to_string(),
            description: format!(
                "Identified {} deleted game prefetch (.pf) files.",
                deleted_game_pf_usns.len()
            ),
            evidence: deleted_game_pf_usns.iter().take(20).copied().collect(),
        });
    }

    deleted_pf_events.sort_by_key(|e| e.0);
    let window_ticks = 50_000_000i64;
    let mut prefetch_bursts: Vec<Vec<i64>> = Vec::new();
    let mut current_cluster: Vec<i64> = Vec::new();
    let mut window_start = 0i64;

    for (ts, usn) in &deleted_pf_events {
        if current_cluster.is_empty() {
            window_start = *ts;
            current_cluster.push(*usn);
        } else if *ts - window_start <= window_ticks {
            current_cluster.push(*usn);
        } else {
            if current_cluster.len() >= 50 {
                prefetch_bursts.push(current_cluster.clone());
            }
            current_cluster.clear();
            window_start = *ts;
            current_cluster.push(*usn);
        }
    }

    if current_cluster.len() >= 50 {
        prefetch_bursts.push(current_cluster);
    }

    if !prefetch_bursts.is_empty() {
        let total_files: usize = prefetch_bursts.iter().map(|c| c.len()).sum();
        let sample_usns: Vec<i64> = prefetch_bursts
            .iter()
            .flat_map(|c| c.iter().copied())
            .take(20)
            .collect();

        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Rapid Prefetch Deletion Burst".to_string(),
            description: format!(
                "Detected rapid deletion burst of {} prefetch files within 5-second windows (suggestive of disk cleanup or trace wiping).",
                total_files
            ),
            evidence: sample_usns,
        });
    }

    findings
}

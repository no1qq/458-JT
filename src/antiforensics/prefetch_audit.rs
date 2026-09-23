use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_FILE_DELETE};

pub fn audit_prefetch_tampering(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
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

    findings
}

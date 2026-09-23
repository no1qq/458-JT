use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_FILE_DELETE};

pub fn audit_prefetch_tampering(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut deleted_pf_usns = Vec::new();
    let mut deleted_game_pf_usns = Vec::new();

    let competitive_games = [
        "javaw", "minecraft", "cs2", "csgo", "valorant", "fortnite", "roblox", "r5apex", "fivem",
    ];

    let cleanup_tools = [
        "fsutil", "srumutil", "bleachbit", "ccleaner", "privazer", "wipe", "eraser", "usndelete",
    ];

    for r in records {
        if (r.reason & USN_REASON_FILE_DELETE) != 0 {
            let lower_name = r.file_name.to_ascii_lowercase();
            if lower_name.ends_with(".pf") {
                deleted_pf_usns.push(r.usn);

                let is_game = competitive_games.iter().any(|g| lower_name.contains(g));
                let is_cleaner = cleanup_tools.iter().any(|c| lower_name.contains(c));

                if is_game || is_cleaner {
                    deleted_game_pf_usns.push(r.usn);
                }
            }
        }
    }

    if !deleted_game_pf_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Competitive Game or Cleaner Prefetch Wiping Detected".to_string(),
            description: format!(
                "Discovered {} deleted prefetch (.pf) files matching competitive game binaries or anti-forensic cleaning tools.",
                deleted_game_pf_usns.len()
            ),
            evidence: deleted_game_pf_usns.iter().take(20).copied().collect(),
        });
    } else if deleted_pf_usns.len() >= 50 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Mass Prefetch File Deletion".to_string(),
            description: format!(
                "Identified {} general prefetch file deletions, suggesting execution history cleaning.",
                deleted_pf_usns.len()
            ),
            evidence: deleted_pf_usns.iter().take(20).copied().collect(),
        });
    }

    findings
}

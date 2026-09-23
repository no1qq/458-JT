use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_RENAME_NEW_NAME, USN_REASON_STREAM_CHANGE};

pub fn detect_evasion_techniques(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut ads_usns = Vec::new();
    let mut spoof_usns = Vec::new();

    let _exe_extensions = [".exe", ".dll", ".sys", ".jar"];
    let innocent_extensions = [".png", ".jpg", ".txt", ".tmp", ".dat", ".log", ".ico"];

    for r in records {
        if (r.reason & USN_REASON_STREAM_CHANGE) != 0 || r.file_name.contains(':') {
            ads_usns.push(r.usn);
        }

        if (r.reason & USN_REASON_RENAME_NEW_NAME) != 0 {
            let lower = r.file_name.to_ascii_lowercase();
            let has_innocent_ext = innocent_extensions.iter().any(|ext| lower.ends_with(ext));
            if has_innocent_ext && (lower.contains("loader") || lower.contains("inject") || lower.contains("cheat") || lower.contains("bypass")) {
                spoof_usns.push(r.usn);
            }
        }
    }

    if !ads_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "NTFS Alternate Data Stream (ADS) Activity".to_string(),
            description: format!(
                "Discovered {} events involving Alternate Data Streams (ADS) or Zone.Identifier stripping.",
                ads_usns.len()
            ),
            evidence: ads_usns.iter().take(20).copied().collect(),
        });
    }

    if !spoof_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Extension Spoofing Rename Pattern".to_string(),
            description: format!(
                "Identified {} files renamed to innocent document/image extensions matching suspicious binary naming signatures.",
                spoof_usns.len()
            ),
            evidence: spoof_usns.iter().take(20).copied().collect(),
        });
    }

    findings
}

use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{
    UsnRecord, USN_REASON_FILE_DELETE, USN_REASON_RENAME_NEW_NAME, USN_REASON_STREAM_CHANGE,
};

pub fn detect_evasion_techniques(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut ads_exec_usns = Vec::new();
    let mut zone_id_strip_usns = Vec::new();
    let mut spoof_usns = Vec::new();

    let exe_extensions = [".exe", ".dll", ".sys", ".jar", ".ps1", ".bat", ".vbs"];
    let innocent_extensions = [".png", ".jpg", ".txt", ".tmp", ".dat", ".log", ".ico"];

    for r in records {
        let lower = r.file_name.to_ascii_lowercase();

        if lower.contains(":zone.identifier") && (r.reason & USN_REASON_FILE_DELETE) != 0 {
            zone_id_strip_usns.push(r.usn);
        } else if lower.contains(':') {
            let is_exec_stream = exe_extensions.iter().any(|ext| lower.ends_with(ext));
            let is_whitelisted_stream = lower.contains(":zone.identifier")
                || lower.contains(":summaryinformation")
                || lower.contains(":documentcatalog")
                || lower.contains(":$data")
                || lower.contains(":favicon")
                || lower.contains(":syncstatus")
                || lower.contains(":wmpinfo");

            if is_exec_stream {
                ads_exec_usns.push(r.usn);
            } else if !is_whitelisted_stream && (r.reason & USN_REASON_STREAM_CHANGE) != 0 {
                ads_exec_usns.push(r.usn);
            }
        }

        if (r.reason & USN_REASON_RENAME_NEW_NAME) != 0 {
            let has_innocent_ext = innocent_extensions.iter().any(|ext| lower.ends_with(ext));
            if has_innocent_ext
                && (lower.contains("loader")
                    || lower.contains("inject")
                    || lower.contains("cheat")
                    || lower.contains("bypass"))
            {
                spoof_usns.push(r.usn);
            }
        }
    }

    if !ads_exec_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Executable Alternate Data Stream (ADS) Concealment".to_string(),
            description: format!(
                "Identified {} events involving executable payloads or hidden data streams inside NTFS Alternate Data Streams.",
                ads_exec_usns.len()
            ),
            evidence: ads_exec_usns.iter().take(20).copied().collect(),
        });
    }

    if !zone_id_strip_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Mark of the Web (Zone.Identifier) Stripping".to_string(),
            description: format!(
                "Discovered {} events where Zone.Identifier streams were deleted, indicating deliberate unblocking of downloaded files.",
                zone_id_strip_usns.len()
            ),
            evidence: zone_id_strip_usns.iter().take(20).copied().collect(),
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

use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::{UsnRecord, USN_REASON_BASIC_INFO_CHANGE};

pub fn audit_signature_changes(records: &[UsnRecord]) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut basic_info_usns = Vec::new();

    let user_paths = ["\\temp\\", "\\appdata\\", "\\desktop\\", "\\downloads\\"];

    for r in records {
        if (r.reason & USN_REASON_BASIC_INFO_CHANGE) != 0 && (r.reason & 0x0000_0007) == 0 {
            let lower_path = r.full_path.to_ascii_lowercase();
            if user_paths.iter().any(|p| lower_path.contains(p)) {
                let lower_name = r.file_name.to_ascii_lowercase();
                if lower_name.ends_with(".exe") || lower_name.ends_with(".dll") || lower_name.ends_with(".sys") {
                    basic_info_usns.push(r.usn);
                }
            }
        }
    }

    if basic_info_usns.len() >= 25 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Mass Basic Information Attribute Alterations".to_string(),
            description: format!(
                "Identified {} executable events with isolated Basic Info Change (no file data modifications) in user directories. Often correlates with mass timestamp stamping or attribute masking.",
                basic_info_usns.len()
            ),
            evidence: basic_info_usns.iter().take(20).copied().collect(),
        });
    }

    findings
}

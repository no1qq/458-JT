use std::collections::HashMap;

use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::mft::MftNode;
use crate::core::usn_record::UsnRecord;

pub fn analyze_timestomping(
    records: &[UsnRecord],
    mft_nodes: &HashMap<u64, MftNode>,
) -> Vec<TamperFinding> {
    let mut findings = Vec::new();
    let mut zero_nano_usns = Vec::new();
    let mut si_fn_delta_usns = Vec::new();

    let sensitive_exts = [".exe", ".dll", ".sys", ".bat", ".ps1", ".jar", ".vbs"];

    for r in records {
        let is_sensitive = sensitive_exts
            .iter()
            .any(|ext| r.file_name.to_ascii_lowercase().ends_with(ext));

        if is_sensitive && r.timestamp_raw > 0 && r.timestamp_raw % 10_000_000 == 0 {
            zero_nano_usns.push(r.usn);
        }

        if let Some(mft) = mft_nodes.get(&r.file_ref_number) {
            if mft.si_created > 0 && mft.fn_created > 0 {
                let delta = mft.fn_created - mft.si_created;
                if delta > 10_000_000 {
                    si_fn_delta_usns.push(r.usn);
                }
            }
        }
    }

    if !zero_nano_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Nanosecond Zeroing Timestomp Pattern".to_string(),
            description: format!(
                "Identified {} executable events with exactly zeroed fractional seconds (FILETIME % 10_000_000 == 0), characteristic of basic Win32 SetFileTime tampering.",
                zero_nano_usns.len()
            ),
            evidence: zero_nano_usns.iter().take(20).copied().collect(),
        });
    }

    if !si_fn_delta_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "$STANDARD_INFO vs $FILE_NAME Timestamp Divergence".to_string(),
            description: format!(
                "Detected {} files where $STANDARD_INFORMATION creation time is artificially earlier than $FILE_NAME creation time. Conclusive evidence of backdated timestomping.",
                si_fn_delta_usns.len()
            ),
            evidence: si_fn_delta_usns.iter().take(20).copied().collect(),
        });
    }

    findings
}

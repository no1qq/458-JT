use std::collections::{HashMap, HashSet};

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
    let mut checked_mft_entries = HashSet::new();

    let sensitive_exts = [".exe", ".dll", ".sys", ".bat", ".ps1", ".jar", ".vbs"];
    let ignored_paths = [
        "\\program files",
        "\\windows\\winsxs",
        "\\windows\\servicing",
        "\\windows\\system32",
        "\\windows\\microsoft.net",
    ];

    for r in records {
        let lower_path = r.full_path.to_ascii_lowercase();
        if ignored_paths.iter().any(|p| lower_path.contains(p)) {
            continue;
        }

        let is_sensitive = sensitive_exts
            .iter()
            .any(|ext| r.file_name.to_ascii_lowercase().ends_with(ext));

        if !is_sensitive {
            continue;
        }

        if let Some(mft) = mft_nodes.get(&r.file_ref_number) {
            if checked_mft_entries.insert(r.file_ref_number) {
                if mft.si_created > 0 && mft.si_created % 10_000_000 == 0 {
                    zero_nano_usns.push(r.usn);
                }

                if mft.si_created > 0 && mft.fn_created > 0 {
                    let delta = mft.fn_created - mft.si_created;
                    let is_zero_nano = mft.si_created % 10_000_000 == 0;
                    let is_user_path = lower_path.contains("\\temp\\")
                        || lower_path.contains("\\appdata\\")
                        || lower_path.contains("\\desktop\\")
                        || lower_path.contains("\\downloads\\");

                    if delta > 86400 * 10_000_000 && is_user_path && is_zero_nano {
                        si_fn_delta_usns.push(r.usn);
                    }
                }
            }
        }
    }

    if !zero_nano_usns.is_empty() {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "Nanosecond Zeroing Timestomp Pattern".to_string(),
            description: format!(
                "Identified {} executable files with exactly zeroed fractional seconds (FILETIME % 10_000_000 == 0) in $STANDARD_INFORMATION, characteristic of Win32 SetFileTime timestamp manipulation.",
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
                "Detected {} suspicious executable files in user folders with backdated $STANDARD_INFORMATION timestamps and zeroed subsecond precision.",
                si_fn_delta_usns.len()
            ),
            evidence: si_fn_delta_usns.iter().take(20).copied().collect(),
        });
    }

    findings
}

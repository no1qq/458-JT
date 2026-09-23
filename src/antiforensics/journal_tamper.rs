use crate::core::usn_io::UsnJournalData;

#[derive(Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub enum TamperSeverity {
    Clean,
    Suspicious,
    Critical,
}

#[derive(Clone, Debug)]
pub struct TamperFinding {
    pub severity: TamperSeverity,
    pub title: String,
    pub description: String,
    pub evidence: Vec<i64>,
}

pub fn check_journal_tampering(journal: &UsnJournalData, record_count: usize) -> Vec<TamperFinding> {
    let mut findings = Vec::new();

    if journal.maximum_size > 0 && journal.maximum_size < 2 * 1024 * 1024 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "Abnormally Small USN Journal Allocation".to_string(),
            description: format!(
                "USN Journal maximum size is set to {} bytes (< 2MB). This is a known technique to force rapid journal truncation and destroy execution history.",
                journal.maximum_size
            ),
            evidence: vec![],
        });
    }

    if journal.lowest_valid_usn == 0 && journal.next_usn > 0 && record_count < 1000 {
        findings.push(TamperFinding {
            severity: TamperSeverity::Suspicious,
            title: "USN Journal Freshly Recreated or Purged".to_string(),
            description: format!(
                "LowestValidUsn is 0 with only {} entries. The journal may have been recently cleared via 'fsutil usn deletejournal'.",
                record_count
            ),
            evidence: vec![],
        });
    }

    if journal.next_usn < journal.first_usn {
        findings.push(TamperFinding {
            severity: TamperSeverity::Critical,
            title: "USN Cursor Inversion Anomaly".to_string(),
            description: format!(
                "NextUsn ({}) is lower than FirstUsn ({}). Indicates direct sector tampering or journal stream corruption.",
                journal.next_usn, journal.first_usn
            ),
            evidence: vec![],
        });
    }

    findings
}

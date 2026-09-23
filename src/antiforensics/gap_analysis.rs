use crate::antiforensics::journal_tamper::{TamperFinding, TamperSeverity};
use crate::core::usn_record::UsnRecord;

#[allow(dead_code)]
pub struct GapReport {
    pub total_gaps: usize,
    pub max_gap_bytes: i64,
    pub findings: Vec<TamperFinding>,
    pub gap_usns: Vec<i64>,
}

pub fn analyze_usn_gaps(records: &[UsnRecord]) -> GapReport {
    let mut findings = Vec::new();
    let mut gap_usns = Vec::new();
    let mut total_gaps = 0usize;
    let mut max_gap_bytes = 0i64;

    if records.len() < 2 {
        return GapReport {
            total_gaps: 0,
            max_gap_bytes: 0,
            findings,
            gap_usns,
        };
    }

    for i in 0..records.len() - 1 {
        let current = &records[i];
        let next = &records[i + 1];

        let aligned_length = ((current.record_length as i64 + 7) / 8) * 8;
        let expected_next_usn = current.usn + aligned_length;

        if next.usn > expected_next_usn {
            let gap_size = next.usn - expected_next_usn;
            total_gaps += 1;
            if gap_size > max_gap_bytes {
                max_gap_bytes = gap_size;
            }

            if gap_size > 64 * 1024 {
                gap_usns.push(current.usn);
            }
        }
    }

    if !gap_usns.is_empty() {
        let severity = if max_gap_bytes > 10 * 1024 * 1024 {
            TamperSeverity::Critical
        } else {
            TamperSeverity::Suspicious
        };

        findings.push(TamperFinding {
            severity,
            title: "USN Sequence Discontinuity Gaps Detected".to_string(),
            description: format!(
                "Discovered {} non-contiguous USN sequence jumps with max gap size of {} bytes. Indicates selective record zeroing or journal truncation.",
                total_gaps, max_gap_bytes
            ),
            evidence: gap_usns.iter().take(20).copied().collect(),
        });
    }

    GapReport {
        total_gaps,
        max_gap_bytes,
        findings,
        gap_usns,
    }
}

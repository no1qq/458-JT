pub mod burst_detector;
pub mod evasion;
pub mod gap_analysis;
pub mod journal_tamper;
pub mod prefetch_audit;
pub mod signature_audit;
pub mod timestomp;

use std::collections::{HashMap, HashSet};

use crate::antiforensics::burst_detector::detect_deletion_bursts;
use crate::antiforensics::evasion::detect_evasion_techniques;
use crate::antiforensics::gap_analysis::analyze_usn_gaps;
use crate::antiforensics::journal_tamper::{check_journal_tampering, TamperFinding, TamperSeverity};
use crate::antiforensics::prefetch_audit::audit_prefetch_tampering;
use crate::antiforensics::signature_audit::audit_signature_changes;
use crate::antiforensics::timestomp::analyze_timestomping;
use crate::core::mft::MftNode;
use crate::core::usn_io::UsnJournalData;
use crate::core::usn_record::UsnRecord;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub enum OverallRisk {
    #[default]
    Clean,
    Suspicious,
    CriticalTampering,
}

impl OverallRisk {
    pub fn as_str(&self) -> &'static str {
        match self {
            OverallRisk::Clean => "[CLEAN]",
            OverallRisk::Suspicious => "[SUSPICIOUS]",
            OverallRisk::CriticalTampering => "[CRITICAL TAMPERING DETECTED]",
        }
    }
}

#[derive(Clone, Debug, Default)]
#[allow(dead_code)]
pub struct AntiForensicsReport {
    pub overall_risk: OverallRisk,
    pub critical_count: usize,
    pub suspicious_count: usize,
    pub findings: Vec<TamperFinding>,
    pub evidence_usns: HashSet<i64>,
}

pub fn run_antiforensics_audit(
    journal: &UsnJournalData,
    records: &[UsnRecord],
    mft_nodes: &HashMap<u64, MftNode>,
) -> AntiForensicsReport {
    let mut all_findings = Vec::new();

    all_findings.extend(check_journal_tampering(journal, records.len()));

    let gap_report = analyze_usn_gaps(records);
    all_findings.extend(gap_report.findings);

    all_findings.extend(analyze_timestomping(records, mft_nodes));
    all_findings.extend(detect_deletion_bursts(records));
    all_findings.extend(audit_prefetch_tampering(records));
    all_findings.extend(detect_evasion_techniques(records));
    all_findings.extend(audit_signature_changes(records));

    let mut critical_count = 0;
    let mut suspicious_count = 0;
    let mut evidence_usns = HashSet::new();

    for f in &all_findings {
        match f.severity {
            TamperSeverity::Critical => critical_count += 1,
            TamperSeverity::Suspicious => suspicious_count += 1,
            TamperSeverity::Clean => {}
        }
        for usn in &f.evidence {
            evidence_usns.insert(*usn);
        }
    }

    let overall_risk = if critical_count > 0 {
        OverallRisk::CriticalTampering
    } else if suspicious_count > 0 {
        OverallRisk::Suspicious
    } else {
        OverallRisk::Clean
    };

    AntiForensicsReport {
        overall_risk,
        critical_count,
        suspicious_count,
        findings: all_findings,
        evidence_usns,
    }
}

use std::collections::HashSet;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;

use crossbeam_channel::{unbounded, Receiver, Sender};

use crate::antiforensics::{run_antiforensics_audit, AntiForensicsReport};
use crate::core::mft::stream_mft_nodes;
use crate::core::rewind::RewindResolver;
use crate::core::unallocated::scan_volume_clusters_for_slack;
use crate::core::usn_io::{query_usn_journal, read_usn_chunk};
use crate::core::usn_record::{filetime_to_formatted_local, parse_usn_record, UsnRecord};
use crate::core::volume::open_volume;

#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct ScanStats {
    pub oldest_timestamp_raw: i64,
    pub oldest_timestamp_formatted: String,
    pub total_entries: usize,
    pub file_count: usize,
    pub dir_count: usize,
}

#[allow(dead_code)]
pub enum WorkerCommand {
    StartScan { drive_letter: char },
    StartCarve { drive_letter: char },
    Cancel,
}

pub enum WorkerEvent {
    Status(String),
    Progress { percent: f32, message: String },
    BatchRecords(Vec<UsnRecord>),
    ScanFinished { stats: ScanStats },
    BypassReport(AntiForensicsReport),
    Error(String),
}

pub struct WorkerHandle {
    pub cmd_sender: Sender<WorkerCommand>,
    pub event_receiver: Receiver<WorkerEvent>,
    pub is_scanning: Arc<AtomicBool>,
}

impl WorkerHandle {
    pub fn new() -> Self {
        let (cmd_tx, cmd_rx) = unbounded::<WorkerCommand>();
        let (event_tx, event_rx) = unbounded::<WorkerEvent>();
        let is_scanning = Arc::new(AtomicBool::new(false));

        let scanning_flag = is_scanning.clone();
        thread::spawn(move || {
            worker_loop(cmd_rx, event_tx, scanning_flag);
        });

        Self {
            cmd_sender: cmd_tx,
            event_receiver: event_rx,
            is_scanning,
        }
    }

    pub fn start_scan(&self, drive_letter: char) {
        let _ = self.cmd_sender.send(WorkerCommand::StartScan { drive_letter });
    }

    pub fn start_carve(&self, drive_letter: char) {
        let _ = self.cmd_sender.send(WorkerCommand::StartCarve { drive_letter });
    }

    #[allow(dead_code)]
    pub fn cancel(&self) {
        let _ = self.cmd_sender.send(WorkerCommand::Cancel);
    }
}

fn worker_loop(
    cmd_rx: Receiver<WorkerCommand>,
    event_tx: Sender<WorkerEvent>,
    scanning_flag: Arc<AtomicBool>,
) {
    let mut last_known_usns = HashSet::new();

    while let Ok(cmd) = cmd_rx.recv() {
        match cmd {
            WorkerCommand::StartScan { drive_letter } => {
                scanning_flag.store(true, Ordering::SeqCst);
                let _ = event_tx.send(WorkerEvent::Status(format!(
                    "Opening raw volume handle for {}:...",
                    drive_letter
                )));

                let volume = match open_volume(drive_letter) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = event_tx.send(WorkerEvent::Error(e.message));
                        scanning_flag.store(false, Ordering::SeqCst);
                        continue;
                    }
                };

                let _ = event_tx.send(WorkerEvent::Status("Querying USN journal data...".to_string()));
                let journal_data = match query_usn_journal(&volume) {
                    Ok(jd) => jd,
                    Err(e) => {
                        let _ = event_tx.send(WorkerEvent::Error(e.message));
                        scanning_flag.store(false, Ordering::SeqCst);
                        continue;
                    }
                };

                let _ = event_tx.send(WorkerEvent::Status(
                    "Streaming MFT directory index...".to_string(),
                ));
                let _ = event_tx.send(WorkerEvent::Progress {
                    percent: 0.05,
                    message: "Streaming MFT entries for path resolution...".to_string(),
                });

                let mft_nodes = stream_mft_nodes(&volume, Some(600_000)).unwrap_or_default();

                let _ = event_tx.send(WorkerEvent::Status(
                    "Reading USN journal records...".to_string(),
                ));

                let total_span = (journal_data.next_usn - journal_data.first_usn).max(1) as f32;
                let mut current_usn = journal_data.first_usn;
                let mut raw_records = Vec::with_capacity(300_000);
                let mut chunk_buf = vec![0u8; 1024 * 1024];
                let mut rec_id = 0usize;

                loop {
                    if !scanning_flag.load(Ordering::SeqCst) {
                        break;
                    }

                    match read_usn_chunk(volume.handle, journal_data.usn_journal_id, current_usn, &mut chunk_buf) {
                        Ok((next_usn, bytes_read)) => {
                            if bytes_read <= 8 || next_usn <= current_usn {
                                break;
                            }

                            let mut offset = 8;
                            while offset + 8 <= bytes_read {
                                if let Some((rec, rec_len)) = parse_usn_record(&chunk_buf[offset..bytes_read], rec_id) {
                                    last_known_usns.insert(rec.usn);
                                    raw_records.push(rec);
                                    rec_id += 1;
                                    offset += rec_len;
                                    if offset % 8 != 0 {
                                        offset += 8 - (offset % 8);
                                    }
                                } else {
                                    break;
                                }
                            }

                            current_usn = next_usn;
                            let progress = ((current_usn - journal_data.first_usn) as f32 / total_span).clamp(0.0, 1.0);
                            let _ = event_tx.send(WorkerEvent::Progress {
                                percent: 0.10 + progress * 0.65,
                                message: format!("Parsed {} USN records...", raw_records.len()),
                            });

                            if current_usn >= journal_data.next_usn {
                                break;
                            }
                        }
                        Err(e) => {
                            let _ = event_tx.send(WorkerEvent::Error(e.message));
                            break;
                        }
                    }
                }

                let _ = event_tx.send(WorkerEvent::Status(
                    "Running CyberCX Rewind path reconstruction...".to_string(),
                ));
                let _ = event_tx.send(WorkerEvent::Progress {
                    percent: 0.80,
                    message: "Resolving full file paths...".to_string(),
                });

                let mut resolver = RewindResolver::new(drive_letter, mft_nodes.clone());
                resolver.index_records(&raw_records);
                resolver.resolve_all_paths(&mut raw_records);

                let _ = event_tx.send(WorkerEvent::Status(
                    "Running Anti-Forensics Analysis Engine...".to_string(),
                ));
                let _ = event_tx.send(WorkerEvent::Progress {
                    percent: 0.90,
                    message: "Scanning for bypasses and timestomping...".to_string(),
                });

                let bypass_report = run_antiforensics_audit(&journal_data, &raw_records, &mft_nodes);

                let mut oldest_time = i64::MAX;
                let mut file_count = 0usize;
                let mut dir_count = 0usize;

                for r in &raw_records {
                    if r.timestamp_raw > 0 && r.timestamp_raw < oldest_time {
                        oldest_time = r.timestamp_raw;
                    }
                    if (r.file_attributes & 0x10) != 0 {
                        dir_count += 1;
                    } else {
                        file_count += 1;
                    }
                }

                let oldest_formatted = if oldest_time != i64::MAX {
                    filetime_to_formatted_local(oldest_time)
                } else {
                    "N/A".to_string()
                };

                let stats = ScanStats {
                    oldest_timestamp_raw: oldest_time,
                    oldest_timestamp_formatted: oldest_formatted,
                    total_entries: raw_records.len(),
                    file_count,
                    dir_count,
                };

                let chunk_size = 50_000;
                for chunk in raw_records.chunks(chunk_size) {
                    let _ = event_tx.send(WorkerEvent::BatchRecords(chunk.to_vec()));
                }

                let _ = event_tx.send(WorkerEvent::BypassReport(bypass_report));
                let _ = event_tx.send(WorkerEvent::ScanFinished { stats });
                scanning_flag.store(false, Ordering::SeqCst);
            }
            WorkerCommand::StartCarve { drive_letter } => {
                scanning_flag.store(true, Ordering::SeqCst);
                let _ = event_tx.send(WorkerEvent::Status(
                    "Scanning volume slack clusters for orphan USN records...".to_string(),
                ));

                let volume = match open_volume(drive_letter) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = event_tx.send(WorkerEvent::Error(e.message));
                        scanning_flag.store(false, Ordering::SeqCst);
                        continue;
                    }
                };

                let total_clusters = volume.boot_info.total_sectors / (volume.boot_info.sectors_per_cluster as u64).max(1);
                let scan_limit = total_clusters.min(300_000);

                let tx = event_tx.clone();
                let _ = scan_volume_clusters_for_slack(
                    &volume,
                    0,
                    scan_limit,
                    &last_known_usns,
                    |carved_batch| {
                        let _ = tx.send(WorkerEvent::BatchRecords(carved_batch));
                    },
                );

                let _ = event_tx.send(WorkerEvent::Status("Carving completed.".to_string()));
                scanning_flag.store(false, Ordering::SeqCst);
            }
            WorkerCommand::Cancel => {
                scanning_flag.store(false, Ordering::SeqCst);
                let _ = event_tx.send(WorkerEvent::Status("Operation cancelled.".to_string()));
            }
        }
    }
}

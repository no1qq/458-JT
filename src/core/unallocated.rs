use std::collections::HashSet;

use crate::core::usn_record::{parse_usn_record, UsnRecord};
use crate::core::volume::{VolumeError, VolumeHandle};

pub fn carve_usn_records_from_buffer(
    buf: &[u8],
    base_id: usize,
    known_usns: &HashSet<i64>,
) -> Vec<UsnRecord> {
    let mut carved = Vec::new();
    let mut offset = 0;
    let min_record_size = 60;
    let max_record_size = 1024;
    let mut current_id = base_id;

    while offset + min_record_size <= buf.len() {
        if offset % 8 != 0 {
            offset += 8 - (offset % 8);
            if offset + min_record_size > buf.len() {
                break;
            }
        }

        let slice = &buf[offset..];
        let record_len = u32::from_le_bytes(slice[0..4].try_into().unwrap()) as usize;
        let major = u16::from_le_bytes(slice[4..6].try_into().unwrap());
        let minor = u16::from_le_bytes(slice[6..8].try_into().unwrap());

        if (major == 2 || major == 3)
            && minor == 0
            && record_len >= min_record_size
            && record_len <= max_record_size
            && offset + record_len <= buf.len()
        {
            if let Some((mut record, _)) = parse_usn_record(&slice[..record_len], current_id) {
                let valid_reason = record.reason != 0 && (record.reason & !0x81FF_FFFF) == 0;
                let valid_time = record.timestamp_raw > 120_000_000_000_000_000
                    && record.timestamp_raw < 150_000_000_000_000_000;
                let valid_name = !record.file_name.is_empty()
                    && record.file_name.chars().all(|c| !c.is_control());

                if valid_reason && valid_time && valid_name {
                    if !known_usns.contains(&record.usn) {
                        record.is_ghost = true;
                        carved.push(record);
                        current_id += 1;
                    }
                    offset += record_len;
                    continue;
                }
            }
        }

        offset += 8;
    }

    carved
}

pub fn scan_volume_clusters_for_slack(
    volume: &VolumeHandle,
    start_cluster: u64,
    cluster_count: u64,
    known_usns: &HashSet<i64>,
    mut on_batch: impl FnMut(Vec<UsnRecord>),
) -> Result<usize, VolumeError> {
    let cluster_size = volume.boot_info.cluster_size as u64;
    let batch_clusters = 128u64;
    let batch_bytes = (batch_clusters * cluster_size) as usize;
    let mut buffer = vec![0u8; batch_bytes];
    let mut total_carved = 0usize;
    let mut clusters_processed = 0u64;

    while clusters_processed < cluster_count {
        let current_lcn = start_cluster + clusters_processed;
        let clusters_to_read = (cluster_count - clusters_processed).min(batch_clusters);
        let bytes_to_read = (clusters_to_read * cluster_size) as usize;
        let slice = &mut buffer[..bytes_to_read];

        let disk_offset = current_lcn * cluster_size;
        if volume.read_bytes_at(disk_offset, slice).is_ok() {
            let found = carve_usn_records_from_buffer(slice, 900_000 + total_carved, known_usns);
            if !found.is_empty() {
                total_carved += found.len();
                on_batch(found);
            }
        }

        clusters_processed += clusters_to_read;
    }

    Ok(total_carved)
}

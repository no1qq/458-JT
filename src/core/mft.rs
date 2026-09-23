#![allow(clippy::chunks_exact_to_as_chunks)]

use std::collections::HashMap;

use crate::core::volume::{VolumeError, VolumeHandle};

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct MftNode {
    pub entry: u64,
    pub sequence: u16,
    pub parent_entry: u64,
    pub parent_sequence: u16,
    pub name: String,
    pub is_dir: bool,
    pub si_created: i64,
    pub si_modified: i64,
    pub fn_created: i64,
    pub fn_modified: i64,
}

#[derive(Clone, Debug)]
pub struct ClusterRun {
    pub start_lcn: i64,
    pub cluster_count: u64,
}

pub fn apply_mft_fixup(record: &mut [u8]) -> bool {
    if record.len() < 512 || &record[0..4] != b"FILE" {
        return false;
    }

    let usa_offset = u16::from_le_bytes(record[4..6].try_into().unwrap()) as usize;
    let usa_count = u16::from_le_bytes(record[6..8].try_into().unwrap()) as usize;

    if usa_offset + usa_count * 2 > record.len() || usa_count < 2 {
        return false;
    }

    let check_val = u16::from_le_bytes(record[usa_offset..usa_offset + 2].try_into().unwrap());
    let sector_count = usa_count - 1;

    for i in 0..sector_count {
        let sector_end = (i + 1) * 512;
        if sector_end > record.len() {
            break;
        }
        let end_bytes = &record[sector_end - 2..sector_end];
        let actual_val = u16::from_le_bytes(end_bytes.try_into().unwrap());
        if actual_val != check_val {
            return false;
        }
    }

    for i in 0..sector_count {
        let sector_end = (i + 1) * 512;
        if sector_end > record.len() {
            break;
        }
        let fixup_offset = usa_offset + 2 + i * 2;
        record[sector_end - 2] = record[fixup_offset];
        record[sector_end - 1] = record[fixup_offset + 1];
    }

    true
}

pub fn decode_runlist(data: &[u8]) -> Vec<ClusterRun> {
    let mut runs = Vec::new();
    let mut cursor = 0;
    let mut current_lcn: i64 = 0;

    while cursor < data.len() {
        let header = data[cursor];
        if header == 0 {
            break;
        }
        cursor += 1;

        let count_len = (header & 0x0F) as usize;
        let offset_len = ((header >> 4) & 0x0F) as usize;

        if cursor + count_len + offset_len > data.len() {
            break;
        }

        let mut count_val: u64 = 0;
        for i in 0..count_len {
            count_val |= (data[cursor + i] as u64) << (i * 8);
        }
        cursor += count_len;

        let mut offset_val: i64 = 0;
        if offset_len > 0 {
            for i in 0..offset_len {
                offset_val |= (data[cursor + i] as i64) << (i * 8);
            }
            let sign_bit = 1i64 << (offset_len * 8 - 1);
            if (offset_val & sign_bit) != 0 {
                let mask = !0i64 << (offset_len * 8);
                offset_val |= mask;
            }
            cursor += offset_len;
            current_lcn += offset_val;
        }

        runs.push(ClusterRun {
            start_lcn: current_lcn,
            cluster_count: count_val,
        });
    }

    runs
}

pub fn parse_mft_record(record: &[u8], entry_idx: u64) -> Option<MftNode> {
    if record.len() < 48 || &record[0..4] != b"FILE" {
        return None;
    }

    let seq = u16::from_le_bytes(record[16..18].try_into().ok()?);
    let flags = u16::from_le_bytes(record[22..24].try_into().ok()?);
    let is_dir = (flags & 0x02) != 0;

    let mut attr_offset = u16::from_le_bytes(record[20..22].try_into().ok()?) as usize;

    let mut si_created = 0i64;
    let mut si_modified = 0i64;

    let mut fn_name = String::new();
    let mut fn_parent = 0u64;
    let mut fn_parent_seq = 0u16;
    let mut fn_created = 0i64;
    let mut fn_modified = 0i64;
    let mut preferred_ns = 255u8;

    while attr_offset + 8 <= record.len() {
        let attr_type = u32::from_le_bytes(record[attr_offset..attr_offset + 4].try_into().ok()?);
        if attr_type == 0xFFFF_FFFF {
            break;
        }

        let attr_len =
            u32::from_le_bytes(record[attr_offset + 4..attr_offset + 8].try_into().ok()?) as usize;
        if attr_len == 0 || attr_offset + attr_len > record.len() {
            break;
        }

        let non_resident = record[attr_offset + 8];

        if attr_type == 0x10 && non_resident == 0 {
            if attr_offset + 22 <= record.len() {
                let val_offset =
                    u16::from_le_bytes(record[attr_offset + 20..attr_offset + 22].try_into().ok()?)
                        as usize;
                let val_start = attr_offset + val_offset;
                if val_start + 32 <= record.len() {
                    si_created =
                        i64::from_le_bytes(record[val_start..val_start + 8].try_into().ok()?);
                    si_modified =
                        i64::from_le_bytes(record[val_start + 8..val_start + 16].try_into().ok()?);
                }
            }
        } else if attr_type == 0x30 && non_resident == 0 && attr_offset + 22 <= record.len() {
            let val_offset =
                    u16::from_le_bytes(record[attr_offset + 20..attr_offset + 22].try_into().ok()?)
                        as usize;
                let val_start = attr_offset + val_offset;
                if val_start + 66 <= record.len() {
                    let raw_parent =
                        u64::from_le_bytes(record[val_start..val_start + 8].try_into().ok()?);
                    let parent_entry = raw_parent & 0x0000_FFFF_FFFF_FFFF;
                    let parent_seq = ((raw_parent >> 48) & 0xFFFF) as u16;

                    let cr =
                        i64::from_le_bytes(record[val_start + 8..val_start + 16].try_into().ok()?);
                    let md = i64::from_le_bytes(
                        record[val_start + 16..val_start + 24]
                            .try_into()
                            .ok()?,
                    );

                    let name_len = record[val_start + 64] as usize;
                    let namespace = record[val_start + 65];

                    if val_start + 66 + name_len * 2 <= record.len() {
                        let name_bytes = &record[val_start + 66..val_start + 66 + name_len * 2];
                        let utf16_chars: Vec<u16> = name_bytes
                            .chunks_exact(2)
                            .map(|c| u16::from_le_bytes([c[0], c[1]]))
                            .collect();
                        let decoded_name = String::from_utf16_lossy(&utf16_chars);

                        let should_use = match namespace {
                            1 | 3 => true,
                            0 => preferred_ns > 0,
                            2 => preferred_ns > 2,
                            _ => fn_name.is_empty(),
                        };

                        if should_use || fn_name.is_empty() {
                            fn_name = decoded_name;
                            fn_parent = parent_entry;
                            fn_parent_seq = parent_seq;
                            fn_created = cr;
                            fn_modified = md;
                            preferred_ns = namespace;
                        }
                    }
                }
            }

        attr_offset += attr_len;
    }

    if fn_name.is_empty() {
        return None;
    }

    Some(MftNode {
        entry: entry_idx,
        sequence: seq,
        parent_entry: fn_parent,
        parent_sequence: fn_parent_seq,
        name: fn_name,
        is_dir,
        si_created,
        si_modified,
        fn_created,
        fn_modified,
    })
}

pub fn extract_mft_runs(record_zero: &[u8]) -> Option<Vec<ClusterRun>> {
    if record_zero.len() < 48 || &record_zero[0..4] != b"FILE" {
        return None;
    }

    let mut attr_offset =
        u16::from_le_bytes(record_zero[20..22].try_into().ok()?) as usize;

    while attr_offset + 8 <= record_zero.len() {
        let attr_type =
            u32::from_le_bytes(record_zero[attr_offset..attr_offset + 4].try_into().ok()?);
        if attr_type == 0xFFFF_FFFF {
            break;
        }

        let attr_len = u32::from_le_bytes(
            record_zero[attr_offset + 4..attr_offset + 8]
                .try_into()
                .ok()?,
        ) as usize;
        if attr_len == 0 || attr_offset + attr_len > record_zero.len() {
            break;
        }

        let non_resident = record_zero[attr_offset + 8];

        if attr_type == 0x80 && non_resident == 1 {
            let runlist_offset = u16::from_le_bytes(
                record_zero[attr_offset + 32..attr_offset + 34]
                    .try_into()
                    .ok()?,
            ) as usize;
            let runlist_start = attr_offset + runlist_offset;
            if runlist_start < record_zero.len() {
                return Some(decode_runlist(&record_zero[runlist_start..]));
            }
        }

        attr_offset += attr_len;
    }

    None
}

pub fn stream_mft_nodes(
    volume: &VolumeHandle,
    max_records: Option<usize>,
) -> Result<HashMap<u64, MftNode>, VolumeError> {
    let cluster_size = volume.boot_info.cluster_size as u64;
    let record_size = volume.boot_info.mft_record_size as usize;
    let mft_start_offset = volume.boot_info.mft_start_lcn * cluster_size;

    let mut record_zero_buf = vec![0u8; record_size.max(512)];
    volume.read_bytes_at(mft_start_offset, &mut record_zero_buf)?;

    let mut fixed_zero = record_zero_buf.clone();
    let _ = apply_mft_fixup(&mut fixed_zero);

    let runs = extract_mft_runs(&fixed_zero).unwrap_or_else(|| {
        vec![ClusterRun {
            start_lcn: volume.boot_info.mft_start_lcn as i64,
            cluster_count: 8192,
        }]
    });

    let mut nodes = HashMap::new();
    let mut total_records_parsed = 0usize;
    let chunk_clusters = 64u64;
    let chunk_bytes = (chunk_clusters * cluster_size) as usize;
    let mut chunk_buf = vec![0u8; chunk_bytes];

    'run_loop: for run in runs {
        if run.start_lcn <= 0 {
            continue;
        }
        let run_bytes = run.cluster_count * cluster_size;
        let mut offset_in_run = 0u64;

        while offset_in_run < run_bytes {
            let to_read = (run_bytes - offset_in_run).min(chunk_bytes as u64) as usize;
            let aligned_to_read = to_read.div_ceil(512) * 512;
            let slice = &mut chunk_buf[..aligned_to_read];

            let disk_offset = (run.start_lcn as u64 * cluster_size) + offset_in_run;
            if volume.read_bytes_at(disk_offset, slice).is_err() {
                break;
            }

            let mut rec_cursor = 0;
            while rec_cursor + record_size <= to_read {
                let rec_slice = &mut slice[rec_cursor..rec_cursor + record_size];
                let entry_idx = total_records_parsed as u64;
                if apply_mft_fixup(rec_slice) {
                    if let Some(node) = parse_mft_record(rec_slice, entry_idx) {
                        nodes.insert(node.entry, node);
                    }
                }
                total_records_parsed += 1;
                rec_cursor += record_size;

                if let Some(max) = max_records {
                    if total_records_parsed >= max {
                        break 'run_loop;
                    }
                }
            }

            offset_in_run += to_read as u64;
        }
    }

    Ok(nodes)
}

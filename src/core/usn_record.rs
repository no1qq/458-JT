#![allow(clippy::chunks_exact_to_as_chunks)]

use chrono::{DateTime, Local, TimeZone};
use serde::{Deserialize, Serialize};

pub const USN_REASON_DATA_OVERWRITE: u32 = 0x0000_0001;
pub const USN_REASON_DATA_EXTEND: u32 = 0x0000_0002;
pub const USN_REASON_DATA_TRUNCATION: u32 = 0x0000_0004;
pub const USN_REASON_NAMED_DATA_OVERWRITE: u32 = 0x0000_0010;
pub const USN_REASON_NAMED_DATA_EXTEND: u32 = 0x0000_0020;
pub const USN_REASON_NAMED_DATA_TRUNCATION: u32 = 0x0000_0040;
pub const USN_REASON_FILE_CREATE: u32 = 0x0000_0100;
pub const USN_REASON_FILE_DELETE: u32 = 0x0000_0200;
pub const USN_REASON_EA_CHANGE: u32 = 0x0000_0400;
pub const USN_REASON_SECURITY_CHANGE: u32 = 0x0000_0800;
pub const USN_REASON_RENAME_OLD_NAME: u32 = 0x0000_1000;
pub const USN_REASON_RENAME_NEW_NAME: u32 = 0x0000_2000;
pub const USN_REASON_INDEXABLE_CHANGE: u32 = 0x0000_4000;
pub const USN_REASON_BASIC_INFO_CHANGE: u32 = 0x0000_8000;
pub const USN_REASON_HARD_LINK_CHANGE: u32 = 0x0001_0000;
pub const USN_REASON_COMPRESSION_CHANGE: u32 = 0x0002_0000;
pub const USN_REASON_ENCRYPTION_CHANGE: u32 = 0x0004_0000;
pub const USN_REASON_OBJECT_ID_CHANGE: u32 = 0x0008_0000;
pub const USN_REASON_REPARSE_POINT_CHANGE: u32 = 0x0010_0000;
pub const USN_REASON_STREAM_CHANGE: u32 = 0x0020_0000;
pub const USN_REASON_TRANSACTED_CHANGE: u32 = 0x0040_0000;
pub const USN_REASON_INTEGRITY_CHANGE: u32 = 0x0080_0000;
pub const USN_REASON_DESIRED_STORAGE_CLASS: u32 = 0x0100_0000;
pub const USN_REASON_CLOSE: u32 = 0x8000_0000;

pub const ALL_REASONS: &[(u32, &str)] = &[
    (USN_REASON_DATA_OVERWRITE, "Data Overwrite"),
    (USN_REASON_DATA_EXTEND, "Data Extend"),
    (USN_REASON_DATA_TRUNCATION, "Data Truncation"),
    (USN_REASON_NAMED_DATA_OVERWRITE, "Named Data Overwrite"),
    (USN_REASON_NAMED_DATA_EXTEND, "Named Data Extend"),
    (USN_REASON_NAMED_DATA_TRUNCATION, "Named Data Truncation"),
    (USN_REASON_FILE_CREATE, "File Created"),
    (USN_REASON_FILE_DELETE, "File Deleted"),
    (USN_REASON_EA_CHANGE, "EA Change"),
    (USN_REASON_SECURITY_CHANGE, "Security Change"),
    (USN_REASON_RENAME_OLD_NAME, "Rename Old Name"),
    (USN_REASON_RENAME_NEW_NAME, "Rename New Name"),
    (USN_REASON_INDEXABLE_CHANGE, "Indexable Change"),
    (USN_REASON_BASIC_INFO_CHANGE, "Basic Info Change"),
    (USN_REASON_HARD_LINK_CHANGE, "Hard Link Change"),
    (USN_REASON_COMPRESSION_CHANGE, "Compression Change"),
    (USN_REASON_ENCRYPTION_CHANGE, "Encryption Change"),
    (USN_REASON_OBJECT_ID_CHANGE, "Object ID Change"),
    (USN_REASON_REPARSE_POINT_CHANGE, "Reparse Point Change"),
    (USN_REASON_STREAM_CHANGE, "Stream Change"),
    (USN_REASON_TRANSACTED_CHANGE, "Transacted Change"),
    (USN_REASON_INTEGRITY_CHANGE, "Integrity Change"),
    (USN_REASON_DESIRED_STORAGE_CLASS, "Desired Storage Class"),
    (USN_REASON_CLOSE, "Close"),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct UsnRecord {
    pub id: usize,
    pub record_length: u32,
    pub major_version: u16,
    pub minor_version: u16,
    pub file_ref_number: u64,
    pub file_ref_seq: u16,
    pub parent_file_ref_number: u64,
    pub parent_file_ref_seq: u16,
    pub usn: i64,
    pub timestamp_raw: i64,
    pub timestamp_formatted: String,
    pub reason: u32,
    pub reason_str: String,
    pub source_info: u32,
    pub security_id: u32,
    pub file_attributes: u32,
    pub file_name: String,
    pub full_path: String,
    pub is_ghost: bool,
    pub is_stomp: bool,
}

pub fn format_reasons(reason: u32) -> String {
    let mut parts = Vec::with_capacity(4);
    for (flag, name) in ALL_REASONS {
        if (reason & flag) != 0 {
            parts.push(*name);
        }
    }
    if parts.is_empty() {
        "None".to_string()
    } else {
        parts.join(", ")
    }
}

pub fn filetime_to_formatted_local(filetime: i64) -> String {
    const FILETIME_TO_UNIX_OFFSET: i64 = 116_444_736_000_000_000;
    if filetime <= FILETIME_TO_UNIX_OFFSET {
        return "1970-01-01 00:00:00".to_string();
    }
    let diff = filetime - FILETIME_TO_UNIX_OFFSET;
    let secs = diff / 10_000_000;
    let nsecs = ((diff % 10_000_000) * 100) as u32;

    match Local.timestamp_opt(secs, nsecs) {
        chrono::LocalResult::Single(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::Ambiguous(dt, _) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        chrono::LocalResult::None => "1970-01-01 00:00:00".to_string(),
    }
}

#[allow(dead_code)]
pub fn filetime_to_datetime_utc(filetime: i64) -> Option<DateTime<chrono::Utc>> {
    const FILETIME_TO_UNIX_OFFSET: i64 = 116_444_736_000_000_000;
    if filetime <= FILETIME_TO_UNIX_OFFSET {
        return None;
    }
    let diff = filetime - FILETIME_TO_UNIX_OFFSET;
    let secs = diff / 10_000_000;
    let nsecs = ((diff % 10_000_000) * 100) as u32;
    DateTime::from_timestamp(secs, nsecs)
}

pub fn parse_usn_record(buf: &[u8], id: usize) -> Option<(UsnRecord, usize)> {
    if buf.len() < 8 {
        return None;
    }
    let record_len = u32::from_le_bytes(buf[0..4].try_into().ok()?) as usize;
    if record_len < 8 || record_len > buf.len() {
        return None;
    }
    let major_version = u16::from_le_bytes(buf[4..6].try_into().ok()?);
    let minor_version = u16::from_le_bytes(buf[6..8].try_into().ok()?);

    match major_version {
        2 => {
            if record_len < 60 {
                return None;
            }
            let raw_file_ref = u64::from_le_bytes(buf[8..16].try_into().ok()?);
            let raw_parent_ref = u64::from_le_bytes(buf[16..24].try_into().ok()?);
            let usn = i64::from_le_bytes(buf[24..32].try_into().ok()?);
            let timestamp_raw = i64::from_le_bytes(buf[32..40].try_into().ok()?);
            let reason = u32::from_le_bytes(buf[40..44].try_into().ok()?);
            let source_info = u32::from_le_bytes(buf[44..48].try_into().ok()?);
            let security_id = u32::from_le_bytes(buf[48..52].try_into().ok()?);
            let file_attributes = u32::from_le_bytes(buf[52..56].try_into().ok()?);
            let file_name_len = u16::from_le_bytes(buf[56..58].try_into().ok()?) as usize;
            let file_name_offset = u16::from_le_bytes(buf[58..60].try_into().ok()?) as usize;

            if file_name_offset > record_len || file_name_offset + file_name_len > record_len {
                return None;
            }

            let name_slice = &buf[file_name_offset..file_name_offset + file_name_len];
            let utf16_chars: Vec<u16> = name_slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let file_name = String::from_utf16_lossy(&utf16_chars);

            let file_ref_number = raw_file_ref & 0x0000_FFFF_FFFF_FFFF;
            let file_ref_seq = ((raw_file_ref >> 48) & 0xFFFF) as u16;
            let parent_file_ref_number = raw_parent_ref & 0x0000_FFFF_FFFF_FFFF;
            let parent_file_ref_seq = ((raw_parent_ref >> 48) & 0xFFFF) as u16;

            let timestamp_formatted = filetime_to_formatted_local(timestamp_raw);
            let reason_str = format_reasons(reason);

            Some((
                UsnRecord {
                    id,
                    record_length: record_len as u32,
                    major_version,
                    minor_version,
                    file_ref_number,
                    file_ref_seq,
                    parent_file_ref_number,
                    parent_file_ref_seq,
                    usn,
                    timestamp_raw,
                    timestamp_formatted,
                    reason,
                    reason_str,
                    source_info,
                    security_id,
                    file_attributes,
                    file_name: file_name.clone(),
                    full_path: file_name,
                    is_ghost: false,
                    is_stomp: false,
                },
                record_len,
            ))
        }
        3 => {
            if record_len < 76 {
                return None;
            }
            let raw_file_ref = u64::from_le_bytes(buf[8..16].try_into().ok()?);
            let raw_parent_ref = u64::from_le_bytes(buf[24..32].try_into().ok()?);
            let usn = i64::from_le_bytes(buf[40..48].try_into().ok()?);
            let timestamp_raw = i64::from_le_bytes(buf[48..56].try_into().ok()?);
            let reason = u32::from_le_bytes(buf[56..60].try_into().ok()?);
            let source_info = u32::from_le_bytes(buf[60..64].try_into().ok()?);
            let security_id = u32::from_le_bytes(buf[64..68].try_into().ok()?);
            let file_attributes = u32::from_le_bytes(buf[68..72].try_into().ok()?);
            let file_name_len = u16::from_le_bytes(buf[72..74].try_into().ok()?) as usize;
            let file_name_offset = u16::from_le_bytes(buf[74..76].try_into().ok()?) as usize;

            if file_name_offset > record_len || file_name_offset + file_name_len > record_len {
                return None;
            }

            let name_slice = &buf[file_name_offset..file_name_offset + file_name_len];
            let utf16_chars: Vec<u16> = name_slice
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .collect();
            let file_name = String::from_utf16_lossy(&utf16_chars);

            let file_ref_number = raw_file_ref & 0x0000_FFFF_FFFF_FFFF;
            let file_ref_seq = ((raw_file_ref >> 48) & 0xFFFF) as u16;
            let parent_file_ref_number = raw_parent_ref & 0x0000_FFFF_FFFF_FFFF;
            let parent_file_ref_seq = ((raw_parent_ref >> 48) & 0xFFFF) as u16;

            let timestamp_formatted = filetime_to_formatted_local(timestamp_raw);
            let reason_str = format_reasons(reason);

            Some((
                UsnRecord {
                    id,
                    record_length: record_len as u32,
                    major_version,
                    minor_version,
                    file_ref_number,
                    file_ref_seq,
                    parent_file_ref_number,
                    parent_file_ref_seq,
                    usn,
                    timestamp_raw,
                    timestamp_formatted,
                    reason,
                    reason_str,
                    source_info,
                    security_id,
                    file_attributes,
                    file_name: file_name.clone(),
                    full_path: file_name,
                    is_ghost: false,
                    is_stomp: false,
                },
                record_len,
            ))
        }
        4 => {
            if record_len < 40 {
                return None;
            }
            let raw_file_ref = u64::from_le_bytes(buf[8..16].try_into().ok()?);
            let raw_parent_ref = u64::from_le_bytes(buf[16..24].try_into().ok()?);
            let usn = i64::from_le_bytes(buf[24..32].try_into().ok()?);
            let reason = u32::from_le_bytes(buf[32..36].try_into().ok()?);

            let file_ref_number = raw_file_ref & 0x0000_FFFF_FFFF_FFFF;
            let file_ref_seq = ((raw_file_ref >> 48) & 0xFFFF) as u16;
            let parent_file_ref_number = raw_parent_ref & 0x0000_FFFF_FFFF_FFFF;
            let parent_file_ref_seq = ((raw_parent_ref >> 48) & 0xFFFF) as u16;

            Some((
                UsnRecord {
                    id,
                    record_length: record_len as u32,
                    major_version,
                    minor_version,
                    file_ref_number,
                    file_ref_seq,
                    parent_file_ref_number,
                    parent_file_ref_seq,
                    usn,
                    timestamp_raw: 0,
                    timestamp_formatted: "N/A".to_string(),
                    reason,
                    reason_str: format_reasons(reason),
                    source_info: 0,
                    security_id: 0,
                    file_attributes: 0,
                    file_name: String::new(),
                    full_path: String::new(),
                    is_ghost: false,
                    is_stomp: false,
                },
                record_len,
            ))
        }
        _ => None,
    }
}

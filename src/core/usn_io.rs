use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::IO::DeviceIoControl;

use crate::core::volume::{VolumeError, VolumeHandle};

pub const FSCTL_QUERY_USN_JOURNAL: u32 = 0x000900F4;
pub const FSCTL_READ_USN_JOURNAL: u32 = 0x000900BB;

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct UsnJournalData {
    pub usn_journal_id: u64,
    pub first_usn: i64,
    pub next_usn: i64,
    pub lowest_valid_usn: i64,
    pub max_usn: i64,
    pub maximum_size: u64,
    pub allocation_delta: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct ReadUsnJournalData {
    pub start_usn: i64,
    pub reason_mask: u32,
    pub return_only_on_close: u32,
    pub timeout: u64,
    pub bytes_to_wait_for: u64,
    pub usn_journal_id: u64,
}

pub fn query_usn_journal(volume: &VolumeHandle) -> Result<UsnJournalData, VolumeError> {
    let mut journal_data = UsnJournalData::default();
    let mut bytes_returned: u32 = 0;

    unsafe {
        DeviceIoControl(
            volume.handle,
            FSCTL_QUERY_USN_JOURNAL,
            None,
            0,
            Some(&mut journal_data as *mut _ as *mut _),
            std::mem::size_of::<UsnJournalData>() as u32,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| VolumeError {
            message: format!(
                "FSCTL_QUERY_USN_JOURNAL failed on drive {}: 0x{:08X}",
                volume.drive_letter,
                e.code().0
            ),
        })?;
    }

    Ok(journal_data)
}

pub fn read_usn_chunk(
    volume_handle: HANDLE,
    journal_id: u64,
    start_usn: i64,
    output_buf: &mut [u8],
) -> Result<(i64, usize), VolumeError> {
    if output_buf.len() < 8 {
        return Err(VolumeError {
            message: "USN read buffer must be at least 8 bytes".to_string(),
        });
    }

    let input = ReadUsnJournalData {
        start_usn,
        reason_mask: 0xFFFF_FFFF,
        return_only_on_close: 0,
        timeout: 0,
        bytes_to_wait_for: 0,
        usn_journal_id: journal_id,
    };

    let mut bytes_returned: u32 = 0;

    unsafe {
        DeviceIoControl(
            volume_handle,
            FSCTL_READ_USN_JOURNAL,
            Some(&input as *const _ as *const _),
            std::mem::size_of::<ReadUsnJournalData>() as u32,
            Some(output_buf.as_mut_ptr() as *mut _),
            output_buf.len() as u32,
            Some(&mut bytes_returned),
            None,
        )
        .map_err(|e| VolumeError {
            message: format!("FSCTL_READ_USN_JOURNAL failed: 0x{:08X}", e.code().0),
        })?;
    }

    let returned_size = bytes_returned as usize;
    if returned_size < 8 {
        return Ok((start_usn, 0));
    }

    let next_usn = i64::from_le_bytes(output_buf[0..8].try_into().unwrap());
    Ok((next_usn, returned_size))
}

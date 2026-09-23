use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, INVALID_HANDLE_VALUE, LUID};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW,
    TokenElevation, LUID_AND_ATTRIBUTES, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY,
};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, ReadFile, SetFilePointerEx, FILE_BEGIN,
    FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_NO_BUFFERING, FILE_GENERIC_READ,
    FILE_GENERIC_WRITE, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

#[derive(Debug, Clone)]
pub struct VolumeError {
    pub message: String,
}

impl std::fmt::Display for VolumeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for VolumeError {}

#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct BootSectorInfo {
    pub bytes_per_sector: u32,
    pub sectors_per_cluster: u32,
    pub cluster_size: u32,
    pub total_sectors: u64,
    pub mft_start_lcn: u64,
    pub clusters_per_mft_record: i8,
    pub mft_record_size: u32,
}

pub struct VolumeHandle {
    pub handle: HANDLE,
    pub drive_letter: char,
    pub boot_info: BootSectorInfo,
}

impl Drop for VolumeHandle {
    fn drop(&mut self) {
        if self.handle != INVALID_HANDLE_VALUE && !self.handle.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.handle);
            }
        }
    }
}

pub fn is_process_elevated() -> bool {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token).is_err() {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION::default();
        let mut return_length: u32 = 0;
        let success = GetTokenInformation(
            token,
            TokenElevation,
            Some(&mut elevation as *mut _ as *mut _),
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut return_length,
        );
        let _ = CloseHandle(token);
        if success.is_ok() {
            elevation.TokenIsElevated != 0
        } else {
            false
        }
    }
}

pub fn enable_privileges() -> Result<(), VolumeError> {
    unsafe {
        let mut token: HANDLE = HANDLE::default();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        )
        .is_err()
        {
            return Err(VolumeError {
                message: "Failed to open process token for privilege adjustment".to_string(),
            });
        }

        let privileges = [
            "SeBackupPrivilege",
            "SeRestorePrivilege",
            "SeManageVolumePrivilege",
            "SeSecurityPrivilege",
        ];

        for priv_name in privileges {
            let wide: Vec<u16> = OsStr::new(priv_name)
                .encode_wide()
                .chain(std::iter::once(0))
                .collect();
            let mut luid = LUID::default();
            if LookupPrivilegeValueW(PCWSTR::null(), PCWSTR(wide.as_ptr()), &mut luid).is_ok() {
                let tp = TOKEN_PRIVILEGES {
                    PrivilegeCount: 1,
                    Privileges: [LUID_AND_ATTRIBUTES {
                        Luid: luid,
                        Attributes: SE_PRIVILEGE_ENABLED,
                    }],
                };
                let _ = AdjustTokenPrivileges(
                    token,
                    false,
                    Some(&tp),
                    std::mem::size_of::<TOKEN_PRIVILEGES>() as u32,
                    None,
                    None,
                );
            }
        }

        let _ = CloseHandle(token);
        Ok(())
    }
}

pub fn open_volume(drive_letter: char) -> Result<VolumeHandle, VolumeError> {
    let _ = enable_privileges();

    let path_str = format!("\\\\.\\{}:", drive_letter.to_ascii_uppercase());
    let path_wide: Vec<u16> = OsStr::new(&path_str)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let share_mode = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;
    let flags = FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_NO_BUFFERING;

    let handle = unsafe {
        let h = CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            FILE_GENERIC_READ.0 | FILE_GENERIC_WRITE.0,
            share_mode,
            None,
            OPEN_EXISTING,
            flags,
            HANDLE::default(),
        );

        match h {
            Ok(handle) if !handle.is_invalid() => handle,
            _ => {
                let fallback = CreateFileW(
                    PCWSTR(path_wide.as_ptr()),
                    FILE_GENERIC_READ.0,
                    share_mode,
                    None,
                    OPEN_EXISTING,
                    flags,
                    HANDLE::default(),
                );
                fallback.map_err(|e| VolumeError {
                    message: format!(
                        "Failed to open raw volume handle for {}: error code 0x{:08X}",
                        path_str,
                        e.code().0
                    ),
                })?
            }
        }
    };

    let mut sector_zero = vec![0u8; 512];
    unsafe {
        let mut bytes_read: u32 = 0;
        let mut distance: i64 = 0;
        let _ = SetFilePointerEx(handle, 0, Some(&mut distance), FILE_BEGIN);
        ReadFile(
            handle,
            Some(&mut sector_zero),
            Some(&mut bytes_read),
            None,
        )
        .map_err(|_| VolumeError {
            message: format!("Failed to read boot sector for {}", path_str),
        })?;
    }

    let boot_info = parse_boot_sector(&sector_zero)?;

    Ok(VolumeHandle {
        handle,
        drive_letter: drive_letter.to_ascii_uppercase(),
        boot_info,
    })
}

fn parse_boot_sector(buf: &[u8]) -> Result<BootSectorInfo, VolumeError> {
    if buf.len() < 512 {
        return Err(VolumeError {
            message: "Sector buffer too small for boot record".to_string(),
        });
    }

    if &buf[3..7] != b"NTFS" {
        return Err(VolumeError {
            message: "Target volume is not a valid NTFS filesystem".to_string(),
        });
    }

    let bytes_per_sector = u16::from_le_bytes(buf[0x0B..0x0D].try_into().unwrap()) as u32;
    let sectors_per_cluster = buf[0x0D] as u32;
    let cluster_size = bytes_per_sector * sectors_per_cluster;
    let total_sectors = u64::from_le_bytes(buf[0x28..0x30].try_into().unwrap());
    let mft_start_lcn = u64::from_le_bytes(buf[0x30..0x38].try_into().unwrap());
    let clusters_per_mft_record = buf[0x40] as i8;

    let mft_record_size = if clusters_per_mft_record >= 0 {
        (clusters_per_mft_record as u32) * cluster_size
    } else {
        1u32 << (-(clusters_per_mft_record as i32))
    };

    Ok(BootSectorInfo {
        bytes_per_sector,
        sectors_per_cluster,
        cluster_size,
        total_sectors,
        mft_start_lcn,
        clusters_per_mft_record,
        mft_record_size,
    })
}

impl VolumeHandle {
    pub fn read_bytes_at(&self, offset: u64, dest: &mut [u8]) -> Result<(), VolumeError> {
        let sector_size = self.boot_info.bytes_per_sector as u64;
        if !offset.is_multiple_of(sector_size) || !(dest.len() as u64).is_multiple_of(sector_size) {
            return Err(VolumeError {
                message: "Unaligned sector read requested on unbuffered volume handle".to_string(),
            });
        }

        unsafe {
            let mut pos: i64 = 0;
            SetFilePointerEx(self.handle, offset as i64, Some(&mut pos), FILE_BEGIN)
                .map_err(|e| VolumeError {
                    message: format!("Seek failure at offset {}: 0x{:08X}", offset, e.code().0),
                })?;

            let mut bytes_read: u32 = 0;
            ReadFile(
                self.handle,
                Some(dest),
                Some(&mut bytes_read),
                None,
            )
            .map_err(|e| VolumeError {
                message: format!("Read error at offset {}: 0x{:08X}", offset, e.code().0),
            })?;

            if (bytes_read as usize) != dest.len() {
                return Err(VolumeError {
                    message: format!(
                        "Short read: expected {} bytes, got {}",
                        dest.len(),
                        bytes_read
                    ),
                });
            }
        }
        Ok(())
    }
}

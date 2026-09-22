<div align="center">
  <img src="https://i.ibb.co/xKSCFRqj/458-Background.png" width="200" alt="458 JT Logo" />
  <h1 style="border-bottom: none;">458 JT (JournalTrace)</h1>
  <p>
    <a href="https://discord.gg/wybwu9dsYg"><img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord" /></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-CE412B?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" alt="GPLv3 License" /></a>
  </p>
</div>

### features
- USN journal bypass and anti-forensics detection (gap analysis, record stomping, zeroed sectors)
- journal deletion and recreation auditing (fsutil tracking, journal ID changes, size resets)
- timestomping analysis ($SI vs $FN attribute delta verification, 100ns precision truncation)
- CyberCX Rewind path reconstruction algorithm for 100% accuracy on reused MFT entries
- unallocated cluster slack carving to extract deleted ghost USN records
- live real-time journal event monitoring with USN cursor polling
- automated PC check presets for competitive gaming checks and triage

### requirements
- Windows 10 / 11 (64-bit)
- NTFS file system volume
- Administrator privileges (required for raw disk handles and SeBackupPrivilege)

### quick start
```powershell
# run standard PC check forensic scan
458-jt.exe scan --preset pccheck

# run dedicated anti-forensics and bypass audit
458-jt.exe bypasses

# stream live file operations in real time
458-jt.exe live

# carve unallocated clusters for ghost USN records
458-jt.exe carve --volume C:
```

### license
licensed under the [GNU General Public License v3.0](LICENSE).  
Copyright (c) 2026 The 458 Development Team

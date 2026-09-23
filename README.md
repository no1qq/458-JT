<div align="center">
  <img src="https://i.ibb.co/xKSCFRqj/458-Background.png" width="200" alt="458 JT Logo" />
  <h1 style="border-bottom: none;">458 JT (JournalTrace)</h1>
  <p>
    <a href="https://discord.gg/wybwu9dsYg"><img src="https://img.shields.io/badge/Discord-5865F2?style=for-the-badge&logo=discord&logoColor=white" alt="Discord" /></a>
    <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/Rust-CE412B?style=for-the-badge&logo=rust&logoColor=white" alt="Rust" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-GPLv3-blue?style=for-the-badge" alt="GPLv3 License" /></a>
  </p>
</div>

a fast, low-level NTFS USN Journal parser and anti-forensics detection engine written in pure Rust for PC checkers, screensharers, and forensic analysts.

### features
- USN journal bypass and anti-forensics detection (gap analysis, record stomping, zeroed sectors)
- journal deletion and recreation auditing (fsutil tracking, journal ID changes, size resets)
- timestomping analysis ($SI vs $FN attribute delta verification, 100ns precision truncation)
- CyberCX Rewind path reconstruction algorithm for 100% accuracy on reused MFT entries
- unallocated cluster slack carving to extract deleted ghost USN records
- hardware-accelerated desktop UI capable of rendering 500k+ records smoothly
- automated PC check presets for competitive gaming checks and triage

### requirements
- Windows 10 / 11 (64-bit)
- NTFS file system volume
- Administrator privileges (auto-elevated via UAC manifest)

### usage
simply launch `458-jt.exe`. the application automatically requests administrator elevation via UAC to obtain raw volume access (`\\.\C:`).

- **search bar**: filter file names or paths in real time. supports exact substrings, regex patterns (`r/\.dll$/`), and direct USN jumps (`#123456`).
- **source selector**: switch seamlessly between active `$UsnJrnl:$J`, volume shadow copies, and unallocated carved slack.
- **bypass checks**: click the risk badge (`[CLEAN]`, `[SUSPICIOUS]`, `[CRITICAL]`) in the top bar to inspect detected journal wipes, timestomping, rapid deletion bursts, and prefetch tampering.
- **reason filters**: toggle any of the 24 NTFS USN reason bitmasks in the sidebar or apply the one-click `PC Check Filter` preset.
- **record inspector**: click any row in the virtualized grid to view detailed attributes, MFT indices, and file metadata.
- **export**: export filtered findings to CSV or full forensic report to JSON directly from the top bar.

### building
to build the standalone release binary with embedded UAC manifest and icon:
```cmd
build.bat
```
the compiled single-file executable will be placed in `bin\458-jt.exe`.

### license
licensed under the [GNU General Public License v3.0](LICENSE).  
Copyright (c) 2026 The 458 Development Team

@echo off
rem cleaning cargo target directory
cargo clean
if exist "target" rmdir /s /q "target" 2>nul
rem cleaning bin directory and binaries
if exist "bin" rmdir /s /q "bin" 2>nul
if exist "*.old.exe" del /f /q "*.old.exe" 2>nul
echo clean complete: build artifacts removed
pause

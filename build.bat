@echo off
rem building release binary with embedded uac administrator manifest and app icon
cargo rustc --bin 458-jt --release -- -C link-arg=/MANIFEST:EMBED -C "link-arg=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
if %errorlevel% neq 0 (
    rem build failed
    exit /b %errorlevel%
)
if not exist "bin" mkdir "bin"
if exist "bin\458-jt.old.exe" del /f /q "bin\458-jt.old.exe" 2>nul
move /y "bin\458-jt.exe" "bin\458-jt.old.exe" >nul 2>nul
copy /y "target\release\458-jt.exe" "bin\458-jt.exe" >nul
del /f /q "bin\458-jt.old.exe" 2>nul
rem build complete single executable placed in bin folder
echo build successful: bin\458-jt.exe

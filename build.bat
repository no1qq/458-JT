@echo off
rem building release binary with embedded uac administrator manifest
cargo rustc --bin 458-jt --release -- -C link-arg=/MANIFEST:EMBED -C "link-arg=/MANIFESTUAC:level='requireAdministrator' uiAccess='false'"
if %errorlevel% neq 0 (
    rem build failed
    exit /b %errorlevel%
)
if not exist "bin" mkdir "bin"
copy /y "target\release\458-jt.exe" "bin\458-jt.exe" >nul
rem build complete single executable placed in bin folder with uac admin requirement
echo build successful: bin\458-jt.exe

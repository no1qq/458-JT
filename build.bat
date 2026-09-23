@echo off
rem building release binary with static crt
cargo build --release
if %errorlevel% neq 0 (
    rem build failed
    exit /b %errorlevel%
)
if not exist "bin" mkdir "bin"
copy /y "target\release\458-jt.exe" "bin\458-jt.exe" >nul
rem build complete single executable placed in bin folder
echo build successful: bin\458-jt.exe

@echo off
chcp 65001 >nul
rem ---------------------------------------------------------------------------
rem  Status check (thin wrapper -> bin\status.ps1, shared with the skill)
rem  ASCII only / NO BOM. cmd.exe treats a leading UTF-8 BOM as part of the first
rem  command, so "@echo off" would break and every line would be echoed.
rem  chcp 65001 keeps the Chinese output of the PowerShell script readable.
rem ---------------------------------------------------------------------------
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0bin\status.ps1"
set RC=%ERRORLEVEL%
echo.
pause
exit /b %RC%

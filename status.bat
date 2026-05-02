@echo off
title ExplorerWatermarkService - Status
set "BASEDIR=%~dp0"
set "NSSM=%BASEDIR%tools\nssm.exe"
set "SVCNAME=ExplorerWatermarkService"

echo ============================================
echo  ExplorerWatermarkService Status
echo ============================================
echo.

echo [Service Status]
%NSSM% status %SVCNAME% 2>nul
if %errorlevel% neq 0 (
    echo Service is not installed.
    echo Run install.bat to install.
) else (
    echo.
    echo [Recent Logs]
    if exist "%BASEDIR%bin\service.log" (
        powershell -Command "Get-Content '%BASEDIR%bin\service.log' -Tail 15"
    ) else (
        echo No log file found.
    )
)

echo.
echo ============================================
pause
@echo off
setlocal EnableDelayedExpansion
title ExplorerWatermarkService - Install

:: Request admin elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting admin privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  ExplorerWatermarkService Installer
echo ============================================
echo.

:: Get absolute path of this script's directory
set "BASEDIR=%~dp0"
set "BASEDIR=%BASEDIR:~0,-1%"

set "NSSM=%BASEDIR%\tools\nssm.exe"
set "SVCNAME=ExplorerWatermarkService"
set "SCRIPT=%BASEDIR%\bin\monitor.ps1"
set "PWRSHELL=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"

echo [INFO] BASEDIR: %BASEDIR%
echo [INFO] NSSM   : %NSSM%
echo [INFO] SCRIPT : %SCRIPT%
echo.

:: Check files exist
if not exist "%NSSM%" (
    echo [ERROR] NSSM not found: %NSSM%
    pause
    exit /b 1
)

if not exist "%SCRIPT%" (
    echo [ERROR] Script not found: %SCRIPT%
    pause
    exit /b 1
)

:: Remove old service if exists
echo [1/6] Checking old service...
%NSSM% status %SVCNAME% >nul 2>&1
if %errorlevel% equ 0 (
    echo [INFO] Service exists, removing...
    %NSSM% stop %SVCNAME% >nul 2>&1
    timeout /t 2 /nobreak >nul
    %NSSM% remove %SVCNAME% confirm >nul 2>&1
    timeout /t 2 /nobreak >nul
)

:: Install new service
echo [2/6] Installing service...
%NSSM% install %SVCNAME% "%PWRSHELL%" -NoProfile -ExecutionPolicy Bypass -File "%SCRIPT%"
if %errorlevel% neq 0 (
    echo [ERROR] Failed to install service!
    pause
    exit /b 1
)

:: Configure service
echo [3/6] Configuring service...
%NSSM% set %SVCNAME% AppDirectory "%BASEDIR%\bin"
%NSSM% set %SVCNAME% DisplayName "Explorer Watermark Clear Service"
%NSSM% set %SVCNAME% Description "Monitor explorer.exe restart and auto clear Win11 desktop watermark"
%NSSM% set %SVCNAME% Start SERVICE_AUTO_START
%NSSM% set %SVCNAME% AppStdout "%BASEDIR%\bin\stdout.log"
%NSSM% set %SVCNAME% AppStderr "%BASEDIR%\bin\stderr.log"
%NSSM% set %SVCNAME% AppRotateFiles 1
%NSSM% set %SVCNAME% AppRotateBytes 1048576

:: Start service
echo [4/6] Starting service...
%NSSM% start %SVCNAME%
timeout /t 3 /nobreak >nul

:: Verify
echo [5/6] Verifying...
%NSSM% status %SVCNAME%

echo.
echo [6/6] Done!
echo.
echo ============================================
echo  Service installed successfully!
echo ============================================
echo.
echo  Service name : %SVCNAME%
echo  Config    : %BASEDIR%\bin\config.json
echo  Log       : %BASEDIR%\bin\service.log
echo.
echo  To uninstall: run uninstall.bat
echo ============================================
echo.
pause
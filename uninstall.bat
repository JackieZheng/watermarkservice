@echo off
title ExplorerWatermarkService - Uninstall
:: Request admin elevation
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting admin privileges...
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo ============================================
echo  ExplorerWatermarkService Uninstaller
echo ============================================
echo.

set "BASEDIR=%~dp0"
set "NSSM=%BASEDIR%tools\nssm.exe"
set "SVCNAME=ExplorerWatermarkService"

:: Check if service exists
%NSSM% status %SVCNAME% >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Service is not installed. Nothing to remove.
    pause
    exit /b 0
)

:: Stop service
echo [1/3] Stopping service...
%NSSM% stop %SVCNAME% >nul 2>&1
timeout /t 3 /nobreak >nul

:: Remove service
echo [2/3] Removing service...
%NSSM% remove %SVCNAME% confirm
if %errorlevel% neq 0 (
    echo [ERROR] Failed to remove service!
    pause
    exit /b 1
)

echo.
echo [3/3] Done!
echo.
echo ============================================
echo  Service removed successfully!
echo ============================================
echo.
echo  Log files are kept in:
echo  %BASEDIR%bin\
echo.
echo  To fully remove, delete this folder:
echo  %BASEDIR%
echo ============================================
echo.
pause
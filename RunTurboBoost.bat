@echo off
title Launching PCTurboBoost

:: Check if running as admin, and if not, request elevation
net session >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Requesting administrative privileges...
    powershell.exe -NoProfile -Command "Start-Process cmd.exe -ArgumentList '/c \"\"%~f0\"\"' -Verb RunAs"
    exit /b
)

:: Run the PowerShell script with Bypass policy
echo Starting PCTurboBoost.ps1...
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0PCTurboBoost.ps1"
if %ERRORLEVEL% NEQ 0 (
    echo Error: Failed to run PCTurboBoost.ps1. Check the script or permissions.
    pause
    exit /b %ERRORLEVEL%
)

echo PCTurboBoost completed.
pause
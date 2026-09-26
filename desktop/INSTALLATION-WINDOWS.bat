@echo off
setlocal
cd /d "%~dp0"
title Emergency Delivery - Standalone Windows Build
where node >nul 2>&1
if errorlevel 1 (echo Node.js 20+ wird nur zum Erstellen des Installers benoetigt.&pause&exit /b 1)
cd desktop
call npm install
if errorlevel 1 goto error
call npm run dist
if errorlevel 1 goto error
echo.
echo FERTIG: %CD%\dist\Emergency-Delivery-Setup-1.64.0.exe
pause
exit /b 0
:error
echo BUILD FEHLGESCHLAGEN
pause
exit /b 1

@echo off
title AEGIS-SENTINEL Launcher
color 0A
echo.
echo  ======================================================
echo   [+] AEGIS-SENTINEL - Device Security Platform
echo   [+] Starting production server...
echo  ======================================================
echo.

cd /d "%~dp0"

:: Check if port 3000 is already active
netstat -ano | findstr ":3000 " >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  [OK] Server is already active on port 3000!
    goto open_browser
)

:: Attempt PM2 start first, fall back to Node
where pm2 >nul 2>&1
if %ERRORLEVEL% EQU 0 (
    echo  [+] Launching via PM2...
    pm2 start server.js --name aegis-sentinel
    goto open_browser
)

echo  [+] Launching via Node.js...
start "AEGIS-SENTINEL Server" /min node server.js

:open_browser
timeout /t 2 /nobreak >nul
echo.
echo  ======================================================
echo   [OK] Server URL: http://localhost:3000
echo  ======================================================
echo.
start http://localhost:3000
echo Server is running in background. Press any key to exit launcher window.
pause >nul

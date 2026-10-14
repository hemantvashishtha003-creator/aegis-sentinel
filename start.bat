@echo off
title AEGIS-SENTINEL Device Security & Incident Response
color 0B
echo =====================================================================
echo   AEGIS-SENTINEL: Advanced Device Security & Incident Response Suite
echo =====================================================================
echo.
echo [1/3] Verifying Node.js environment...
node -v >nul 2>&1
if %errorlevel% neq 0 (
    echo [ERROR] Node.js is not installed or not in PATH!
    echo Please install Node.js 20+ from https://nodejs.org/
    pause
    exit /b 1
)

echo [2/3] Setting production environment...
set NODE_ENV=production
set PORT=3000
set HOST=0.0.0.0

echo [3/3] Launching AEGIS-SENTINEL server...
echo.
echo =====================================================================
echo  LIVE DASHBOARD: http://localhost:3000
echo  Press Ctrl+C to stop the server at any time.
echo =====================================================================
echo.

node server.js

pause

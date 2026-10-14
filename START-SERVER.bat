@echo off
title AEGIS-SENTINEL Launcher
color 0A
echo.
echo  ╔══════════════════════════════════════════════════╗
echo  ║     AEGIS-SENTINEL  -  Security Platform         ║
echo  ║     Starting production server via PM2...        ║
echo  ╚══════════════════════════════════════════════════╝
echo.

:: Start or restart the app via PM2
pm2 start "h:\Security Gardddd\server.js" --name aegis-sentinel 2>nul
pm2 restart aegis-sentinel 2>nul
pm2 save

echo.
echo  [OK] Server running at: http://localhost:3000
echo.

:: Open the browser automatically
start http://localhost:3000

echo  To check status:  pm2 status
echo  To view logs:     pm2 logs aegis-sentinel
echo  To stop server:   pm2 stop aegis-sentinel
echo.
pause

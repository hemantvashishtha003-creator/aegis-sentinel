@echo off
title AEGIS-SENTINEL - Vercel Free Deployer
color 0B
echo.
echo  ======================================================
echo   [+] AEGIS-SENTINEL: VERCEL DEPLOYMENT (WITHOUT GITHUB)
echo   [+] Aapke software ko Vercel par live kiya ja raha hai...
echo  ======================================================
echo.

cd /d "%~dp0"

:: 1. Check Vercel CLI
where vercel >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo  [!] Vercel CLI install ho raha hai, kripya 1 minute intezaar karein...
    npm install -g vercel
)

echo.
echo  ------------------------------------------------------
echo   STEP 1: Vercel Login
echo  ------------------------------------------------------
echo  Browser mein ek page khulega, wahan apna Email ya Google se login karein.
echo.
call vercel login

echo.
echo  ------------------------------------------------------
echo   STEP 2: Deploy to Production
echo  ------------------------------------------------------
echo  Ab aapka project Vercel par bina GitHub ke upload hoga.
echo.
call vercel --prod --yes

echo.
echo  ======================================================
echo   [OK] Badhaai ho! Aapka project live ho chuka hai!
echo  ======================================================
echo.
pause

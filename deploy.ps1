# AEGIS-SENTINEL: Windows Deployment Script
Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host "🛡️  AEGIS-SENTINEL: Windows Deployment Helper" -ForegroundColor Cyan
Write-Host "==========================================================" -ForegroundColor Cyan

# 1. Check if Docker is installed
$hasDocker = Get-Command docker -ErrorAction SilentlyContinue

if ($hasDocker) {
    Write-Host "🐳 Docker detected! Deploying via Docker Compose..." -ForegroundColor Green
    
    if (-not (Test-Path -Path ".env")) {
        Write-Host "📋 Creating .env from .env.example..." -ForegroundColor Yellow
        Copy-Item -Path ".env.example" -Destination ".env"
    }

    if (-not (Test-Path -Path "data")) {
        New-Item -ItemType Directory -Path "data" | Out-Null
    }

    Write-Host "🚀 Starting Docker containers..." -ForegroundColor Green
    docker compose up -d --build
    
    Start-Sleep -Seconds 5
    docker compose ps

    Write-Host "==========================================================" -ForegroundColor Cyan
    Write-Host "✅ Docker Deployment Successful!" -ForegroundColor Green
    Write-Host "🌐 Production Gateway: http://localhost:80" -ForegroundColor White
    Write-Host "📡 Direct Port:        http://localhost:3000" -ForegroundColor White
    Write-Host "==========================================================" -ForegroundColor Cyan
} else {
    Write-Host "⚠️  Docker is not installed on this Windows system." -ForegroundColor Yellow
    Write-Host "Launching in Native Production Mode with Node.js..." -ForegroundColor Cyan
    
    # Check if .env exists
    if (-not (Test-Path -Path ".env")) {
        Copy-Item -Path ".env.example" -Destination ".env"
    }

    Write-Host "🚀 Starting AEGIS-SENTINEL directly on Node.js..." -ForegroundColor Green
    Write-Host "🌐 App URL: http://localhost:3000" -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop the server." -ForegroundColor Yellow
    
    $env:NODE_ENV = "production"
    node server.js
}

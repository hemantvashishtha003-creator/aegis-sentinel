#!/bin/bash
set -e

echo "=========================================================="
echo "🛡️  AEGIS-SENTINEL: Production Docker Deployment"
echo "=========================================================="

# Check if .env exists, if not copy from example
if [ ! -f .env ]; then
  echo "📋 Creating .env from .env.example..."
  cp .env.example .env
  
  # Generate unique cryptographic keys
  MASTER_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null || openssl rand -hex 32)
  HMAC_KEY=$(node -e "console.log(require('crypto').randomBytes(32).toString('hex'))" 2>/dev/null || openssl rand -hex 32)
  
  sed -i "s/MASTER_ENCRYPTION_KEY=.*/MASTER_ENCRYPTION_KEY=$MASTER_KEY/" .env
  sed -i "s/HMAC_SECRET=.*/HMAC_SECRET=$HMAC_KEY/" .env
  echo "🔒 Generated unique AES-256-GCM Master Key & HMAC Secret."
fi

# Create persistent data directory
mkdir -p data

# Build and start services
echo "🚀 Building and starting Docker containers..."
docker compose up -d --build

# Wait for healthy service
echo "⏳ Waiting for health check verification..."
sleep 5
docker compose ps

echo "=========================================================="
echo "✅ Deployment Successful!"
echo "🌐 Application available at: http://localhost (via Nginx)"
echo "📡 Direct App Endpoint:       http://localhost:3000"
echo "=========================================================="

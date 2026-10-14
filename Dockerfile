# ==============================================================================
# AEGIS-SENTINEL: Production Multi-Stage Hardened Dockerfile
# Base: Node.js 24 Alpine (LTS Minimal Footprint)
# ==============================================================================

FROM node:24-alpine AS base

# Install curl for container health checks
RUN apk add --no-cache curl

WORKDIR /app

# Step 1: Install production dependencies
COPY package*.json ./
RUN npm ci --omit=dev && npm cache clean --force

# Step 2: Copy application files
COPY . .

# Step 3: Create directory for persistent SQLite database and set permissions
RUN mkdir -p /app/data && chown -R node:node /app

# Switch to non-privileged node user for security defense-in-depth
USER node

# Environment defaults
ENV NODE_ENV=production \
    PORT=3000 \
    HOST=0.0.0.0 \
    DB_PATH=/app/data/security_sentinel.sqlite

# Container healthcheck
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:3000/api/stats/dashboard-stats || exit 1

EXPOSE 3000

CMD ["npm", "start"]

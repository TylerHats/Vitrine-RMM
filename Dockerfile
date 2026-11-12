# Multi-stage Docker build for Vitrine RMM v2.5.1 (linux/amd64 & linux/arm64)
# Stage 1: Build Frontend and Backend (with native better-sqlite3 toolchain)
FROM node:22-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package manifests & lockfiles for deterministic installation
COPY package.json package-lock.json* ./
COPY backend/package.json backend/package-lock.json* ./backend/
COPY frontend/package.json frontend/package-lock.json* ./frontend/

# Install workspace dependencies
RUN cd /app/backend && npm ci --no-audit
RUN cd /app/frontend && npm ci --no-audit

# Copy source trees and default branding assets
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY branding/ ./branding/

# Build production frontend & backend bundles, then prune devDependencies
RUN cd /app/frontend && npm run build
RUN cd /app/backend && npm run build && npm prune --omit=dev

# Stage 2: Minimal Production Runtime
FROM node:22-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV DATA_DIR=/app/data
ENV BRANDING_DIR=/app/branding
ENV VITRINE_DOCKER=true

# Copy pruned production backend dependencies & compiled artifacts
COPY backend/package.json ./package.json
COPY --from=builder /app/backend/node_modules ./node_modules
COPY --from=builder /app/backend/dist ./dist
COPY --from=builder /app/frontend/dist ./frontend/dist
COPY --from=builder /app/branding ./branding
COPY --from=builder /app/branding ./branding-defaults

RUN mkdir -p /app/data && chmod 700 /app/data

VOLUME ["/app/data", "/app/branding"]

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"

CMD ["node", "dist/server.js"]

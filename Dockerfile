# Multi-stage Docker build for Vitrine RMM
# Stage 1: Build Frontend and Backend
FROM node:20-slim AS builder

WORKDIR /app

# Copy root and package manifests
COPY package.json package-lock.json* ./
COPY backend/package.json ./backend/
COPY frontend/package.json ./frontend/

# Install build dependencies
RUN cd /app/backend && npm install
RUN cd /app/frontend && npm install

# Copy source trees
COPY backend/ ./backend/
COPY frontend/ ./frontend/
COPY branding/ ./branding/

# Build assets
RUN cd /app/frontend && npm run build
RUN cd /app/backend && npm run build

# Stage 2: Production Minimal Runtime
FROM node:20-slim AS runner

WORKDIR /app

ENV NODE_ENV=production
ENV PORT=8080
ENV DATA_DIR=/app/data

# Install production dependencies for backend
COPY backend/package.json ./
RUN npm install --only=production --no-audit

# Copy compiled backend and frontend distribution
COPY --from=builder /app/backend/dist ./dist
COPY --from=builder /app/frontend/dist ./frontend/dist
COPY --from=builder /app/branding ./branding

# Create volume mounts for persistent database and branding assets
VOLUME ["/app/data", "/app/branding"]

EXPOSE 8080

CMD ["node", "dist/server.js"]

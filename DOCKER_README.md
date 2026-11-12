# Vitrine RMM — Official Docker Image (`v2.5.0`)

Vitrine RMM is a modern, glassmorphic, self-hosted Remote Monitoring and Management (RMM) platform engineered for enterprise MSP fleet governance, zero-trust credential vaulting, and low-latency remote orchestration powered by MeshCentral 2.

---

## ⚡ Quickstart (`docker-compose.yml`)

Create a `docker-compose.yml` file with persistent host volumes for your SQLite database, AES-256-GCM vault key, encrypted backups, and custom white-label branding:

```yaml
services:
  vitrine-rmm:
    image: tylerhats/vitrine-rmm:latest
    container_name: vitrine-rmm
    ports:
      - "8080:8080"
    volumes:
      # Persistent SQLite WAL database, .vault-key.json, backups, and branding
      - ./data:/app/data
      - ./branding:/app/branding
    environment:
      - PORT=8080
      - DATA_DIR=/app/data
      - BRANDING_DIR=/app/branding
      - NODE_ENV=production
      - VITRINE_DOCKER=true
      # Optional: supply an explicit 64-hex-char (32-byte) master vault key via secret manager
      # - VITRINE_MASTER_KEY=your_64_char_hex_key
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:8080/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    restart: unless-stopped
```

### Launch the Container
```bash
docker compose up -d
```

Open `http://localhost:8080` in your browser to create your **Initial MSP Super Admin** account (with RFC 6238 TOTP MFA & 8 single-use recovery codes) and walk through the built-in **Setup & Reverse Proxy Wizard**.

---

## 🏷️ Image Tags & Updating

*   `tylerhats/vitrine-rmm:latest` — Latest stable production release (`v2.5.0`).
*   `tylerhats/vitrine-rmm:2.5.0` — Pinned version tag for reproducible deployments.

Because containers are immutable, Vitrine RMM automatically detects `VITRINE_DOCKER=true` in **System Settings -> System Updates** and displays update availability alongside exact `docker compose pull && docker compose up -d` upgrade commands:

```bash
docker compose pull
docker compose up -d
```

---

## 📁 Persistent Volumes & Disaster Recovery

*   `/app/data`: Stores the SQLite WAL database (`vitrine.db`, Schema v15), auto-generated master encryption key (`.vault-key.json`, `0600` permissions), and AES-256-GCM encrypted `.vrmm-backup.gz` (`VRMMENC1`) archives under `/app/data/backups`.
*   `/app/branding`: Stores custom uploaded white-label logos (`logo.png`). On first boot with an empty host bind-mount, the container automatically seeds the default Vitrine logo into `/app/branding/logo.png`.

> **Important**: Always back up `/app/data` (or configure automated encrypted backups + S3/R2/MinIO/B2 offsite sync under **Settings -> Backups & Disaster Recovery**) so both `vitrine.db` and `.vault-key.json` are preserved together.

---

## 📖 Full Documentation

*   [**GitHub Repository**](https://github.com/TylerHats/Vitrine-RMM)
*   [**Vitrine RMM GitHub Wiki**](https://github.com/TylerHats/Vitrine-RMM/wiki)

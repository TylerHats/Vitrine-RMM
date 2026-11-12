# Vitrine RMM — Official Multi-Arch Docker Image (`v2.5.1`)

Vitrine RMM is a modern, glassmorphic, self-hosted Remote Monitoring and Management (RMM) platform engineered for enterprise MSP fleet governance, zero-trust credential vaulting, OpenID Connect (`OIDC` + `S256 PKCE`) SSO, live hypervisor orchestration, and low-latency remote control powered by MeshCentral 2.

---

## 🏗️ Supported Architectures (`linux/amd64` & `linux/arm64`)

Both `tylerhats/vitrine-rmm:latest` and `tylerhats/vitrine-rmm:2.5.1` are published as **multi-architecture OCI manifests** supporting:
*   **`linux/amd64`** — Intel / AMD `x86_64` bare-metal servers, Proxmox VMs, and cloud instances.
*   **`linux/arm64`** — ARM64 servers, AWS Graviton, Oracle Ampere, Apple Silicon Docker hosts, and Raspberry Pi 5 appliances.

Docker automatically pulls the native image matching your host CPU architecture.

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
      # (LAPS_MASTER_SECRET is also supported as an alias)
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

Open `http://localhost:8080` in your browser to create your **Initial MSP Super Admin** account (with RFC 6238 TOTP MFA & 8 single-use recovery codes) and walk through the built-in **Setup, Reverse Proxy & Backup Key Escrow Wizard**.

---

## 🏷️ Image Tags & Updating

*   `tylerhats/vitrine-rmm:latest` — Latest stable multi-arch production release (`v2.5.1`, `linux/amd64` + `linux/arm64`).
*   `tylerhats/vitrine-rmm:2.5.1` — Pinned version tag for reproducible deployments (`linux/amd64` + `linux/arm64`).

Because containers are immutable, Vitrine RMM automatically detects `VITRINE_DOCKER=true` in **System Settings -> System Updates** and displays update availability alongside exact `docker compose pull && docker compose up -d` upgrade commands:

```bash
docker compose pull
docker compose up -d
```

---

## 📁 Persistent Volumes & Disaster Recovery

*   `/app/data`: Stores the SQLite WAL database (`vitrine.db`, Schema `v16`), auto-generated master encryption key (`.vault-key.json`, `0600` permissions), and AES-256-GCM encrypted `.vrmm-backup.gz` (`VRMMENC1`) archives under `/app/data/backups`.
*   `/app/branding`: Stores custom uploaded white-label logos (`logo.png`). On first boot with an empty host bind-mount, the container automatically seeds the default Vitrine logo into `/app/branding/logo.png`.

> **Important**: Store your **Backup Encryption Recovery Key** offline in your password vault! Super Admins can reveal, copy, or download a `.txt` escrow copy at any time via **Settings -> Backups -> Reveal / Export Backup Recovery Key** (Step-Up MFA-gated).

---

## 📖 Full Documentation

*   [**GitHub Repository**](https://github.com/TylerHats/Vitrine-RMM)
*   [**Vitrine RMM GitHub Wiki**](https://github.com/TylerHats/Vitrine-RMM/wiki)

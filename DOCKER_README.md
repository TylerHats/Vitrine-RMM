# Vitrine RMM — Official Multi-Arch Docker Image (`v2.8.0`)

Vitrine RMM is a modern, glassmorphic, self-hosted Remote Monitoring and Management (RMM) platform engineered for enterprise MSP fleet governance, zero-trust credential vaulting, OpenID Connect (`OIDC` + `S256 PKCE`) SSO, native 6-section UCRT Windows PE & C++17 POSIX WSS agents, broadened bidirectional ITFlow & PSA integration, live hypervisor orchestration, and low-latency remote control powered by MeshCentral 2.

---

## 🏗️ Supported Architectures (`linux/amd64` & `linux/arm64`)

Both `tylerhats/vitrine-rmm:latest` and `tylerhats/vitrine-rmm:2.8.0` are published as **multi-architecture OCI manifests** supporting:
*   **`linux/amd64`** — Intel / AMD `x86_64` bare-metal servers, Proxmox VMs, and cloud instances.
*   **`linux/arm64`** — ARM64 servers, AWS Graviton, Oracle Ampere, Apple Silicon Docker hosts, and Raspberry Pi 5 appliances.

Both architecture images pre-compile all **5 native 64-bit Windows PE executable templates** (`vitrine-installer-template.exe`, `vitrine-companion-setup-template.exe`, `vitrine-quicksupport-template.exe`, `vitrine-companion-template.exe`, and `vitrine-tray-template.exe`) via **Clang + LLD + MinGW-w64 UCRT** AND pre-compile all **4 unified C++17 Linux native agents** (`vitrine-agent-linux-x86_64`, `vitrine-agent-linux-headless-x86_64`, `vitrine-agent-linux-arm64`, and `vitrine-agent-linux-headless-arm64`) for click-to-run **`.deb` / `.rpm` GUI installers**, **Headless `.sh`**, and persistent **WSS (`/ws/agent`) + HTTP fallback** — so runtime downloads require zero compiler overhead. *(Note: macOS native binaries require Apple's proprietary `MacOSX.sdk` and can be built via `osxcross` or supplied via `backend/posix-agent/prebuilt/vitrine-agent-macos-universal`.)*

Docker automatically pulls the native image matching your host CPU architecture.

---

## ⚡ Quickstart (`docker-compose.yml`)

Use Docker named volumes (`vitrine_data` and `vitrine_branding`) so Docker initializes `/app/data` and `/app/branding` with `node:node` (`1000:1000`) ownership automatically:

```yaml
services:
  vitrine-rmm:
    image: tylerhats/vitrine-rmm:latest
    container_name: vitrine-rmm
    ports:
      - "8080:8080"
    volumes:
      # Named volumes are populated from the image with `node:node` ownership so `USER node` never hits EACCES
      - vitrine_data:/app/data
      - vitrine_branding:/app/branding
    environment:
      - PORT=8080
      - DATA_DIR=/app/data
      - BRANDING_DIR=/app/branding
      - NODE_ENV=production
      - VITRINE_DOCKER=true
      # Enable VITRINE_TRUST_PROXY=true ONLY when running behind a trusted reverse proxy (Caddy/Nginx/Traefik/Cloudflare Tunnel)
      # - VITRINE_TRUST_PROXY=true
      # - VITRINE_PUBLIC_URL=https://rmm.example.com
      # Optional: supply an explicit 64-hex-char (32-byte) master vault key via secret manager
      # (LAPS_MASTER_SECRET is also supported as an alias)
      # - VITRINE_MASTER_KEY=your_64_char_hex_key
      # - VITRINE_ALLOW_PRIVATE_OIDC=true
    healthcheck:
      test: ["CMD", "node", "-e", "fetch('http://127.0.0.1:' + (process.env.PORT || 8080) + '/api/health').then(r => process.exit(r.ok ? 0 : 1)).catch(() => process.exit(1))"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 15s
    restart: unless-stopped

volumes:
  vitrine_data:
  vitrine_branding:
```

### Using Host Bind Mounts Instead of Named Volumes
If you prefer host bind mounts (`./data:/app/data` and `./branding:/app/branding`), **pre-create both directories and assign UID/GID `1000:1000`** before starting the container so unprivileged `USER node` never encounters `EACCES`:
```bash
mkdir -p data branding
sudo chown -R 1000:1000 data branding
```

### Launch the Container
```bash
docker compose up -d
```

### Optional Co-Packaged MeshCentral 2 Stack (`--profile full-stack`)
The repository `docker-compose.yml` includes an optional, isolated MeshCentral 2 service (`vitrine-meshcentral`) under the `full-stack` profile:
```bash
MESHCENTRAL_HOSTNAME=mesh.example.com docker compose --profile full-stack up -d
```
*   **Container-to-Container URL**: Inside Vitrine's Setup Wizard or Settings, connect using `https://meshcentral:443`.
*   **Framing (`ALLOW_FRAMING`)**: The `full-stack` profile sets `ALLOW_FRAMING=true` so MeshCentral desktop/remote sessions embed cleanly inside Vitrine.
*   **Self-Signed TLS**: Inside the isolated Docker network, MeshCentral serves a self-signed certificate on `https://meshcentral:443` by default — enable the **Allow Self-Signed TLS** checkbox in Vitrine's MeshCentral settings/wizard (or set `MESHCENTRAL_ALLOW_SELF_SIGNED=true` on the `vitrine-rmm` service).
*   **Post-Setup Lockdown**: Once you create your MeshCentral administrator account and mint a Login Token for Vitrine, set `MESHCENTRAL_ALLOW_NEW_ACCOUNTS=false` and recreate the `meshcentral` container (`docker compose --profile full-stack up -d`) so public MeshCentral account registration is closed.

### First-Run Bootstrap & Sign-In
Open `http://localhost:8080` in your browser:
1. **Initial MSP Super Admin & Mandatory TOTP Verification**: Create your Super Admin account, scan the generated QR code (or save the Base32 secret and 8 single-use recovery codes), and **verify a 6-digit TOTP code** before entering the guided Setup Wizard.
2. **Enforced MFA & OIDC SSO**: Subsequent password logins enforce the **TOTP / single-use recovery-code MFA challenge**. When OpenID Connect (`S256 PKCE`) is configured, the login screen also displays a one-click **`Sign in with SSO`** button.

---

## 🏷️ Image Tags & Updating

*   `tylerhats/vitrine-rmm:latest` — Latest stable multi-arch production release (`v2.8.0`, `linux/amd64` + `linux/arm64`).
*   `tylerhats/vitrine-rmm:2.8.0` — Pinned version tag for reproducible deployments (`linux/amd64` + `linux/arm64`).

Because containers are immutable, Vitrine RMM automatically detects `VITRINE_DOCKER=true` in **Settings -> Updates & System Backups** and displays update availability alongside exact upgrade commands:

```bash
docker compose pull
docker compose up -d
```

---

## 🔧 Environment Variables Reference

| Variable | Default | Description |
| :--- | :--- | :--- |
| `PORT` | `8080` | HTTP listen port for Fastify control plane and healthcheck. |
| `HOST` | `0.0.0.0` | Network bind address inside the container. |
| `DATA_DIR` | `/app/data` | Persistent storage directory for SQLite WAL DB, vault key, backups, recordings, packages, and signed agents. |
| `BRANDING_DIR` | `/app/branding` | Persistent storage directory for custom white-label logos (`logo.png` seeded on first boot if empty). |
| `NODE_ENV` | `production` | Runtime mode (`production` disables cross-port localhost dev CORS and enforces production OIDC HTTPS checks). |
| `VITRINE_DOCKER` | `true` | Enables container-mode detection in System Updates (prevents in-place git self-pull inside immutable images). |
| `VITRINE_TRUST_PROXY` | `false` | Set `true` **only** behind a trusted reverse proxy (`Nginx`, `Caddy`, `Traefik`, `Cloudflare Tunnel`) to honor `X-Forwarded-*` headers. |
| `VITRINE_PUBLIC_URL` | *(unset)* | Explicit external base URL (e.g., `https://rmm.example.com`) used when generating agent enrollment/callback links. |
| `VITRINE_ALLOWED_ORIGINS` | *(unset)* | Comma-separated extra CORS/WebSocket `Origin` allowlist entries beyond same-host and configured `custom_domain`. |
| `VITRINE_MASTER_KEY` / `LAPS_MASTER_SECRET` | *(auto `.vault-key.json`)* | Optional explicit master key (min 16 chars; 64-hex-char 32-byte recommended) overriding `.vault-key.json` for secret-manager key injection. |
| `VITRINE_ALLOW_PRIVATE_OIDC` | `false` | Set `true` to allow OIDC discovery/token/JWKS endpoints on RFC1918/ULA private LAN addresses (HTTPS still required in production). |
| `FORCE_SECURE_COOKIE` | `false` | Forces `Secure` flag on `vitrine_session` cookies regardless of TLS termination headers. |
| `MESHCENTRAL_ALLOW_SELF_SIGNED` | `false` | Global override allowing self-signed TLS certificates when connecting to MeshCentral 2 servers. |
| `SMTP_ALLOW_SELF_SIGNED` | `false` | Global override allowing self-signed TLS certificates on outbound SMTP relays. |
| `CODE_SIGNING_URL` | *(unset)* | Default HTTP/HTTPS URL for the 3-stage Authenticode / RFC 3161 signing microservice (`POST /sign`). |
| `CODE_SIGNING_API_KEY` | *(unset)* | Default `Bearer` token sent to `CODE_SIGNING_URL` if not overridden in Settings. |
| `VITRINE_GITHUB_REPO` | `TylerHats/Vitrine-RMM` | GitHub `owner/repo` slug queried by the System Updates catalog checker. |

---

## 📁 Persistent Volumes & Disaster Recovery (`/app/data` & `/app/branding`)

*   `/app/data` (`chmod 700` inside container):
    *   `vitrine.db`: SQLite WAL database (Schema `v19`).
    *   `.vault-key.json`: Auto-generated instance master secret & KDF salt (`0600` permissions, unless overridden by `VITRINE_MASTER_KEY` / `LAPS_MASTER_SECRET`).
    *   `install-meta.json`: Installed version/commit metadata created by bare-metal installs (optional in Docker).
    *   `backups/`: Scheduled, manual, and pre-upgrade AES-256-GCM `.vrmm-backup.gz` (`VRMMENC1`) archives.
    *   `recordings/`: WebM remote session captures and compliance metadata.
    *   `packages/`: Uploaded MSI/DEB/binary software packages served to endpoints.
    *   `signed-agents/`: Authenticode verification metadata and signed MeshCentral 2 agent binary cache (`0700`).
    *   `signing-staging/`: Temporary `0700` staging directory used during 3-stage PowerShell script signing.
*   `/app/branding`: Stores custom uploaded white-label logos (`logo.png`). On first boot with an empty volume/bind-mount, the container automatically seeds the default Vitrine logo from `/app/branding-defaults/logo.png`.

> **Important**: Store your **Backup Encryption Recovery Key** offline in your password vault! Super Admins can reveal, copy, or download a `.txt` escrow copy at any time via **Settings -> Updates & System Backups -> Reveal / Export Recovery Key (MFA)**.

---

## 📖 Full Documentation

*   [**GitHub Repository**](https://github.com/TylerHats/Vitrine-RMM)
*   [**Vitrine RMM GitHub Wiki**](https://github.com/TylerHats/Vitrine-RMM/wiki)

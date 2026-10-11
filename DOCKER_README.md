# Vitrine RMM

Vitrine RMM is a modern, glassmorphic, self-hosted Remote Monitoring and Management (RMM) platform engineered as a next-generation orchestration frontend powered by MeshCentral 2 as its remote execution and communication engine.

This repository hosts the official Docker image for Vitrine RMM.

---

## ⚡ Quickstart (Docker Compose)

The easiest and most reliable way to run Vitrine RMM is using Docker Compose. Create a `docker-compose.yml` file with the following configuration:

```yaml
version: '3.8'

services:
  vitrine-rmm:
    image: tylerhats/vitrine-rmm:latest
    container_name: vitrine-rmm
    ports:
      - "8080:8080"
    volumes:
      # Keep your database, LAPS vault, and custom white-label branding safe on the host
      - ./data:/app/data
      - ./branding:/app/branding
    environment:
      - PORT=8080
      - DATA_DIR=/app/data
      - NODE_ENV=production
    restart: unless-stopped
```

### Running the Container

Once you have created the `docker-compose.yml` file, launch Vitrine RMM in detached mode:

```bash
docker compose up -d
```

Vitrine RMM will be accessible on your host machine at `http://localhost:8080`.

---

## 📁 Persistent Volumes & Configuration

To ensure your fleet telemetry, LAPS credential vault, policies, and white-labeling configurations persist across container restarts or image updates, ensure the following directories are mounted:

*   `/app/data`: Houses the SQLite database file (`vitrine.db`), policy hierarchies, and AES-256 encrypted LAPS vaults.
*   `/app/branding`: Houses your customized company logos (`logo.png`) and application icons.

---

## 📖 Detailed Documentation & GitHub Wiki

For complete instructions on connecting to external MeshCentral 2 servers, setting up Authentik / OpenID Connect SSO, configuring silent background tools, deploying Windows/Linux/macOS agents, and setting up Two-Way ITFlow PSA sync, please refer to the official documentation:

*   [Vitrine RMM GitHub Wiki Documentation](https://github.com/TylerHats/Vitrine-RMM/wiki)

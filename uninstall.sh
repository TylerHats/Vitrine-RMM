#!/usr/bin/env bash

# Exit immediately on command failure or unset variable errors
set -euo pipefail

PROJ_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$PROJ_ROOT"

RESOLVED_DATA_DIR="${DATA_DIR:-$PROJ_ROOT/data}"
RESOLVED_BRANDING_DIR="${BRANDING_DIR:-$PROJ_ROOT/branding}"

LOCAL_MS2_FOUND=0
LOCAL_MS2_DIR=""
LOCAL_MS2_SERVICE=""

detect_local_meshcentral() {
    LOCAL_MS2_FOUND=0
    LOCAL_MS2_DIR=""
    LOCAL_MS2_SERVICE=""

    local canon_proj
    canon_proj="$(cd "$PROJ_ROOT" 2>/dev/null && pwd -P || printf '%s' "$PROJ_ROOT")"

    if command -v systemctl &> /dev/null; then
        local unit_files line unit_name unit_cfg wd
        unit_files="$(systemctl list-unit-files --no-pager 2>/dev/null || true)"
        while IFS= read -r line; do
            unit_name="${line%%[[:space:]]*}"
            if [[ -n "$unit_name" && "$unit_name" != "vitrine-rmm.service" && "$unit_name" == *meshcentral*.service ]]; then
                LOCAL_MS2_FOUND=1
                LOCAL_MS2_SERVICE="$unit_name"
                unit_cfg="$(systemctl cat "$unit_name" 2>/dev/null || true)"
                wd="$(printf '%s\n' "$unit_cfg" | sed -n 's/^WorkingDirectory=//p' | head -n 1 | sed 's/^"//; s/"$//')"
                if [ -n "$wd" ] && [ -d "$wd" ]; then
                    LOCAL_MS2_DIR="$(cd "$wd" 2>/dev/null && pwd -P || printf '%s' "$wd")"
                fi
                break
            fi
        done <<< "$unit_files"
    fi

    if [ "$LOCAL_MS2_FOUND" -eq 0 ] && command -v pgrep &> /dev/null; then
        local proc_lines pline
        proc_lines="$(pgrep -af "node.*meshcentral" 2>/dev/null || true)"
        while IFS= read -r pline; do
            if [ -n "$pline" ] && [[ "$pline" != *"$canon_proj"* ]] && [[ "$pline" != *"dev-meshcentral"* ]]; then
                LOCAL_MS2_FOUND=1
                break
            fi
        done <<< "$proc_lines"
    fi

    if [ "$LOCAL_MS2_FOUND" -eq 0 ] || [ -z "$LOCAL_MS2_DIR" ]; then
        local candidates=(
            "/opt/meshcentral"
            "/var/lib/meshcentral"
            "/srv/meshcentral"
            "/usr/local/meshcentral"
            "/root/meshcentral"
            "/root"
        )
        local hdir
        for hdir in /home/*; do
            if [ -d "$hdir" ]; then
                candidates+=("$hdir" "$hdir/meshcentral")
            fi
        done

        local cand resolved_cand
        for cand in "${candidates[@]}"; do
            [ -d "$cand" ] || continue
            resolved_cand="$(cd "$cand" 2>/dev/null && pwd -P || true)"
            [ -n "$resolved_cand" ] || continue
            if [ "$resolved_cand" = "$canon_proj" ] || [[ "$resolved_cand" == "$canon_proj/"* ]]; then
                continue
            fi
            if [ -f "$resolved_cand/node_modules/meshcentral/meshctrl.js" ] || [ -f "$resolved_cand/meshcentral-data/config.json" ]; then
                LOCAL_MS2_FOUND=1
                if [ -z "$LOCAL_MS2_DIR" ]; then
                    LOCAL_MS2_DIR="$resolved_cand"
                fi
                break
            fi
        done
    fi
}

detect_local_meshcentral

echo "=========================================================="
echo "             Vitrine RMM Uninstallation Script            "
echo "=========================================================="
echo "This script will cleanly remove Vitrine RMM from your system."
if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
    echo "SAFETY GUARANTEE: Local MeshCentral 2 services (${LOCAL_MS2_DIR:-$LOCAL_MS2_SERVICE}),"
    echo "databases, certificates, and agents will NOT be touched."
fi
echo "=========================================================="
echo ""

run_priv() {
    if [ "$(id -u)" -eq 0 ]; then
        "$@"
    else
        sudo "$@"
    fi
}

find_vitrine_pids() {
    local canon_proj pid_dir pid cmd cwd
    canon_proj="$(cd "$PROJ_ROOT" 2>/dev/null && pwd -P || printf '%s' "$PROJ_ROOT")"
    local matches=()

    if [ -d /proc ]; then
        for pid_dir in /proc/[0-9]*; do
            pid="${pid_dir##*/}"
            if [ "$pid" = "$$" ]; then
                continue
            fi
            [ -r "$pid_dir/cmdline" ] || continue
            cmd="$(tr '\0' ' ' < "$pid_dir/cmdline" 2>/dev/null || true)"
            [ -n "$cmd" ] || continue
            if [[ "$cmd" == *"$canon_proj/backend/dist/server.js"* ]] || [[ "$cmd" == *"$canon_proj/backend/src/server.ts"* ]]; then
                matches+=("$pid")
                continue
            fi
            if [[ "$cmd" == *"dist/server.js"* ]] || [[ "$cmd" == *"src/server.ts"* ]]; then
                cwd="$(readlink -f "$pid_dir/cwd" 2>/dev/null || true)"
                if [ "$cwd" = "$canon_proj" ] || [[ "$cwd" == "$canon_proj/"* ]]; then
                    matches+=("$pid")
                fi
            fi
        done
    elif command -v pgrep &> /dev/null; then
        local escaped_root
        escaped_root="$(printf '%s' "$canon_proj" | sed 's/[][\\.^$*+?(){}|]/\\&/g')"
        while IFS= read -r pid; do
            [ -n "$pid" ] && matches+=("$pid")
        done < <(pgrep -f "${escaped_root}/backend/(dist/server\\.js|src/server\\.ts)" 2>/dev/null || true)
    fi

    if [ "${#matches[@]}" -gt 0 ]; then
        printf '%s\n' "${matches[@]}"
    fi
}

VITRINE_STOPPED=0
stop_vitrine_processes() {
    if [ "$VITRINE_STOPPED" -eq 1 ]; then
        return 0
    fi
    if [ -f /etc/systemd/system/vitrine-rmm.service ] && command -v systemctl &> /dev/null; then
        if systemctl is-active --quiet vitrine-rmm.service 2>/dev/null; then
            echo "--> Stopping vitrine-rmm.service cleanly..."
            run_priv systemctl stop vitrine-rmm.service || true
        fi
    fi

    local pids=()
    while IFS= read -r p; do
        [ -n "$p" ] && pids+=("$p")
    done < <(find_vitrine_pids)

    if [ "${#pids[@]}" -gt 0 ]; then
        echo "--> Stopping active Vitrine RMM Node.js server process(es) (${pids[*]})..."
        local pid
        for pid in "${pids[@]}"; do
            kill -TERM "$pid" 2>/dev/null || run_priv kill -TERM "$pid" 2>/dev/null || true
        done
        local waited=0
        while [ "$waited" -lt 10 ]; do
            local still_alive=0
            for pid in "${pids[@]}"; do
                if kill -0 "$pid" 2>/dev/null || run_priv kill -0 "$pid" 2>/dev/null; then
                    still_alive=1
                    break
                fi
            done
            [ "$still_alive" -eq 0 ] && break
            sleep 0.5
            waited=$((waited + 1))
        done
        for pid in "${pids[@]}"; do
            if kill -0 "$pid" 2>/dev/null || run_priv kill -0 "$pid" 2>/dev/null; then
                echo "    [!] Process $pid did not exit after SIGTERM; sending SIGKILL..."
                kill -KILL "$pid" 2>/dev/null || run_priv kill -KILL "$pid" 2>/dev/null || true
            fi
        done
    fi
    VITRINE_STOPPED=1
}

# 0. Optional Vitrine-companion-only cleanup across connected endpoints (never touches MeshAgent)
if [ -t 0 ] && [ -f "$PROJ_ROOT/backend/dist/services/meshcentral/index.js" ] && [ -f "$RESOLVED_DATA_DIR/vitrine.db" ] && command -v node &> /dev/null; then
    REMOVE_ENDPOINTS="n"
    echo "Optional: Remove the Vitrine companion agent, tray, and scheduled tasks from connected endpoints?"
    echo "  (Note: MeshCentral 2 MeshAgent services, certificates, and remote tunnels remain untouched.)"
    read -p "Push Vitrine companion removal to online/isolated endpoints before uninstalling? [y/N]: " -n 1 -r
    echo ""
    REMOVE_ENDPOINTS="${REPLY:-n}"
    if [[ "$REMOVE_ENDPOINTS" =~ ^[Yy]$ ]]; then
        # Stop running Vitrine service/processes first so two processes never access SQLite WAL concurrently
        stop_vitrine_processes
        echo "--> Connecting to MeshCentral bridge to remove Vitrine-only companion artifacts..."
        (
            cd "$PROJ_ROOT/backend" && \
            NODE_ENV="${NODE_ENV:-production}" \
            DATA_DIR="$RESOLVED_DATA_DIR" \
            BRANDING_DIR="$RESOLVED_BRANDING_DIR" \
            node --input-type=module -e '
              import { db, initDatabase, closeDatabase } from "./dist/db/index.js";
              import { meshBridge } from "./dist/services/meshcentral/index.js";
              let timeout = setTimeout(() => { console.error("    Endpoint cleanup timed out."); try { closeDatabase(); } catch {} process.exit(0); }, 45000);
              timeout.unref();
              try {
                try { initDatabase(); } catch {}
                const cols = new Set((db.prepare("PRAGMA table_info(devices)").all() || []).map((c) => c.name));
                const condParts = ["agent_auth_token IS NOT NULL"];
                if (cols.has("companion_installed")) condParts.push("COALESCE(companion_installed, 0) = 1");
                if (cols.has("companion_deploy_pending")) condParts.push("COALESCE(companion_deploy_pending, 0) = 1");
                const lifecycleExpr = cols.has("lifecycle_state") ? "COALESCE(lifecycle_state, '\''active'\'') = '\''active'\''" : "1=1";
                const devs = db.prepare(`
                  SELECT id, hostname, status, mesh_node_id
                  FROM devices
                  WHERE mesh_node_id IS NOT NULL
                    AND ${lifecycleExpr}
                    AND (${condParts.join(" OR ")})
                `).all();
                clearTimeout(timeout);
                timeout = setTimeout(() => { console.error("    Endpoint cleanup timed out."); try { closeDatabase(); } catch {} process.exit(0); }, Math.max(45000, devs.length * 4000));
                timeout.unref();
                if (!devs.length) {
                  console.log("    No Vitrine companion endpoints registered.");
                } else {
                  const connOk = await meshBridge.reconnectAndWait(4500);
                  if (!connOk) {
                    console.log("    MeshCentral bridge offline (" + (meshBridge.getStatus().lastError || "not connected") + "). Skipping endpoint cleanup.");
                  } else {
                    let cleaned = 0, skipped = 0;
                    for (const d of devs) {
                      if (d.status !== "online" && d.status !== "isolated") { skipped++; continue; }
                      const res = await meshBridge.removeVitrineCompanionOnlyOverMesh(d.id);
                      if (res.live) { cleaned++; console.log("    [OK] Cleaned Vitrine companion on " + d.hostname); }
                      else { skipped++; console.log("    [WARN] Failed on " + d.hostname + ": " + res.output); }
                    }
                    console.log("    Companion cleanup summary: " + cleaned + " endpoint(s) cleaned, " + skipped + " offline/skipped.");
                  }
                }
              } catch (err) {
                console.error("    Endpoint cleanup skipped:", err?.message || err);
              } finally {
                clearTimeout(timeout);
                try { await closeDatabase(); } catch {}
              }
              process.exit(0);
            '
        ) || true
    fi
fi

# 1. Stop and remove ONLY vitrine-rmm.service (never touch neighboring MeshCentral services)
stop_vitrine_processes

if [ -f /etc/systemd/system/vitrine-rmm.service ]; then
    echo "--> Removing vitrine-rmm.service systemd unit..."
    run_priv systemctl disable vitrine-rmm.service || true
    run_priv rm -f /etc/systemd/system/vitrine-rmm.service
    run_priv systemctl daemon-reload
    echo "--> vitrine-rmm systemd service removed."
fi

if [ -n "$LOCAL_MS2_SERVICE" ]; then
    echo "--> Verified: Neighboring ${LOCAL_MS2_SERVICE} remains intact and untouched."
elif command -v systemctl &> /dev/null; then
    UNIT_FILES="$(systemctl list-unit-files --no-pager 2>/dev/null || true)"
    if [[ "$UNIT_FILES" == *"meshcentral"* ]]; then
        echo "--> Verified: Neighboring MeshCentral service(s) remain intact and untouched."
    fi
fi

# 2. Clean Vitrine build artifacts, dist bundles, and workspace node_modules
echo "--> Cleaning Vitrine build artifacts and dependencies..."
rm -rf "$PROJ_ROOT/frontend/dist" "$PROJ_ROOT/backend/dist" 2>/dev/null || run_priv rm -rf "$PROJ_ROOT/frontend/dist" "$PROJ_ROOT/backend/dist" || true
rm -rf "$PROJ_ROOT/node_modules" "$PROJ_ROOT/backend/node_modules" "$PROJ_ROOT/frontend/node_modules" 2>/dev/null || run_priv rm -rf "$PROJ_ROOT/node_modules" "$PROJ_ROOT/backend/node_modules" "$PROJ_ROOT/frontend/node_modules" || true

TARGET_USER="${SUDO_USER:-$(id -un)}"
TARGET_GROUP="$(id -gn "$TARGET_USER" 2>/dev/null || id -gn)"
TARGET_HOME="$(getent passwd "$TARGET_USER" 2>/dev/null | cut -d: -f6 || true)"
if [ -z "$TARGET_HOME" ] || [ ! -d "$TARGET_HOME" ]; then
    TARGET_HOME="${HOME:-/tmp}"
fi
if [ "$(id -u)" -ne 0 ] && [ ! -w "$TARGET_HOME" ]; then
    TARGET_HOME="${HOME:-/tmp}"
fi
if [ ! -d "$TARGET_HOME" ] || ( [ "$(id -u)" -ne 0 ] && [ ! -w "$TARGET_HOME" ] ); then
    TARGET_HOME="/tmp"
fi

# 3. Optional pre-uninstall backup export & database/branding/dev-meshcentral wipe
if [ -d "$RESOLVED_DATA_DIR" ] || [ -d "$RESOLVED_BRANDING_DIR" ]; then
    EXPORT_BAK="n"
    DELETE_DATA="n"

    if [ -t 0 ]; then
        read -p "Would you like to export a final backup archive before deciding on data removal? (y/n): " -n 1 -r
        echo ""
        EXPORT_BAK="$REPLY"
    fi

    if [[ "$EXPORT_BAK" =~ ^[Yy]$ ]]; then
        FINAL_BAK="${TARGET_HOME}/vitrine-rmm-final-backup-$(date +%Y%m%d-%H%M%S).tar.gz"
        TAR_ARGS=()
        if [ -d "$RESOLVED_DATA_DIR" ]; then
            TAR_ARGS+=(-C "$(dirname "$RESOLVED_DATA_DIR")" "$(basename "$RESOLVED_DATA_DIR")")
        fi
        if [ -d "$RESOLVED_BRANDING_DIR" ]; then
            TAR_ARGS+=(-C "$(dirname "$RESOLVED_BRANDING_DIR")" "$(basename "$RESOLVED_BRANDING_DIR")")
        fi
        if [ "${#TAR_ARGS[@]}" -gt 0 ]; then
            (umask 077 && tar -czf "$FINAL_BAK" "${TAR_ARGS[@]}")
            chmod 600 "$FINAL_BAK"
            if [ "$(id -u)" -eq 0 ] && [ "$TARGET_USER" != "root" ]; then
                chown "$TARGET_USER:$TARGET_GROUP" "$FINAL_BAK" || true
            fi
            echo "--> Saved restricted (0600) final backup archive to: $FINAL_BAK"
            echo "    [SECURITY NOTICE] This .tar.gz archive is UNENCRYPTED and contains data/.vault-key.json"
            echo "                      (master vault key) and vitrine.db. Move it to encrypted offline storage"
            echo "                      or shred/delete it after migration."
        fi
    fi

    if [ -t 0 ]; then
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            read -p "Would you like to delete Vitrine's local data/ and custom uploaded branding assets (vitrine.db & vault key)? Local MeshCentral data will NOT be affected. (y/n): " -n 1 -r
        else
            read -p "Would you like to delete Vitrine's local data/ and custom uploaded branding assets (vitrine.db & vault key)? (y/n): " -n 1 -r
        fi
        echo ""
        DELETE_DATA="$REPLY"
    fi

    if [[ "$DELETE_DATA" =~ ^[Yy]$ ]]; then
        if [[ -n "$PROJ_ROOT" && "$PROJ_ROOT" != "/" && -f "$PROJ_ROOT/uninstall.sh" ]]; then
            echo "--> Removing Vitrine data directory ($RESOLVED_DATA_DIR)..."
            rm -rf "$RESOLVED_DATA_DIR" 2>/dev/null || run_priv rm -rf "$RESOLVED_DATA_DIR"

            if [ -d "$RESOLVED_BRANDING_DIR" ]; then
                if [ -d "$PROJ_ROOT/.git" ] && [ "$RESOLVED_BRANDING_DIR" = "$PROJ_ROOT/branding" ] && command -v git &> /dev/null; then
                    echo "--> Cleaning custom uploads in branding/ while preserving git-tracked repository defaults..."
                    git -C "$PROJ_ROOT" clean -fdX -- branding/ 2>/dev/null || true
                    git -C "$PROJ_ROOT" clean -fd -- branding/ 2>/dev/null || true
                    git -C "$PROJ_ROOT" checkout -- branding/ 2>/dev/null || true
                else
                    echo "--> Removing branding directory ($RESOLVED_BRANDING_DIR)..."
                    rm -rf "$RESOLVED_BRANDING_DIR" 2>/dev/null || run_priv rm -rf "$RESOLVED_BRANDING_DIR"
                fi
            fi
            echo "--> Vitrine database, local vaults, and custom branding uploads deleted."
        fi
    else
        echo "--> Keeping data directory ($RESOLVED_DATA_DIR) for future upgrades or restores."
    fi
fi

if [ -d "$PROJ_ROOT/dev-meshcentral" ] && [ -t 0 ]; then
    DELETE_DEV_MS2="n"
    read -p "Detected local dev-meshcentral/ directory inside $PROJ_ROOT. Delete dev-meshcentral/? [y/N]: " -n 1 -r
    echo ""
    DELETE_DEV_MS2="${REPLY:-n}"
    if [[ "$DELETE_DEV_MS2" =~ ^[Yy]$ ]]; then
        rm -rf "$PROJ_ROOT/dev-meshcentral" 2>/dev/null || run_priv rm -rf "$PROJ_ROOT/dev-meshcentral"
        echo "--> Removed $PROJ_ROOT/dev-meshcentral."
    else
        echo "--> Keeping $PROJ_ROOT/dev-meshcentral."
    fi
fi

# 4. Optional full installation directory removal (only when local data/ has been removed or absent)
REMOVE_DIR="n"
CANON_ROOT=""
SAFE_TO_REMOVE_DIR=0

if [ ! -d "$RESOLVED_DATA_DIR" ]; then
    CANON_ROOT="$(cd "$PROJ_ROOT" 2>/dev/null && pwd -P || true)"
    SAFE_TO_REMOVE_DIR=1

    if [ -z "$CANON_ROOT" ] || [ "$CANON_ROOT" = "/" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    if [ -n "${HOME:-}" ] && [ "$CANON_ROOT" = "${HOME%/}" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    if [ -n "$TARGET_HOME" ] && [ "$CANON_ROOT" = "${TARGET_HOME%/}" ]; then
        SAFE_TO_REMOVE_DIR=0
    fi
    case "$CANON_ROOT" in
        /root|/home|/opt|/usr|/var|/etc|/tmp|/srv|/opt/meshcentral|/opt/meshcentral/*)
            SAFE_TO_REMOVE_DIR=0
            ;;
    esac
    if [ -n "$LOCAL_MS2_DIR" ]; then
        if [ "$CANON_ROOT" = "$LOCAL_MS2_DIR" ] || [[ "$CANON_ROOT" == "$LOCAL_MS2_DIR/"* ]] || [[ "$LOCAL_MS2_DIR" == "$CANON_ROOT/"* ]]; then
            SAFE_TO_REMOVE_DIR=0
        fi
    fi
    if [ ! -f "$CANON_ROOT/uninstall.sh" ] || [ ! -f "$CANON_ROOT/package.json" ] || [ ! -d "$CANON_ROOT/backend" ] || [ ! -d "$CANON_ROOT/frontend" ]; then
        SAFE_TO_REMOVE_DIR=0
    elif ! grep -q '"name":[[:space:]]*"vitrine-rmm"' "$CANON_ROOT/package.json" 2>/dev/null; then
        SAFE_TO_REMOVE_DIR=0
    fi

    if [ "$SAFE_TO_REMOVE_DIR" -eq 1 ] && [ -t 0 ]; then
        echo ""
        read -p "Would you like to completely remove the Vitrine RMM installation folder ($CANON_ROOT)? (y/n): " -n 1 -r
        echo ""
        REMOVE_DIR="$REPLY"
    fi
fi

{
    if [[ "$REMOVE_DIR" =~ ^[Yy]$ ]] && [ "$SAFE_TO_REMOVE_DIR" -eq 1 ] && [ -n "$CANON_ROOT" ]; then
        cd /
        echo "--> Removing Vitrine RMM installation folder ($CANON_ROOT)..."
        rm -rf "$CANON_ROOT" 2>/dev/null || run_priv rm -rf "$CANON_ROOT"
        echo "--> Completely removed $CANON_ROOT."
        echo ""
        echo "=========================================================="
        echo "Vitrine RMM has been cleanly uninstalled."
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            echo "All local MeshCentral 2 services and files remain intact."
        fi
        echo "Note: If your terminal was inside that folder, run 'cd ~' to refresh your working directory."
        echo "=========================================================="
    else
        echo ""
        echo "=========================================================="
        echo "Vitrine RMM has been cleanly uninstalled."
        if [ "$LOCAL_MS2_FOUND" -eq 1 ]; then
            echo "All local MeshCentral 2 services and files remain intact."
        fi
        echo "=========================================================="
    fi
    exit 0
}

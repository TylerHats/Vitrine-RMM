# Vitrine RMM Frontend

Single-page web application for **Vitrine RMM**, built with **React 18**, **TypeScript**, and **Vite 5** (Node.js **20+** required).

## Development

```bash
npm ci
npm run dev
```

*   Runs the Vite dev server on **`http://localhost:5173`**.
*   `vite.config.ts` proxies `/api`, `/ws` (WebSocket upgrades enabled), and `/branding` to the Fastify backend at `http://localhost:8080`.

## Scripts

*   `npm run dev` — Start Vite HMR development server (`:5173`).
*   `npm run build` — Run `tsc -b && vite build` to produce the production bundle in `dist/`.
*   `npm run lint` — Run ESLint across the TypeScript/React codebase.
*   `npm run preview` — Preview the production `dist/` build locally.

## Architecture Highlights

*   **Code-Split Views & Modals**: Route-level views and heavy modals (including `DeviceDetailView`, `SessionRecordingsView`, `AuditExplorerView`, `DocumentationView`, `PsaSyncView`, `SettingsView`, `QuickSupportPortalView`, and `GuestPortalView`) are lazy-loaded via `React.lazy` in `src/App.tsx`, with vendor chunks (`react-vendor`, `icons-vendor`) configured in `vite.config.ts` (`~34 kB` gzipped core entry).
*   **Interactive PTY Shell & Hardware Specs**: `BackgroundToolsModal` embeds `@xterm/xterm` and `@xterm/addon-fit` connected to `/ws/terminal` for live SYSTEM/root and user-context PTY terminals, while `DeviceDetailView` renders live SMBIOS, DIMM, volume, NIC, BitLocker, and `Uninstall` inventory telemetry.
*   **Square Icon Cropper & Branding (`IconCropModal`)**: Client-side interactive canvas cropper (Fit/Fill square framing, zoom, padding, rounding, backdrop fill, and `16px / 32px / 48px / 64px` live previews) shared by **Policies** (per-tenant/site/role EXE & tray icons) and **Settings** (Global & QuickSupport Portal profiles).
*   **PWA & Service Worker**: `public/manifest.webmanifest` and `public/sw.js` provide installable PWA metadata with network-first caching for `/manifest.webmanifest` and `/logo.png` and strict cache bypass for `/api/`, `/ws/`, and `/branding/`.

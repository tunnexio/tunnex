import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import { resolve } from "node:path";

// The SPA is served as static files (by nginx in compose) and reused by the
// Electron renderer, so the build output is a plain static bundle.
export default defineConfig({
  plugins: [react()],
  server: {
    host: true,
    port: 5173,
    // In `pnpm dev`, proxy API calls to the local API so the dev experience
    // matches the nginx-proxied production path (relative /api and /healthz).
    //
    // ⛔ OVERRIDABLE, because the default is wrong for a compose stack. `make up` publishes nginx on :80
    // (host) -> :8080 (container), so nothing listens on the host's 8080 and `pnpm dev` cannot reach the API
    // at all. That made dev mode unusable for a UI review against a running stack — the exact thing it is
    // for.
    //
    //     TUNNEX_DEV_API=http://localhost:80 pnpm --filter @tunnex/web dev
    //
    // Default left at 8080 so nothing changes for anyone running the API directly.
    proxy: {
      "/api": process.env.TUNNEX_DEV_API ?? "http://localhost:8080",
      "/healthz": process.env.TUNNEX_DEV_API ?? "http://localhost:8080",
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
    // ⛔ TWO ENTRIES, ONE BUILD. `index.html` is the web app; `client.html` is the desktop
    // client's own surface. They share tokens and the build pipeline and NOTHING else — the
    // client mounts no router and imports no page.
    //
    // This is step 1 of the migration: the entry exists and is reviewable at /client.html in a
    // BROWSER, while Electron still loads index.html. Nothing switches until step 3, which is a
    // one-line change to the loader.
    rollupOptions: {
      input: {
        index: resolve(__dirname, "index.html"),
        client: resolve(__dirname, "client.html"),
      },
    },
  },
});

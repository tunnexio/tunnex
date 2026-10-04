import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// Vite's string target shorthand sets changeOrigin=true. Preserve the browser's
// authority (including its port) so dev and preview match production CSRF checks.
const localAPI = () => ({ target: process.env.TUNNEX_DEV_API ?? "http://localhost:8080", changeOrigin: false });

// The dashboard is served as a static bundle by nginx in compose.
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
      "/api": localAPI(),
      "^/ai(?:/|$)": localAPI(),
      "/healthz": localAPI(),
    },
  },
  build: {
    outDir: "dist",
    sourcemap: true,
  },
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveConfig, type ProxyOptions } from "vite";
import { fileURLToPath } from "node:url";

afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });

describe("local console proxy authority", () => {
  it.each([undefined, "http://127.0.0.1:18084"])("preserves browser Host for dev and preview with API target %s", async target => {
    vi.stubEnv("TUNNEX_DEV_API", target);
    // Use Vite's real config loader without a cross-project TypeScript import:
    // clean typechecks run before the composite config project emits declarations.
    const resolved = await resolveConfig({ configFile: fileURLToPath(new URL("../vite.config.ts", import.meta.url)), envFile: false }, "serve");
    for (const proxy of [resolved.server.proxy, resolved.preview.proxy]) {
      for (const path of ["/api", "^/ai(?:/|$)", "/healthz"]) {
        const rule = proxy?.[path];
        // Vite's string shorthand silently enables changeOrigin and loses the
        // browser port, causing exact-origin CSRF checks to reject valid writes.
        expect(typeof rule).toBe("object");
        expect((rule as ProxyOptions).changeOrigin).toBe(false);
        expect((rule as ProxyOptions).target).toBe(target ?? "http://localhost:8080");
      }
    }
  });
});

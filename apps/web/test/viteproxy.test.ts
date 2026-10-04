import { afterEach, describe, expect, it, vi } from "vitest";
import { resolveConfig, type ProxyOptions } from "vite";

afterEach(() => { vi.unstubAllEnvs(); vi.resetModules(); });

describe("local console proxy authority", () => {
  it.each([undefined, "http://127.0.0.1:18084"])("preserves browser Host for dev and preview with API target %s", async target => {
    vi.stubEnv("TUNNEX_DEV_API", target);
    const { default: config } = await import("../vite.config");
    const resolved = await resolveConfig({ ...config, configFile: false, envFile: false }, "serve");
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

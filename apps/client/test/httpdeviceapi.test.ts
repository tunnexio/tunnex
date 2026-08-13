import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { HttpDeviceApi } from "../src/main/httpdeviceapi";

// Stub global fetch with a scripted per-path responder. Each entry matches a URL
// substring and yields { ok, status, body }.
type Route = { match: string; ok?: boolean; status?: number; body: unknown };
const realFetch = globalThis.fetch;
function stubFetch(routes: Route[], inspect?: (url: string, init?: RequestInit) => void) {
  globalThis.fetch = (async (url: string, init?: RequestInit) => {
    inspect?.(url, init);
    const r = routes.find((rt) => url.includes(rt.match));
    if (!r) throw new Error(`no stub for ${url}`);
    return {
      ok: r.ok ?? true,
      status: r.status ?? 200,
      json: async () => r.body,
    } as Response;
  }) as typeof fetch;
}
afterEach(() => {
  globalThis.fetch = realFetch;
});

const api = () => new HttpDeviceApi("https://t.example", () => "tok");

test("deviceStatus: requires the current session user to own the stored device", async () => {
  const current = { match: "/auth/me", body: { id: "user-1" } };
  stubFetch([current, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-1", status: "active" }] }]);
  assert.equal(await api().deviceStatus("dev-1", "o1"), "active");
  stubFetch([current, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-1", status: "pending" }] }]);
  assert.equal(await api().deviceStatus("dev-1", "o1"), "pending");
  stubFetch([current, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-1", status: "revoked" }] }]);
  assert.equal(await api().deviceStatus("dev-1", "o1"), "gone");
  // absent in its OWN org -> genuinely gone (no cross-org scan that a transient omit could
  // false-"gone" — finding #4).
  stubFetch([current, { match: "/organizations/o1/devices", body: [{ id: "other", user_id: "user-1", status: "active" }] }]);
  assert.equal(await api().deviceStatus("dev-1", "o1"), "gone");
  // An org admin can see all device rows, but must not reuse another user's local credential.
  stubFetch([current, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-2", status: "active" }] }]);
  assert.equal(await api().deviceStatus("dev-1", "o1"), "gone");
});

test("deviceStatus: THROWS on a non-OK read (fail-safe — a blip never reads as a transition)", async () => {
  stubFetch([{ match: "/auth/me", body: { id: "user-1" } }, { match: "/organizations/o1/devices", ok: false, status: 503, body: {} }]);
  await assert.rejects(api().deviceStatus("dev-1", "o1"), /list_devices_failed/);
});

test("deviceExists = deviceStatus === 'active' (#6: one fail-safe, no divergence)", async () => {
  stubFetch([{ match: "/auth/me", body: { id: "user-1" } }, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-1", status: "active" }] }]);
  assert.equal(await api().deviceExists("dev-1", "o1"), true);
  stubFetch([{ match: "/auth/me", body: { id: "user-1" } }, { match: "/organizations/o1/devices", body: [{ id: "dev-1", user_id: "user-1", status: "pending" }] }]);
  assert.equal(await api().deviceExists("dev-1", "o1"), false); // pending is not active
  stubFetch([{ match: "/auth/me", body: { id: "user-1" } }, { match: "/organizations/o1/devices", ok: false, status: 500, body: {} }]);
  await assert.rejects(api().deviceExists("dev-1", "o1"), /list_devices_failed/); // inherits the throw
});

test("updateDeviceMode uses an optional query parameter so authorization runs before validation", async () => {
  let seen: { url: string; init?: RequestInit } | undefined;
  stubFetch([
    { match: "/organizations/o1/devices/dev-1/mode?full_tunnel=true", body: {
      device: { full_tunnel: true },
      config: {
        address: "10.99.0.2/32", endpoint: "198.51.100.1:51820", peer_public_key: "peer",
        allowed_ips: ["0.0.0.0/0"],
      },
    } },
  ], (url, init) => { seen = { url, init }; });

  const result = await api().updateDeviceMode("dev-1", "o1", true);
  assert.equal(result.fullTunnel, true);
  assert.equal(seen?.url, "https://t.example/api/v1/organizations/o1/devices/dev-1/mode?full_tunnel=true");
  assert.equal(seen?.init?.method, "PATCH");
  assert.equal(seen?.init?.body, undefined);
});

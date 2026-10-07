import { afterEach, describe, expect, it, vi } from "vitest";
import { createTunnexClient, setApiOrigin } from "@tunnex/shared";

const orgId = "00000000-0000-4000-8000-000000000001";

afterEach(() => {
  setApiOrigin(null);
  vi.unstubAllGlobals();
});

function captureRequests() {
  const requests: Request[] = [];
  vi.stubGlobal("fetch", vi.fn(async (request: Request) => {
    requests.push(request);
    return Response.json([]);
  }));
  return requests;
}

describe("API request transport", () => {
  it.each(["http", "https"])("bypasses cached redirects for %s console reads without widening cookie scope", async (scheme) => {
    const requests = captureRequests();
    const origin = `${scheme}://console.example.test`;
    const api = createTunnexClient(origin);
    await api.GET("/api/v1/organizations/{orgId}/members", {
      params: { path: { orgId } },
    });

    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe(`${origin}/api/v1/organizations/${orgId}/members`);
    expect(requests[0].cache).toBe("no-store");
    expect(requests[0].credentials).toBe("same-origin");
  });

  it("preserves cache bypass and CSRF protection when desktop rewrites the API origin", async () => {
    const requests = captureRequests();
    setApiOrigin("http://private-console.example.test");
    const api = createTunnexClient("https://renderer.example.test");
    await api.PUT("/api/v1/admin/ai-transport-settings", {
      body: { allow_http: true, revision: 1 },
    });

    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe("http://private-console.example.test/api/v1/admin/ai-transport-settings");
    expect(requests[0].cache).toBe("no-store");
    expect(requests[0].credentials).toBe("same-origin");
    expect(requests[0].headers.get("X-Tunnex-CSRF")).toBe("1");
    expect(await requests[0].json()).toEqual({ allow_http: true, revision: 1 });
  });
});

describe("Beam typed client transport", () => {
  it("keeps the same origin, CSRF and cache rules for the separately generated Beam contract", async () => {
    const requests = captureRequests();
    const client = createTunnexClient<import("../src/lib/beam-api").paths>("https://console.example.test");
    await client.POST("/api/v1/organizations/{orgId}/beam/shares/{id}/actions", {
      params: { path: { orgId, id: "00000000-0000-4000-8000-000000000002" } },
      body: { action: "pause", expected_version: 3 },
    });
    expect(requests).toHaveLength(1);
    expect(requests[0].url).toBe(`https://console.example.test/api/v1/organizations/${orgId}/beam/shares/00000000-0000-4000-8000-000000000002/actions`);
    expect(requests[0].headers.get("X-Tunnex-CSRF")).toBe("1");
    expect(requests[0].credentials).toBe("same-origin");
    expect(requests[0].cache).toBe("no-store");
    expect(await requests[0].json()).toEqual({ action: "pause", expected_version: 3 });
  });
});

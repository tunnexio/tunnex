import { test, afterEach } from "node:test";
import assert from "node:assert/strict";

import { HttpDeviceApi } from "../src/main/httpdeviceapi";
import { ManagedLifecycleCoordinator, type CredentialSnapshot } from "../src/main/managedlifecycle";

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

const api = () => new HttpDeviceApi("https://t.example", "tok");
const USER_ID = "00000000-0000-4000-8000-000000000011";
const ORG_ID = "00000000-0000-4000-8000-000000000021";
const DEVICE_ID = "00000000-0000-4000-8000-000000000031";
const NODE_ID = "00000000-0000-4000-8000-000000000041";
const PUBLIC_KEY = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const ENROLLMENT = {
  organizationId: "00000000-0000-4000-8000-000000000022",
  nodeId: NODE_ID,
  name: "tunnex-desktop-test",
  platform: "darwin",
  fullTunnel: false,
  publicKey: PUBLIC_KEY,
};
const VALID_MODE_DEVICE = {
  id: "00000000-0000-4000-8000-000000000032",
  user_id: "00000000-0000-4000-8000-000000000002",
  owner_email: null,
  node_id: "00000000-0000-4000-8000-000000000003",
  name: "Desktop",
  kind: "human",
  public_key: PUBLIC_KEY,
  full_tunnel: true,
  status: "active",
  approved_by: null,
  created_at: "2026-09-01T00:00:00Z",
};

test("an API instance keeps the exact token captured at construction", async () => {
  let storeToken = "token-a";
  const fixedApi = new HttpDeviceApi("https://t.example", storeToken);
  storeToken = "token-b";
  const authorizations: Array<string | null> = [];
  stubFetch(
    [{ match: "/auth/me", body: { id: USER_ID } }],
    (_url, init) => authorizations.push(new Headers(init?.headers).get("authorization")),
  );

  assert.equal(await fixedApi.currentUserId(), USER_ID);
  assert.equal(storeToken, "token-b", "the simulated credential store changed after API construction");
  assert.deepEqual(authorizations, ["Bearer token-a"], "an existing API must remain pinned to its captured token");
});

test("a hung identity request times out statically and releases a queued lifecycle disconnect", async () => {
  const tokenSentinel = "BEARER_TIMEOUT_SECRET_SENTINEL";
  const bodySentinel = "BODY_TIMEOUT_SECRET_SENTINEL";
  const credential: CredentialSnapshot = {
    server: "https://t.example",
    token: tokenSentinel,
    fingerprint: "fingerprint-a",
    expiresAt: "2999-01-01T00:00:00Z",
  };
  const coordinator = new ManagedLifecycleCoordinator(() => credential);
  const timedApi = new HttpDeviceApi(credential.server, credential.token, 10);
  const events: string[] = [];
  globalThis.fetch = (async (_url: string | URL | Request, init?: RequestInit) => ({
    ok: true,
    status: 200,
    // Deliberately ignore abort like a broken body stream. The shared wrapper's
    // deadline must still settle the FIFO; it cannot depend on a cooperative body.
    json: () => new Promise(() => { void init?.signal; }),
  }) as Response) as typeof fetch;

  const connect = coordinator.serial(async () => {
    events.push("connect:start");
    await coordinator.capture(() => timedApi.currentUserId());
  });
  const disconnect = coordinator.serial(() => {
    events.push("disconnect");
  });

  await assert.rejects(connect, (error: unknown) => {
    assert.ok(error instanceof Error);
    assert.equal(error.message, "control_plane_request_timeout");
    assert.doesNotMatch(error.message, new RegExp(`${tokenSentinel}|${bodySentinel}`));
    return true;
  });
  await disconnect;
  assert.deepEqual(events, ["connect:start", "disconnect"]);
});

test("malformed UUID path segments refuse before the false-revoke logout route", async () => {
  const malformed = [
    "../auth/logout?",
    "a/b",
    "%2e%2e%2fauth%2flogout%3f",
    "value?query",
    "value#fragment",
    ".",
    "..",
  ];
  let fetches = 0;
  globalThis.fetch = (async () => {
    fetches += 1;
    return { ok: true, status: 204, json: async () => ({}) } as Response;
  }) as typeof fetch;

  for (const candidate of malformed) {
    await assert.rejects(api().revokeDevice(DEVICE_ID, candidate), /revoke_device_failed: invalid_request/);
    await assert.rejects(api().revokeDevice(candidate, ORG_ID), /revoke_device_failed: invalid_request/);
  }
  assert.equal(fetches, 0, "invalid path identity must not issue even a logout-shaped POST");
});

test("revoke retry treats only typed already_revoked as idempotent completion", async () => {
  let attempts = 0;
  globalThis.fetch = (async () => {
    attempts += 1;
    if (attempts === 1) {
      // The server committed the revoke but the response was lost. The local
      // recovery record therefore remains and the user retries the same POST.
      throw new Error("response_lost_after_commit");
    }
    return {
      ok: false,
      status: 409,
      json: async () => ({ error: { code: "already_revoked" } }),
    } as Response;
  }) as typeof fetch;

  await assert.rejects(
    api().revokeDevice("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023"),
    /response_lost_after_commit/,
  );
  await api().revokeDevice("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023");
  assert.equal(attempts, 2);
});

test("revoke retry rejects generic or malformed 409 responses", async () => {
  for (const body of [
    { error: { code: "device_not_revocable" } },
    { error: {} },
    {},
    null,
  ]) {
    stubFetch([{
      match: "/organizations/00000000-0000-4000-8000-000000000023/devices/00000000-0000-4000-8000-000000000032/revoke",
      ok: false,
      status: 409,
      body,
    }]);
    await assert.rejects(
      api().revokeDevice("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023"),
      /revoke_device_failed: 409/,
    );
  }
});

test("organization context exposes only live membership identity facts", async () => {
  stubFetch([
    { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
    { match: "/api/v1/organizations", body: [
      { id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha", pool_cidr: "10.0.0.0/24" },
      { id: "00000000-0000-4000-8000-000000000022", name: "Beta", slug: "beta", pool_cidr: "10.1.0.0/24" },
    ] },
  ]);
  assert.equal(await api().currentUserId(), "00000000-0000-4000-8000-000000000011");
  assert.deepEqual(await api().organizations(), [
    { id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" },
    { id: "00000000-0000-4000-8000-000000000022", name: "Beta", slug: "beta" },
  ]);
});

test("currentUserId rejects a malformed identity response", async () => {
  for (const body of [{}, { id: "" }, { id: 42 }]) {
    stubFetch([{ match: "/auth/me", body }]);
    await assert.rejects(api().currentUserId(), /current_user_failed: invalid_response/);
  }
});

test("organizations rejects an empty membership id", async () => {
  stubFetch([{
    match: "/api/v1/organizations",
    body: [{ id: "", name: "Alpha", slug: "alpha" }],
  }]);
  await assert.rejects(api().organizations(), /list_organizations_failed: invalid_response/);
});

test("reportHealth accepts only exact, semantically consistent posture verdicts", async () => {
  const valid = [
    { state: "compliant", blocked: false, failed_checks: [] },
    {
      state: "noncompliant",
      blocked: false,
      failed_checks: [{ kind: "disk_encryption", mode: "warn" }],
    },
    {
      state: "noncompliant",
      blocked: true,
      failed_checks: [
        { kind: "disk_encryption", mode: "warn" },
        { kind: "os_version", mode: "require" },
      ],
    },
  ];
  for (const body of valid) {
    stubFetch([{ match: "/organizations/00000000-0000-4000-8000-000000000023/devices/00000000-0000-4000-8000-000000000032/health", body }]);
    assert.deepEqual(
      await api().reportHealth("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023", { platform: "macos", os_version: "14.5" }),
      body,
    );
  }
});

test("reportHealth rejects malformed or semantically impossible 2xx verdicts", async () => {
  const valid = { state: "noncompliant", blocked: true, failed_checks: [{ kind: "disk_encryption", mode: "require" }] };
  const cases: Array<{ name: string; body: unknown }> = [
    { name: "null body", body: null },
    { name: "array body", body: [] },
    { name: "missing state", body: { blocked: false, failed_checks: [] } },
    { name: "extra root key", body: { ...valid, detail: "secret-sentinel" } },
    { name: "invalid state", body: { ...valid, state: "unknown" } },
    { name: "blocked type confusion", body: { ...valid, blocked: "false" } },
    { name: "failed checks type confusion", body: { ...valid, failed_checks: {} } },
    { name: "null failed check", body: { ...valid, failed_checks: [null] } },
    { name: "extra failed-check key", body: { ...valid, failed_checks: [{ kind: "disk_encryption", mode: "require", detail: "secret-sentinel" }] } },
    { name: "unknown failed-check kind", body: { ...valid, failed_checks: [{ kind: "edr", mode: "require" }] } },
    { name: "unknown failed-check mode", body: { ...valid, failed_checks: [{ kind: "disk_encryption", mode: "off" }] } },
    { name: "duplicate server check", body: { ...valid, failed_checks: [{ kind: "disk_encryption", mode: "require" }, { kind: "disk_encryption", mode: "warn" }] } },
    { name: "compliant with failures", body: { ...valid, state: "compliant" } },
    { name: "noncompliant without failures", body: { state: "noncompliant", blocked: false, failed_checks: [] } },
    { name: "require failure not blocked", body: { ...valid, blocked: false } },
    { name: "warn failure blocked", body: { ...valid, failed_checks: [{ kind: "disk_encryption", mode: "warn" }] } },
  ];

  for (const scenario of cases) {
    stubFetch([{ match: "/organizations/00000000-0000-4000-8000-000000000023/devices/00000000-0000-4000-8000-000000000032/health", body: scenario.body }]);
    await assert.rejects(
      api().reportHealth("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023", { platform: "macos", os_version: "14.5" }),
      (error: unknown) => {
        assert.ok(error instanceof Error, scenario.name);
        assert.equal(error.message, "report_health_failed: invalid_response", scenario.name);
        assert.doesNotMatch(error.message, /secret-sentinel/, scenario.name);
        return true;
      },
    );
  }
});

test("reportHealth normalizes malformed JSON success to a static error", async () => {
  globalThis.fetch = (async () => ({
    ok: true,
    status: 200,
    json: async () => { throw new Error("secret-json-parser-sentinel"); },
  }) as unknown as Response) as typeof fetch;

  await assert.rejects(
    api().reportHealth("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000023", { platform: "macos", os_version: "14.5" }),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, "report_health_failed: invalid_response");
      assert.doesNotMatch(error.message, /secret-json-parser-sentinel/);
      return true;
    },
  );
});

test("managed enrollment prepares once and creates with the exact anchored public intent", async () => {
  const seen: Array<{ url: string; init?: RequestInit }> = [];
  stubFetch([
    { match: "/organizations/00000000-0000-4000-8000-000000000022/nodes", body: [{ id: NODE_ID, status: "active" }] },
    { match: "/organizations/00000000-0000-4000-8000-000000000022/devices", body: {
      device: {
        id: DEVICE_ID,
        user_id: USER_ID,
        node_id: NODE_ID,
        public_key: PUBLIC_KEY,
        status: "active",
      },
    } },
  ], (url, init) => { seen.push({ url, init }); });

  const client = api();
  const preparation = await client.prepareDeviceEnrollment(ENROLLMENT.organizationId);
  assert.equal(preparation.nodeId, NODE_ID);
  const result = await client.createDevice({ ...ENROLLMENT, ...preparation });
  assert.equal(result.deviceId, DEVICE_ID);
  assert.equal(result.ownerUserId, USER_ID);
  const posted = JSON.parse(String(seen[1].init?.body)) as Record<string, unknown>;
  assert.equal(posted.public_key, PUBLIC_KEY);
  assert.equal(posted.provisioning, "managed");
  assert.equal(posted.kind, "human");
  assert.deepEqual(seen.map(({ url }) => new URL(url).pathname), [
    "/api/v1/organizations/00000000-0000-4000-8000-000000000022/nodes",
    "/api/v1/organizations/00000000-0000-4000-8000-000000000022/devices",
  ]);
  assert.equal(seen[1].init?.method, "POST");
});

test("createDevice refuses a response without an exact human owner", async () => {
  stubFetch([
    { match: "/organizations/00000000-0000-4000-8000-000000000022/devices", body: {
      device: { id: DEVICE_ID, node_id: NODE_ID, public_key: PUBLIC_KEY, status: "active" },
    } },
  ]);
  await assert.rejects(api().createDevice(ENROLLMENT), /create_device_failed: invalid_response/);
});

test("malformed enrollment JSON cannot expose parser or response bytes", async () => {
  const sentinel = "ENROLLMENT_RESPONSE_SECRET_SENTINEL";
  globalThis.fetch = (async () => ({
    ok: true,
    status: 201,
    json: async () => { throw new Error(`Unexpected token: ${sentinel}`); },
  }) as unknown as Response) as typeof fetch;
  await assert.rejects(
    api().createDevice(ENROLLMENT),
    (error: unknown) => {
      assert.ok(error instanceof Error);
      assert.equal(error.message, "create_device_failed: invalid_response");
      assert.doesNotMatch(error.message, new RegExp(sentinel));
      return true;
    },
  );
});

test("client-key create rejects any server-returned private key or config", async () => {
  for (const secretField of ["private_key", "config"] as const) {
    stubFetch([{ match: "/devices", body: {
      device: { id: DEVICE_ID, user_id: USER_ID, node_id: NODE_ID, public_key: PUBLIC_KEY, status: "active" },
      [secretField]: "SERVER_SECRET_SENTINEL",
    } }]);
    await assert.rejects(api().createDevice(ENROLLMENT), /create_device_failed: invalid_response/);
  }
});

test("public-key recovery validates the full mixed-transport roster and returns only the exact key", async () => {
  stubFetch([{ match: "/devices", body: [
    { id: "00000000-0000-4000-8000-000000000051", user_id: USER_ID, node_id: NODE_ID, public_key: "", status: "active" },
    { id: DEVICE_ID, user_id: USER_ID, node_id: NODE_ID, public_key: PUBLIC_KEY, status: "pending" },
    { id: "00000000-0000-4000-8000-000000000052", user_id: USER_ID, node_id: NODE_ID, public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=", status: "active" },
  ] }]);
  const matches = await api().devicesByPublicKey(ENROLLMENT.organizationId, PUBLIC_KEY);
  assert.deepEqual(matches, [{
    deviceId: DEVICE_ID,
    ownerUserId: USER_ID,
    nodeId: NODE_ID,
    publicKey: PUBLIC_KEY,
    status: "pending",
  }]);
});

test("createDevice rejects malformed active-node responses without a device POST", async () => {
  for (const body of [
    {},
    [null],
    [{ status: "active" }],
    [{ id: "", status: "active" }],
  ]) {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    stubFetch([
      { match: "/organizations/00000000-0000-4000-8000-000000000022/nodes", body },
    ], (url, init) => { seen.push({ url, init }); });

    await assert.rejects(api().prepareDeviceEnrollment("00000000-0000-4000-8000-000000000022"), /list_nodes_failed: invalid_response/);
    assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
  }
});

test("legacy discovery finds its owning org without guessing membership index zero or issuing a POST", async () => {
  const seen: Array<{ url: string; init?: RequestInit }> = [];
  stubFetch([
    { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
    { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", body: [] },
    { match: "/organizations/00000000-0000-4000-8000-000000000022/devices", body: [
      { id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000011", status: "active" },
    ] },
    { match: "/api/v1/organizations", body: [
      { id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" },
      { id: "00000000-0000-4000-8000-000000000022", name: "Beta", slug: "beta" },
    ] },
  ], (url, init) => { seen.push({ url, init }); });
  assert.equal(await api().discoverLegacyDevice("00000000-0000-4000-8000-000000000033", "00000000-0000-4000-8000-000000000011"), "00000000-0000-4000-8000-000000000022");
  assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
});

test("legacy discovery: absent or foreign exact device refuses without POST", async () => {
  for (const body of [
    [],
    [{ id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000012", status: "active" }],
  ]) {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    stubFetch([
      { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
      { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", body },
      { match: "/api/v1/organizations", body: [{ id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" }] },
    ], (url, init) => { seen.push({ url, init }); });
    await assert.rejects(
      api().discoverLegacyDevice("00000000-0000-4000-8000-000000000033", "00000000-0000-4000-8000-000000000011"),
      body.length === 0 ? /legacy_device_owner_unconfirmed/ : /managed_device_owner_mismatch/,
    );
    assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
  }
});

test("legacy discovery: duplicate exact ids across memberships are ambiguous even when one is owned", async () => {
  const seen: Array<{ url: string; init?: RequestInit }> = [];
  stubFetch([
    { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
    { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", body: [{ id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000011", status: "active" }] },
    { match: "/organizations/00000000-0000-4000-8000-000000000022/devices", body: [{ id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000012", status: "active" }] },
    { match: "/api/v1/organizations", body: [
      { id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" },
      { id: "00000000-0000-4000-8000-000000000022", name: "Beta", slug: "beta" },
    ] },
  ], (url, init) => { seen.push({ url, init }); });
  await assert.rejects(api().discoverLegacyDevice("00000000-0000-4000-8000-000000000033", "00000000-0000-4000-8000-000000000011"), /legacy_device_organization_ambiguous/);
  assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
});

test("legacy discovery: malformed or incompletely scanned memberships retain by refusing before POST", async () => {
  const cases: Route[][] = [
    [
      { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", body: [{ id: "00000000-0000-4000-8000-000000000033", status: "active" }] },
    ],
    [
      { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", body: [
        { id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000011", status: "active" },
        { id: "00000000-0000-4000-8000-000000000033", user_id: "00000000-0000-4000-8000-000000000012", status: "active" },
      ] },
    ],
    [
      { match: "/organizations/00000000-0000-4000-8000-000000000021/devices", ok: false, status: 503, body: {} },
    ],
  ];
  for (const deviceRoutes of cases) {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    stubFetch([
      { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
      ...deviceRoutes,
      { match: "/api/v1/organizations", body: [{ id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" }] },
    ], (url, init) => { seen.push({ url, init }); });
    await assert.rejects(api().discoverLegacyDevice("00000000-0000-4000-8000-000000000033", "00000000-0000-4000-8000-000000000011"), /list_devices_failed/);
    assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
  }
});

test("legacy discovery: current-session mismatch and zero memberships refuse without POST", async () => {
  const cases = [
    { expected: "00000000-0000-4000-8000-000000000012", organizations: [{ id: "00000000-0000-4000-8000-000000000021", name: "Alpha", slug: "alpha" }], error: /managed_device_owner_mismatch/ },
    { expected: "00000000-0000-4000-8000-000000000011", organizations: [], error: /legacy_device_owner_unconfirmed/ },
  ];
  for (const c of cases) {
    const seen: Array<{ url: string; init?: RequestInit }> = [];
    stubFetch([
      { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } },
      { match: "/api/v1/organizations", body: c.organizations },
    ], (url, init) => { seen.push({ url, init }); });
    await assert.rejects(api().discoverLegacyDevice("00000000-0000-4000-8000-000000000033", c.expected), c.error);
    assert.equal(seen.some(({ init }) => init?.method === "POST"), false);
  }
});

test("deviceStatus: requires the current session user to own the stored device", async () => {
  const current = { match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } };
  stubFetch([current, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000011", status: "active" }] }]);
  assert.equal(await api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), "active");
  stubFetch([current, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000011", status: "pending" }] }]);
  assert.equal(await api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), "pending");
  stubFetch([current, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000011", status: "revoked" }] }]);
  assert.equal(await api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), "gone");
  // absent in its OWN org -> genuinely gone (no cross-org scan that a transient omit could
  // false-"gone" — finding #4).
  stubFetch([current, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000034", user_id: "00000000-0000-4000-8000-000000000011", status: "active" }] }]);
  assert.equal(await api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), "gone");
  // An org admin can see all device rows, but must not reuse another user's local credential.
  stubFetch([current, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000012", status: "active" }] }]);
  assert.equal(await api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), "gone");
});

test("deviceStatus: THROWS on a non-OK read (fail-safe — a blip never reads as a transition)", async () => {
  stubFetch([{ match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } }, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", ok: false, status: 503, body: {} }]);
  await assert.rejects(api().deviceStatus("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), /list_devices_failed/);
});

test("deviceExists = deviceStatus === 'active' (#6: one fail-safe, no divergence)", async () => {
  stubFetch([{ match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } }, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000011", status: "active" }] }]);
  assert.equal(await api().deviceExists("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), true);
  stubFetch([{ match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } }, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", body: [{ id: "00000000-0000-4000-8000-000000000032", user_id: "00000000-0000-4000-8000-000000000011", status: "pending" }] }]);
  assert.equal(await api().deviceExists("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), false); // pending is not active
  stubFetch([{ match: "/auth/me", body: { id: "00000000-0000-4000-8000-000000000011" } }, { match: "/organizations/00000000-0000-4000-8000-000000000024/devices", ok: false, status: 500, body: {} }]);
  await assert.rejects(api().deviceExists("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024"), /list_devices_failed/); // inherits the throw
});

test("updateDeviceMode uses an optional query parameter so authorization runs before validation", async () => {
  let seen: { url: string; init?: RequestInit } | undefined;
  stubFetch([
    { match: "/organizations/00000000-0000-4000-8000-000000000024/devices/00000000-0000-4000-8000-000000000032/mode?full_tunnel=true", body: {
      device: VALID_MODE_DEVICE,
      config: {
        address: "10.99.0.2/32", endpoint: "198.51.100.1:51820",
        peer_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
        allowed_ips: ["0.0.0.0/0"],
      },
    } },
  ], (url, init) => { seen = { url, init }; });

  const result = await api().updateDeviceMode("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024", true);
  assert.equal(result.fullTunnel, true);
  assert.equal(seen?.url, "https://t.example/api/v1/organizations/00000000-0000-4000-8000-000000000024/devices/00000000-0000-4000-8000-000000000032/mode?full_tunnel=true");
  assert.equal(seen?.init?.method, "PATCH");
  assert.equal(seen?.init?.body, undefined);
});

test("updateDeviceMode rejects malformed 2xx bodies before returning config facts", async () => {
  const valid = {
    device: VALID_MODE_DEVICE,
    config: {
      address: "10.99.0.2/32",
      endpoint: "198.51.100.1:51820",
      peer_public_key: "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=",
      allowed_ips: ["0.0.0.0/0"],
      mtu: 1420,
      persistent_keepalive: 25,
    },
  };
  const secretSentinel = "secret-mode-response-sentinel";
  const cases: Array<{ name: string; body: unknown }> = [
    { name: "missing device", body: { config: valid.config } },
    { name: "missing config", body: { device: valid.device } },
    { name: "extra root field", body: { ...valid, extra: true } },
    { name: "incomplete device", body: { ...valid, device: { full_tunnel: true } } },
    { name: "unknown device field", body: { ...valid, device: { ...valid.device, internal_flag: true } } },
    { name: "device type confusion", body: { ...valid, device: { ...valid.device, online: "true" } } },
    { name: "full-tunnel type confusion", body: { ...valid, device: { ...valid.device, full_tunnel: "true" } } },
    { name: "mode mismatch", body: { ...valid, device: { ...valid.device, full_tunnel: false } } },
    { name: "private key in mutable config", body: { ...valid, config: { ...valid.config, private_key: "secret-mode-response-sentinel" } } },
    { name: "unknown config field", body: { ...valid, config: { ...valid.config, internal_flag: true } } },
    { name: "bad peer key", body: { ...valid, config: { ...valid.config, peer_public_key: secretSentinel } } },
    { name: "bad address", body: { ...valid, config: { ...valid.config, address: "10.99.0.2" } } },
    { name: "unsafe endpoint", body: { ...valid, config: { ...valid.config, endpoint: "127.0.0.1:51820" } } },
    { name: "empty AllowedIPs", body: { ...valid, config: { ...valid.config, allowed_ips: [] } } },
    { name: "AllowedIPs type confusion", body: { ...valid, config: { ...valid.config, allowed_ips: ["0.0.0.0/0", 42] } } },
    { name: "bad MTU", body: { ...valid, config: { ...valid.config, mtu: 100 } } },
  ];

  for (const scenario of cases) {
    stubFetch([{
      match: "/organizations/00000000-0000-4000-8000-000000000024/devices/00000000-0000-4000-8000-000000000032/mode?full_tunnel=true",
      body: scenario.body,
    }]);
    await assert.rejects(
      api().updateDeviceMode("00000000-0000-4000-8000-000000000032", "00000000-0000-4000-8000-000000000024", true),
      (error: unknown) => {
        assert.ok(error instanceof Error, scenario.name);
        assert.equal(error.message, "update_device_mode_failed: invalid_response", scenario.name);
        assert.doesNotMatch(error.message, new RegExp(secretSentinel));
        return true;
      },
    );
  }
});

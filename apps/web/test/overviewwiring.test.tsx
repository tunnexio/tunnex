import { readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import { stripJsComments } from "./support/source";
import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import {
  render,
  screen,
  waitFor,
  cleanup,
  within,
  act,
  fireEvent,
} from "@testing-library/react";
import { Profiler } from "react";

// S14.4 — OVERVIEW. THE FAILURE PATHS ARE THE TEST; the happy path is the easy half.
//
// This screen's whole thesis is that "we have not learned this" and "the answer is zero" are different
// statements. Every assertion below is about which one gets rendered.

afterEach(cleanup);

let overviewFail = false;
let sitesFail = false;
let nodesFail = false;
let empty = false;
let preEnrolledGateway = false;
let edition: string | null = "enterprise";
let orgs = [{ id: "org-1", name: "Acme" }];
type OverviewResult = {
  data?: ReturnType<typeof OV>;
  error?: { code: string; message: string };
};
let overviewReads = new Map<string, OverviewResult | Promise<OverviewResult>>();
let zeroTrustResponse: unknown = { mode: "off" };
let devicesResponse: unknown = [];
let agentsResponse: unknown = { items: [], next_cursor: null };
let inventoryResponses = new Map<string, unknown>();

const OV = () => ({
  members: empty ? 0 : 4,
  devices: empty ? 0 : 7,
  nodes: preEnrolledGateway ? 1 : empty ? 0 : 2,
  online: empty ? 0 : 1,
  recent_activity: empty
    ? []
    : [{ action: "device.created", created_at: new Date().toISOString() }],
});

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  const err = { error: { code: "boom", message: "nope" } };
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string } } }) => {
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta")
          return edition === null
            ? { data: undefined, ...err }
            : { data: { edition } };
        if (path === "/api/v1/organizations")
          return { data: orgs };
        const replacement = [...inventoryResponses].find(([suffix]) => path.endsWith(suffix));
        if (replacement) return { data: replacement[1] };
        if (path.endsWith("/overview")) {
          const savedRead = overviewReads.get(request?.params?.path?.orgId ?? "org-1");
          if (savedRead) return savedRead;
          return overviewFail ? { data: undefined, ...err } : { data: OV() };
        }
        if (path.endsWith("/zero-trust-mode")) return { data: zeroTrustResponse };
        if (path.endsWith("/sites"))
          return sitesFail
            ? { data: undefined, ...err }
            : { data: empty ? [] : [{ id: "s1" }] };
        if (path.endsWith("/devices/pending")) return { data: [] };
        if (path.endsWith("/devices")) return { data: devicesResponse };
        if (path.endsWith("/agents")) return { data: agentsResponse };
        if (path.endsWith("/k8s/clusters"))
          return {
            data: empty
              ? []
              : [
                  {
                    id: "k1",
                    site_id: "s1",
                    connector_node_id: null,
                    name: "gitops-platform",
                    vip_range: "100.96.0.0/24",
                    service_cidr: "10.96.0.0/12",
                    dns_zone: "gitops.internal",
                    dns_vip: null,
                    managed_by_operator: true,
                  },
                  {
                    id: "k2",
                    site_id: "s1",
                    connector_node_id: null,
                    name: "payments",
                    vip_range: "100.97.0.0/24",
                    service_cidr: "10.97.0.0/16",
                    dns_zone: "payments.internal",
                    dns_vip: null,
                    managed_by_operator: false,
                  },
                ],
          };
        if (path.endsWith("/k8s/services"))
          return {
            data: empty
              ? []
              : [
                  {
                    id: "svc-1",
                    cluster_id: "k1",
                    name: "gitops",
                    namespace: "platform",
                    protocol: "tcp",
                    port_low: 443,
                    port_high: 443,
                    vip: "100.96.0.10",
                    fqdn: "gitops.gitops.internal",
                    managed_by_operator: true,
                  },
                  {
                    id: "svc-2",
                    cluster_id: "k2",
                    name: "api",
                    namespace: "payments",
                    protocol: "tcp",
                    port_low: 443,
                    port_high: 443,
                    vip: "100.97.0.10",
                    fqdn: "api.payments.internal",
                    managed_by_operator: false,
                  },
                  {
                    id: "svc-3",
                    cluster_id: "k2",
                    name: "worker",
                    namespace: "payments",
                    protocol: "tcp",
                    port_low: null,
                    port_high: null,
                    vip: "100.97.0.11",
                    fqdn: "worker.payments.internal",
                    managed_by_operator: false,
                  },
                ],
          };
        // The hub-set endpoint returns an OBJECT, not a list. The catch-all `{ data: [] }` below fed an array
        // into hubSetView and threw — which surfaced as "cannot find Members", i.e. the whole page failing to
        // render. A catch-all mock is a fixture that answers questions it was never asked.
        if (path.endsWith("/hub-set"))
          return {
            data: {
              generation: 1,
              members: [{ node_id: "gw-a", role: "primary", hub_priority: 1 }],
            },
          };
        if (path.endsWith("/nodes"))
          return nodesFail
            ? { data: undefined, ...err }
            : {
                data: empty
                  ? []
                  : [
                      {
                        id: "n1",
                        name: "gw-a",
                        policy_degraded: true,
                        policy_degraded_kind: "silent_desync",
                      },
                    ],
              };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { MemoryRouter } from "react-router-dom";
import { OrgProvider, useOrg } from "../src/lib/useOrg";
import Dashboard from "../src/pages/Dashboard";
import { AuthProvider, useAuth } from "../src/lib/auth";
import { api } from "../src/lib/api";

// MemoryRouter is required: the get-started panel links to /devices, and a bare render throws
// "Cannot destructure property 'basename'" — which surfaced as an UNHANDLED ERROR rather than a clean
// failure, so the visible symptom ("could not find Get started") pointed away from the cause.
const show = () =>
  render(
    <MemoryRouter>
      <OrgProvider>
        <AuthProvider>
          <Dashboard />
        </AuthProvider>
      </OrgProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  window.localStorage.clear();
  vi.mocked(api.GET).mockClear();
  overviewFail = false;
  edition = "enterprise";
  sitesFail = false;
  nodesFail = false;
  empty = false;
  preEnrolledGateway = false;
  orgs = [{ id: "org-1", name: "Acme" }];
  overviewReads = new Map();
  zeroTrustResponse = { mode: "off" };
  devicesResponse = [];
  agentsResponse = { items: [], next_cursor: null };
  inventoryResponses = new Map();
});

describe("the six cards resolve INDEPENDENTLY — one failure degrades one card", () => {
  it("a failed /sites leaves the other five intact and marks only Sites unavailable", async () => {
    // The argument against an aggregated endpoint, asserted rather than argued: an API change driven by a
    // layout would convert three independent failures into one blast radius.
    sitesFail = true;
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.getByText("4")).toBeTruthy(); // members still resolved
    expect(screen.getByText("7")).toBeTruthy(); // devices still resolved
    expect(screen.getAllByText("could not load").length).toBe(1); // exactly one card degraded
  });
});

describe("⛔ A FAILED COUNT NEVER RENDERS AS ZERO", () => {
  it("a failed /sites shows 'unavailable', and no card shows 0", async () => {
    sitesFail = true;
    show();
    await waitFor(() => expect(screen.getByText("Sites")).toBeTruthy());
    await waitFor(() =>
      expect(screen.getByText("could not load")).toBeTruthy(),
    );

    // ⚠ THE ASSERTION HAD TO BE SHARPENED, AND THE FIRST VERSION WAS WRONG IN AN INSTRUCTIVE WAY.
    //
    // It was `expect(screen.queryByText("0")).toBeNull()` — "no card shows 0" — and it failed, correctly:
    // /devices/pending returned [] and the Pending-approvals card rendered a TRUE ZERO. We DID learn there
    // are none. That zero is honest and must render.
    //
    // The rule is not "never show 0". It is "NEVER SHOW 0 FOR SOMETHING WE DID NOT LEARN" — and a page-wide
    // text query cannot tell those apart, because on screen they are the same character. So the assertion is
    // scoped to the FAILED card, which is the only place the distinction lives.
    const sitesCard = screen.getByRole("group", { name: "Sites" });
    // (copy changed with the design pass; the ASSERTION is unchanged — a failed card must not show a number)
    expect(within(sitesCard).queryByText("0")).toBeNull();
  });

  it("a failed /overview does not render six zeroes", async () => {
    overviewFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Could not load the overview.")).toBeTruthy(),
    );
    expect(screen.queryByText("0")).toBeNull();
  });
});

describe("the gateway health summary uses the ONE health interpreter", () => {
  it("aggregates the verdict policyHealthBadge produces, not a second vocabulary", async () => {
    show();
    const conditions = await waitFor(() =>
      screen.getByRole("group", { name: "Gateway health conditions" }),
    );
    // `silent_desync` -> "silent desync" comes from lib/healthview.ts. If this screen grew its own mapping,
    // the two would drift and BOTH would still render — which is why there is exactly one interpreter.
    const silentDesync = within(conditions).getByText("silent desync").closest("div");
    expect(silentDesync && within(silentDesync).getByText("1")).toBeTruthy();
    expect(within(conditions).queryByText("gw-a")).toBeNull();
  });

  it("summarizes total, healthy, unhealthy, and revoked gateways in a named figure", async () => {
    show();
    const summary = await waitFor(() =>
      screen.getByRole("figure", { name: "Gateway health summary" }),
    );
    expect(within(summary).getByText("total")).toBeTruthy();
    expect(within(summary).getByText("Healthy")).toBeTruthy();
    expect(within(summary).getByText("Unhealthy")).toBeTruthy();
    expect(within(summary).getByText("Revoked")).toBeTruthy();
    const healthy = within(summary).getByText("Healthy").closest("li");
    const unhealthy = within(summary).getByText("Unhealthy").closest("li");
    const revoked = within(summary).getByText("Revoked").closest("li");
    expect(healthy && within(healthy).getByText("0")).toBeTruthy();
    expect(unhealthy && within(unhealthy).getByText("1")).toBeTruthy();
    expect(revoked && within(revoked).getByText("0")).toBeTruthy();
    expect(within(summary).getAllByText("1")).toHaveLength(2);
  });

  it("a failed /nodes says unavailable — never an empty 'all healthy' list", async () => {
    // "Nothing is wrong" and "we could not check" are opposite claims about a fleet.
    nodesFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Gateway health is unavailable.")).toBeTruthy(),
    );
    expect(screen.queryByRole("figure", { name: "Gateway health summary" })).toBeNull();
  });
});

describe("the populated Overview consolidates operational state into four cards", () => {
  it("renders the approved four regions without the former standalone panel chrome", async () => {
    show();
    await waitFor(() =>
      expect(screen.getByRole("region", { name: "Fleet summary" })).toBeTruthy(),
    );
    expect(screen.getByRole("region", { name: "Gateway Health" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Device Health" })).toBeTruthy();
    expect(screen.getByRole("region", { name: "Your network" })).toBeTruthy();
    expect(screen.queryByRole("region", { name: "Peer Connection Status" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Device Posture" })).toBeNull();
    expect(screen.queryByRole("region", { name: "HA Hub Set" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Network map" })).toBeNull();
    expect(screen.queryByRole("region", { name: "Kubernetes" })).toBeNull();
  });

  it("keeps topology, HA, and compact Kubernetes state visible without a view toggle", async () => {
    show();
    const infrastructure = await waitFor(() =>
      screen.getByRole("region", { name: "Your network" }),
    );
    expect(
      within(infrastructure).queryByRole("tablist", {
        name: "Infrastructure views",
      }),
    ).toBeNull();
    expect(within(infrastructure).getByText("HA Hub Set")).toBeTruthy();
    expect(within(infrastructure).getByText("Kubernetes")).toBeTruthy();
    const kubernetes = within(infrastructure).getByRole("group", {
      name: "Kubernetes summary",
    });
    expect(within(kubernetes).getByText("Exposed services")).toBeTruthy();
    expect(within(kubernetes).getByText("3")).toBeTruthy();
    expect(within(kubernetes).getByText("gitops-platform")).toBeTruthy();
    expect(within(kubernetes).getByText("payments")).toBeTruthy();
    expect(
      within(infrastructure).getByRole("link", { name: /Open Kubernetes/ }),
    ).toBeTruthy();
  });
});

describe("the get-started state appears only when the org is KNOWN to be empty", () => {
  it("a fresh org shows ONE get-started panel", async () => {
    empty = true;
    show();
    await waitFor(() => expect(screen.getByText("Get started")).toBeTruthy());
    expect(screen.getByRole("link", { name: /Company VPN/ }).getAttribute("href")).toBe("/setup?purpose=vpn");
  });

  it("offers setup after installer enrollment without making the user enroll again", async () => {
    empty = true; preEnrolledGateway = true; show();
    expect(await screen.findByRole("link", {name:/Company VPN/})).toBeTruthy();
  });

  it("a failed site read does not invent first-time setup for an existing gateway", async () => {
    empty = true; preEnrolledGateway = true; sitesFail = true; show();
    await screen.findByText("could not load");
    expect(screen.queryByRole("link", {name:/Company VPN/})).toBeNull();
  });

  it("a POPULATED org shows no get-started panel", async () => {
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.queryByText("Get started")).toBeNull();
  });

  it("a FAILED overview shows no get-started panel — a failure is not an empty org", async () => {
    // Showing onboarding because a fetch failed would tell a founder with a working fleet that they have
    // nothing: the reassuring-empty defect wearing an onboarding hat.
    overviewFail = true;
    show();
    await waitFor(() =>
      expect(screen.getByText("Could not load the overview.")).toBeTruthy(),
    );
    expect(screen.queryByText("Get started")).toBeNull();
  });
});

describe("the CUT panels are ABSENT, not hidden", () => {
  it("no throughput chart, no fleet-risk plot, no date picker", async () => {
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    // `hidden: true` searches the whole DOM regardless of visibility — the S14.2 lesson: a plain query would
    // pass against a `display:none` implementation and certify absence it never checked.
    expect(
      screen.queryByRole("figure", { name: /throughput/i, hidden: true }),
    ).toBeNull();
    expect(
      screen.queryByRole("figure", { name: /fleet risk/i, hidden: true }),
    ).toBeNull();
    expect(
      screen.queryByRole("textbox", { name: /date/i, hidden: true }),
    ).toBeNull();
  });

  it("⛔ THE FORBIDDEN LIVENESS LABEL APPEARS NOWHERE IN THE APP — the ruling outlived its card", () => {
    // A render-floor violation in a WORD: `online` is last-handshake RECENCY, not a live session, and the
    // wireframe's own caption says "never green-while-dead" under a label claiming exactly that. The
    // founder ruled the qualification belongs IN THE LABEL, and this test guarded the one card that
    // carried it — "Seen in last 3 min".
    //
    // ⛔ THAT CARD WAS REMOVED (replaced by AI Agents), WHICH LEFT THE GUARD WITH NO SUBJECT. Deleting it
    // would have retired a founder ruling as a side effect of a layout change — the ruling was about how
    // liveness may be NAMED, not about which card names it, and liveness still renders (Peer Connection
    // Status, and the Devices surfaces).
    //
    // So it is re-pointed at the whole source tree instead of one card, which is STRICTER than what it
    // replaced: the old version could only see a label on a screen the test happened to render.
    const src = join(process.cwd(), "src");
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) walk(full);
        else if (/\.tsx?$/.test(e.name)) {
          const body = stripJsComments(readFileSync(full, "utf8"));
          if (/online\s+peers/i.test(body)) offenders.push(full);
        }
      }
    };
    walk(src);
    expect(offenders).toEqual([]);
  });
});

describe("licence capability state does not suppress base operational cards", () => {
  // The defect this fixes: `/devices/pending` is enterprise-only, so the OPEN edition gets
  // `403 edition_required` — a SUCCESSFUL REFUSAL. Read through loadOne alone it became `failed`, and the
  // card rendered a red "could not load" for a feature the org was never sold.
  //
  // A design that carefully enumerates states pushes the danger onto the state nobody enumerated, and it gets
  // absorbed by whichever existing state is nearest — which is almost never the harmless one.
  it("[Community] the Pending-approvals card remains visible; access is determined by the server", async () => {
    edition = "open";
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.getByText("Approvals")).toBeTruthy();
    expect(screen.queryByText("could not load")).toBeNull();
  });

  it("[licensed plan] the card remains rendered", async () => {
    edition = "enterprise";
    show();
    await waitFor(() =>
      expect(screen.getByText("Approvals")).toBeTruthy(),
    );
  });

  it("[licence status pending] the base card remains rendered without inventing a plan restriction", async () => {
    edition = null;
    show();
    await waitFor(() => expect(screen.getByText("Members")).toBeTruthy());
    expect(screen.getByText("Approvals")).toBeTruthy();
  });
});

describe("HA Hub Set un-reporting member rendering", () => {
  it("renders 'not reporting' for a member without metrics (Query Rule One listitem role + exact count)", async () => {
    show();
    await waitFor(() => expect(screen.getByText("HA Hub Set")).toBeTruthy());
    // Query Rule One: Query listitem by role and single-truth accessible name
    const listItems = screen.getAllByRole("listitem", {
      name: /not reporting/i,
    });
    expect(listItems.length).toEqual(1);
    expect(
      screen.getByRole("listitem", {
        name: /gw-a \(primary\): not reporting/i,
      }),
    ).toBeTruthy();
    // Absence assertion: paired with positive role query above
    expect(
      screen.queryByRole("listitem", { name: /gw-a \(primary\): hs n\/a/i }),
    ).toBeNull();
  });
});

describe("Overview scope and refresh boundaries", () => {
  it("withdraws old tenant facts at every commit and ignores a superseded pending response", async () => {
    orgs = [
      { id: "org-1", name: "Acme" },
      { id: "org-2", name: "Waiting organization" },
      { id: "org-3", name: "Unavailable organization" },
    ];
    let resolveWaiting!: (result: OverviewResult) => void;
    overviewReads.set("org-2", new Promise(resolve => { resolveWaiting = resolve; }));
    overviewReads.set("org-3", { error: { code: "unavailable", message: "Unavailable" } });
    let selectedOrg = "org-1";
    const leakedCommits: boolean[] = [];
    function ScopeControls() {
      const { setOrg } = useOrg();
      return <>{orgs.map(org => <button key={org.id} onClick={() => {
        selectedOrg = org.id;
        setOrg(org.id);
      }}>Switch to {org.name}</button>)}</>;
    }
    render(<MemoryRouter><OrgProvider><AuthProvider><ScopeControls />
      <Profiler id="overview-tenant" onRender={() => {
        if (selectedOrg !== "org-1") leakedCommits.push(Boolean(screen.queryByRole("region", { name: "Fleet summary" }) || screen.queryByText("gitops-platform")));
      }}><Dashboard /></Profiler>
    </AuthProvider></OrgProvider></MemoryRouter>);
    await screen.findByText("gitops-platform");

    fireEvent.click(screen.getByRole("button", { name: "Switch to Waiting organization" }));
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("gitops-platform")).toBeNull();
    await waitFor(() => {
      const reads = vi.mocked(api.GET).mock.calls as Array<[string, { params?: { path?: { orgId?: string } } }?]>;
      expect(reads.some(([path, request]) => path.endsWith("/overview") && request?.params?.path?.orgId === "org-2")).toBe(true);
    });
    fireEvent.click(screen.getByRole("button", { name: "Switch to Unavailable organization" }));
    await screen.findByText("Could not load the overview.");
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("Get started")).toBeNull();

    await act(async () => resolveWaiting({ data: { ...OV(), members: 91, devices: 92 } }));
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("91")).toBeNull();
    expect(screen.getByText("Could not load the overview.")).toBeTruthy();
    expect(leakedCommits.length).toBeGreaterThan(0);
    expect(leakedCommits).not.toContain(true);
  });

  it("withdraws committed facts when the actor changes in the same organization", async () => {
    let switchedActor = false;
    const leakedCommits: boolean[] = [];
    function ActorControls() {
      const { state, setUser } = useAuth();
      return <button onClick={() => {
        if (state.status !== "authed") return;
        switchedActor = true;
        overviewReads.set("org-1", { error: { code: "forbidden", message: "Forbidden" } });
        setUser({ ...state.user, id: "u2" });
      }}>Switch actor</button>;
    }
    render(<MemoryRouter><OrgProvider><AuthProvider><ActorControls />
      <Profiler id="overview-actor" onRender={() => {
        if (switchedActor) leakedCommits.push(Boolean(screen.queryByRole("region", { name: "Fleet summary" }) || screen.queryByText("gitops-platform")));
      }}><Dashboard /></Profiler>
    </AuthProvider></OrgProvider></MemoryRouter>);
    await screen.findByText("gitops-platform");
    fireEvent.click(screen.getByRole("button", { name: "Switch actor" }));
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    await screen.findByText("Could not load the overview.");
    expect(leakedCommits.length).toBeGreaterThan(0);
    expect(leakedCommits).not.toContain(true);
  });

  it("refreshes a failed overview without retaining its error after recovery", async () => {
    overviewFail = true;
    show();
    await screen.findByText("Could not load the overview.");
    overviewFail = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh overview" }));
    const fleet = await screen.findByRole("region", { name: "Fleet summary" });
    expect(within(fleet).getByText("4")).toBeTruthy();
    expect(within(fleet).getByText("7")).toBeTruthy();
    expect(screen.queryByText("Could not load the overview.")).toBeNull();
  });

  it("withdraws stale figures while refresh is pending, then exposes failure rather than old counts", async () => {
    show();
    await screen.findByText("gitops-platform");
    let finishRefresh!: (result: OverviewResult) => void;
    overviewReads.set("org-1", new Promise(resolve => { finishRefresh = resolve; }));
    fireEvent.click(screen.getByRole("button", { name: "Refresh overview" }));
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("gitops-platform")).toBeNull();
    await act(async () => finishRefresh({ error: { code: "unavailable", message: "Unavailable" } }));
    await screen.findByText("Could not load the overview.");
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("Get started")).toBeNull();
  });

  it("refreshes independently failed gateway and site sources after the API recovers", async () => {
    sitesFail = true;
    nodesFail = true;
    show();
    await screen.findByText("Gateway health is unavailable.");
    expect(within(screen.getByRole("group", { name: "Sites" })).queryByText("0")).toBeNull();
    sitesFail = false;
    nodesFail = false;
    fireEvent.click(screen.getByRole("button", { name: "Refresh overview" }));
    await screen.findByRole("figure", { name: "Gateway health summary" });
    await waitFor(() => expect(within(screen.getByRole("group", { name: "Sites" })).getByText("1")).toBeTruthy());
    expect(screen.queryByText("Gateway health is unavailable.")).toBeNull();
    expect(screen.queryByText("could not load")).toBeNull();
  });

  it.each([undefined, -1, Number.NaN, 1.5])("refuses an unreadable overview count (%s) instead of rendering a fleet", async members => {
    overviewReads.set("org-1", { data: { ...OV(), members: members as number } });
    show();
    await screen.findByText("Could not load the overview.");
    expect(screen.queryByRole("region", { name: "Fleet summary" })).toBeNull();
    expect(screen.queryByText("Get started")).toBeNull();
  });

  it.each([null, {}, { mode: "unrecognized-mode" }])("does not infer disabled enforcement from an unreadable mode (%j)", async response => {
    zeroTrustResponse = response;
    show();
    const rules = await screen.findByRole("group", { name: "Access Rules" });
    expect(within(rules).getByText("0")).toBeTruthy();
    expect(within(rules).queryByText(/not enforced|enforcing/i)).toBeNull();
  });

  it("qualifies a paginated agent count as loaded rather than claiming a full fleet total", async () => {
    agentsResponse = {
      items: [
        { device_id: "a1", name: "First agent", status: "active", unattributable: false },
        { device_id: "a2", name: "Second agent", status: "active", unattributable: false },
      ],
      next_cursor: "next-agent-page",
    };
    show();
    const agents = await screen.findByRole("group", { name: "AI Agents" });
    expect(within(agents).getByText("2+")).toBeTruthy();
    expect(within(agents).getByText("Loaded agents")).toBeTruthy();
    const reads = vi.mocked(api.GET).mock.calls as Array<[string, unknown?]>;
    expect(reads.filter(([path]) => path.endsWith("/agents"))).toHaveLength(1);
  });

  it("keeps warn-mode posture failures and unreported OpenVPN liveness separate from passing devices", async () => {
    devicesResponse = [
      { id: "warn", name: "Warn device", status: "active", public_key: "wg-key", platform: "macos", online: true, health_state: "noncompliant", health_blocked: false },
      { id: "ovpn", name: "OpenVPN device", status: "active", public_key: "", platform: "windows", online: true, health_state: "unknown", health_blocked: false },
      { id: "revoked", name: "Revoked device", status: "revoked", public_key: "wg-key", platform: "macos", online: true, health_state: "compliant", health_blocked: false },
    ];
    show();
    const connection = await screen.findByRole("figure", { name: "Peer connection status" });
    const count = (scope: HTMLElement, label: string, expected: string) => {
      const row = within(scope).getByText(label).closest("li");
      expect(row && within(row).getByText(expected)).toBeTruthy();
    };
    count(connection, "Recent handshake", "1");
    count(connection, "Liveness not reported", "1");
    count(connection, "Revoked", "1");
    const posture = screen.getByRole("figure", { name: "Device posture" });
    count(posture, "Compliant", "0");
    count(posture, "Noncompliant", "1");
    count(posture, "Blocked", "0");
    count(posture, "Unknown", "1");
  });

  it.each([
    { suffix: "/nodes", message: "Gateway health is unavailable.", figure: "Gateway health summary", data: {} },
    { suffix: "/devices", message: "Device health is unavailable.", figure: "Device posture", data: {} },
    { suffix: "/nodes", message: "Gateway health is unavailable.", figure: "Gateway health summary", data: [null] },
    { suffix: "/devices", message: "Device health is unavailable.", figure: "Device posture", data: [null] },
  ])("treats an unreadable $suffix inventory as unavailable without affecting authoritative fleet counts", async ({ suffix, message, figure, data }) => {
    inventoryResponses.set(suffix, data);
    show();
    await screen.findByText(message);
    expect(screen.queryByRole("figure", { name: figure })).toBeNull();
    expect(within(screen.getByRole("group", { name: "Members" })).getByText("4")).toBeTruthy();
    expect(within(screen.getByRole("group", { name: "Devices" })).getByText("7")).toBeTruthy();
  });

  it("keeps unreadable site inventory distinct from a confirmed empty network", async () => {
    inventoryResponses.set("/sites", {});
    show();
    const sites = await screen.findByRole("group", { name: "Sites" });
    await waitFor(() => expect(within(sites).getByText("could not load")).toBeTruthy());
    expect(within(sites).queryByText("0")).toBeNull();
    expect(screen.queryByText("Get started")).toBeNull();
  });

  it.each([
    { generation: 1, members: {} },
    { generation: 1, members: [null] },
    { generation: 1, members: [{ node_id: "n1" }] },
    { generation: 1, members: [{ node_id: "n1", role: "unreported-role" }] },
  ])("does not turn an unreadable HA hub set into a missing configuration (%j)", async response => {
    inventoryResponses.set("/hub-set", response);
    show();
    await screen.findByText("The hub set is unavailable.");
    expect(screen.queryByText("No HA hub set. Pin two or more gateways to create one.")).toBeNull();
  });

  it("does not report zero Kubernetes services when that independent inventory is unreadable", async () => {
    inventoryResponses.set("/k8s/services", {});
    show();
    await screen.findByText("Service inventory is unavailable.");
    expect(screen.queryByRole("group", { name: "Kubernetes summary" })).toBeNull();
    expect(within(screen.getByRole("group", { name: "Devices" })).getByText("7")).toBeTruthy();
  });

  it.each([
    ["off", "not enforced"],
    ["enforcing", "enforcing"],
  ])("reports the saved %s enforcement mode without changing policy", async (mode, expected) => {
    zeroTrustResponse = { mode };
    show();
    const rules = await screen.findByRole("group", { name: "Access Rules" });
    expect(within(rules).getByText(expected)).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PATCH).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

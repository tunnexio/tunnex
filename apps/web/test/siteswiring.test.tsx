import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent, within, act } from "@testing-library/react";
import { MemoryRouter, useLocation, useNavigate } from "react-router-dom";

// SLICE 5 — Sites. First of the two SHEDDERS, and the shedder constraint drives how these are written.
//
// ⚠ THE REDESIGN SPLITS THIS SCREEN. `Sites.tsx` keeps `sites` and sheds ROUTED RANGES to a NEW `subnets`
// screen (docs/UI-REDESIGN-registration.md — the wireframe declares `subnets` in the main nav). So every
// assertion below is written against the DECISION and NAMES ITS DESTINATION:
//
//   "a routed range that is PENDING must not read as ROUTED"  -> travels to `subnets`
//   "the Sites page shows a routed-range list"                -> does NOT travel, and would be throwaway work
//
// The decision under test is what the user is told about REACHABILITY. A pending subnet is advertised but NOT
// yet routed; presenting it as routed tells an admin a LAN is reachable when it is not, and the inverse hides
// one that is. Neither is a rendering preference.
//
// QUERY RULES 1-4 BIND: role + accessible name; NETWORK-boundary mocks; decisions not rendering; and no
// assertion may assume a viewport — nothing here depends on layout, column order, or width-conditional
// visibility.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let sitesFail = false;
let haTopology = false;
let routeLanTopology = false;
let inventorySites: { id: string; name: string }[] | null = null;
let multiOrg = false;
let holdOldSiteRead = false;
let finishOldSiteRead: ((value: unknown) => void) | null = null;
let viewerRole: "admin" | "member" = "admin";
let inventoryNodes: Array<{ id: string; name: string; status: "active" | "revoked"; site_id?: string; is_site_hub?: boolean }> | null = null;
let servedHubSet: HubSet | null | undefined;
let hubReadFails = false;
let dnsForwards: Record<string, Array<{ domain: string; resolver_ip: string }> | null> = {};
let holdPin = false;
let finishPin: ((value: { data?: unknown; error?: unknown }) => void) | null = null;

const SITES = [{ id: "s1", name: "aws-site" }];
const SUBNETS = [
  {
    id: "sub-approved",
    site_id: "s1",
    cidr: "172.31.0.0/16",
    status: "approved",
  },
  { id: "sub-pending", site_id: "s1", cidr: "10.50.0.0/16", status: "pending" },
];

const HA_SITES = [
  { id: "site-primary", name: "us-east-dc" },
  { id: "site-standby", name: "eu-lan" },
  { id: "site-spoke", name: "ap-lan" },
  { id: "site-unbound", name: "sa-lan" },
];
const HA_NODES = [
  { id: "hub-primary", name: "gw-us-east", status: "active", site_id: "site-primary", is_site_hub: true },
  { id: "hub-standby", name: "gw-eu-west", status: "active", site_id: "site-standby" },
  { id: "spoke", name: "gw-ap-south", status: "active", site_id: "site-spoke" },
];
const ROUTE_LAN_NODES = [
  { id: "gateway-carrier", name: "gw-unbound-1", status: "active", enrolled_kind: "gateway" },
  { id: "agent-not-carrier", name: "mcp-agent-prod", status: "active", enrolled_kind: "agent" },
];

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string, options?: { params?: { path?: { orgId?: string; siteId?: string } } }) => {
        const orgId = options?.params?.path?.orgId;
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta")
          return { data: { edition: "enterprise", protocol_version: 5 } };
        if (path === "/api/v1/organizations")
          return { data: multiOrg ? [{ id: "org-1", name: "Acme" }, { id: "org-2", name: "Second org" }] : [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: orgId === "org-2" ? "member" : viewerRole, email_verified: true }],
          };
        if (path.endsWith("/sites")) {
          if (orgId === "org-2") return { data: [{ id: "org-b-site", name: "B network" }] };
          if (holdOldSiteRead) return new Promise(resolve => { finishOldSiteRead = resolve; });
          if (sitesFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: inventorySites ?? (haTopology ? HA_SITES : SITES) };
        }
        if (path.endsWith("/nodes")) return { data: inventoryNodes ?? (routeLanTopology ? ROUTE_LAN_NODES : haTopology ? HA_NODES : []) };
        if (path.includes("/subnets")) return { data: orgId === "org-2" ? [] : SUBNETS };
        if (path.endsWith("/site-subnets/pending")) return { data: [] };
        if (path.endsWith("/hub-set")) {
          if (hubReadFails) return { error: { message: "Hub read failed" } };
          if (servedHubSet !== undefined) return { data: servedHubSet };
          return haTopology
            ? {
                data: {
                  generation: 9,
                  members: [
                    { node_id: "hub-primary", role: "primary" },
                    { node_id: "hub-standby", role: "standby" },
                  ],
                },
              }
            : { data: null };
        }
        if (path.endsWith("/dns-forwards")) {
          const rows = dnsForwards[options?.params?.path?.siteId ?? ""];
          return rows === null ? { error: { message: "DNS read failed" } } : { data: rows ?? [] };
        }
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => holdPin ? new Promise<{ data?: unknown; error?: unknown }>(resolve => { finishPin = resolve; }) : { data: {} }),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider, useOrg } from "../src/lib/useOrg";
import Sites from "../src/pages/Sites";
import { AuthProvider } from "../src/lib/auth";
import { crossesMultiSiteThreshold } from "../src/lib/sitesview";
import { api, type HubSet } from "../src/lib/api";

// The REAL AuthProvider — stubbing the context puts the TEST's role gate under assertion, not the PRODUCT's.
const withAuth = (ui: React.ReactElement, initialEntries = ["/sites"], initialIndex?: number) =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <AuthProvider>
      <MemoryRouter initialEntries={initialEntries} initialIndex={initialIndex}>
        <OrgProvider>{ui}<LocationProbe /><HistoryControls /></OrgProvider>
      </MemoryRouter>
    </AuthProvider>,
  );

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.search}</output>;
}

function HistoryControls() {
  const navigate = useNavigate();
  return <><button type="button" onClick={() => navigate(-1)}>History back</button><button type="button" onClick={() => navigate(1)}>History forward</button></>;
}

function OrgControls() {
  const { setOrg } = useOrg();
  return <button onClick={() => setOrg("org-2")}>Switch organization</button>;
}

beforeEach(() => {
  vi.clearAllMocks();
  sitesFail = false;
  haTopology = false;
  routeLanTopology = false;
  inventorySites = null;
  multiOrg = false;
  holdOldSiteRead = false;
  finishOldSiteRead = null;
  viewerRole = "admin";
  inventoryNodes = null;
  servedHubSet = undefined;
  hubReadFails = false;
  dnsForwards = {};
  holdPin = false;
  finishPin = null;
  window.localStorage.removeItem("tunnex.currentOrg");
});

async function openRangeDetails() {
  fireEvent.click(await screen.findByRole("button", { name: "aws-site" }));
  fireEvent.click(within(await screen.findByRole("navigation", { name: "Network detail sections" })).getByRole("button", { name: "Ranges" }));
}

describe("Sites — wiring: a routed range must not lie about REACHABILITY (destination: `subnets`)", () => {
  it("a PENDING range is marked pending; an APPROVED one is not — the two must stay distinguishable", async () => {
    withAuth(<Sites />);
    await openRangeDetails();
    // WAIT ON THE THING BEING ASSERTED. The first draft waited on the CIDR text and then queried the title —
    // which raced a partially-rendered tree and passed locally while failing in the gate's container. A
    // waitFor whose condition is weaker than the assertion is not synchronisation, it is luck.
    // Timeout raised above waitFor's 1s default: the FIRST test in a file pays module-init + the page's
    // multi-request load chain, and the gate's container is slower than a dev machine. Evidence it is latency
    // and not absence: the next test asserts the SAME element and passes. A default that works locally and
    // times out in CI is the local-equivalent trap one layer down.
    // WAIT FOR BOTH, then assert. Waiting on only one let the test proceed while the other had not rendered:
    // pending appears BEFORE approved, so test 1 raced ahead and failed on the approved chip while test 2 —
    // which happened to wait on the LATER one — passed. Two tests over the same elements disagreeing is the
    // tell. The rule generalises: a waitFor must cover EVERY element the assertions touch, not the first one
    // that happens to appear.
    const [pendingEl, approvedEl] = await waitFor(
      () => [
        screen.getByRole("listitem", {
          name: /Pending approval, not yet routed/,
        }),
        screen.getByRole("listitem", { name: /Approved, routed/ }),
      ],
      { timeout: 5000 },
    );

    // The decision: pending means ADVERTISED BUT NOT ROUTED. If both rendered identically an admin would read
    // an unapproved LAN as reachable — or, inverted, treat a routed one as still waiting.
    //
    // Queried BY TITLE (the accessible name), not by a regex spanning sibling text nodes. The first draft did
    // the latter and passed locally while FAILING IN THE GATE'S CONTAINER: `{s.cidr}` and `" · pending"` are
    // separate JSX children, so matching across them depends on how a given @testing-library/dom build
    // normalizes whitespace between nodes. That is a DOM-STRUCTURE dependency, which query rule 1 forbids —
    // and the gate caught it, which is the argument for running the gate's own command.
    expect(pendingEl.textContent).toContain("10.50.0.0/16");
    expect(pendingEl.textContent).toContain("pending");

    expect(approvedEl.textContent).toContain("172.31.0.0/16");
    expect(approvedEl.textContent).not.toContain("pending");
  });

  // ⛔ QUERIED BY ROLE + ACCESSIBLE NAME (query rule 1), not by `title`.
  //
  // These asserted `getByTitle`, which is neither a role nor an accessible name — and the chip it queried was
  // a role-less <span> whose `title` a screen reader does not reliably announce. So the test was BOTH a rule-1
  // violation AND evidence of a real defect: the reachability claim, load-bearing in two assertions, was not
  // announced to anyone using assistive tech.
  //
  // THE FIX WAS THE CHIP, NOT THE QUERY. It is now role="listitem" inside role="list", with an aria-label
  // carrying the range AND its state. Fixing the query alone would have kept the test green over a chip that
  // still said nothing.
  it("the reachability claim is carried in the accessible name, not by colour alone", async () => {
    withAuth(<Sites />);
    await openRangeDetails();
    // ⛔ THE WAITFOR COVERS BOTH TITLES, AND IT DID NOT UNTIL S14.5.
    //
    // It waited for "Approved, routed" alone and then asserted on the PENDING one — the exact defect the test
    // directly above documents in its own comment, one test down, unnoticed. It passed for months because
    // both chips render in the same commit; it started failing only when the FULL suite ran slower than the
    // file alone, which is the definition of a race that was always there.
    //
    // SAME SHAPE AS THE MISSING-PRIMITIVE LAW: a lesson written at one call site does not reach the call site
    // beside it. Writing the rule in a comment is not applying it.
    const [approvedEl, pendingEl] = await waitFor(
      () => [
        screen.getByRole("listitem", { name: /Approved, routed/ }),
        screen.getByRole("listitem", {
          name: /Pending approval, not yet routed/,
        }),
      ],
      { timeout: 5000 },
    );
    // The pending counterpart must say the opposite in words. Colour-only differentiation would fail both a
    // screen reader and the accessibility gate the redesign now carries (registration consequence 1).
    expect(approvedEl).toBeTruthy();
    expect(pendingEl).toBeTruthy();
  });

  // The CW crossing decision, asserted through the production function rather than restated. It travels with
  // routed ranges to `subnets`: approving a range that makes the org multi-site routable for the FIRST time is
  // the moment that needs a confirm, and it is a property of the ranges, not of the page.
  it("crossing into multi-site routability is detected only on the FIRST crossing", () => {
    // The approving site contributes nothing yet and exactly one OTHER site does -> this approval crosses.
    expect(crossesMultiSiteThreshold("s2", { s1: 1 })).toBe(true);
    // Already contributing -> not a crossing.
    expect(crossesMultiSiteThreshold("s1", { s1: 1 })).toBe(false);
    // Nobody else routes yet -> still single-site.
    expect(crossesMultiSiteThreshold("s2", {})).toBe(false);
    // Already multi-site -> the crossing happened earlier; do not re-confirm.
    expect(crossesMultiSiteThreshold("s3", { s1: 1, s2: 1 })).toBe(false);
  });
});

describe("Sites — served HA topology", () => {
  it("renders the fixture-shaped primary and standby as distinct keyboard-reachable topology members", async () => {
    haTopology = true;
    withAuth(<Sites />);
    fireEvent.click(await screen.findByRole("link", { name: /^Topology/ }));

    await waitFor(() => {
      expect(screen.getByRole("button", { name: /gw-us-east.*primary/i })).toBeTruthy();
      expect(screen.getByRole("button", { name: /gw-eu-west.*standby/i })).toBeTruthy();
    });
    expect(document.querySelectorAll('[data-node-kind="hub"]')).toHaveLength(1);
    expect(document.querySelectorAll('[data-node-kind="hub-standby"]')).toHaveLength(1);
    expect(document.querySelectorAll('[data-node-kind="spoke"]')).toHaveLength(4);
    fireEvent.click(screen.getByRole("link", { name: /^Inventory/ }));
    expect(screen.queryByRole("figure", { name: "Site topology" })).toBeNull();
    expect(screen.getByRole("link", { name: /^Inventory/ }).getAttribute("aria-current")).toBe("page");
    expect(screen.getByRole("table", { name: "Sites" })).toBeTruthy();
  });
});

describe("Sites map search is an observable focus interaction", () => {
  it("lists a Site result and keyboard-selects it into URL-backed context", async () => {
    withAuth(<Sites />, ["/sites"]);
    fireEvent.click(await screen.findByRole("link", { name: /^Topology/ }));
    const input = await screen.findByRole("combobox", { name: "Search Sites or Gateways" });
    fireEvent.change(input, { target: { value: "aws" } });
    const result = await screen.findByRole("option", { name: /aws-site.*Site/ });
    expect(result).toBeTruthy();
    fireEvent.keyDown(input, { key: "Enter" });
    await waitFor(() => expect(screen.getByLabelText(/Selected Site: aws-site/)).toBeTruthy());
    expect(screen.getByTestId("location").textContent).toContain("site=s1");
  });

  it("names an eligible unbound Gateway instead of inventing a topology location", async () => {
    routeLanTopology = true;
    withAuth(<Sites />, ["/sites"]);
    fireEvent.click(await screen.findByRole("link", { name: /^Topology/ }));
    const input = await screen.findByRole("combobox", { name: "Search Sites or Gateways" });
    fireEvent.change(input, { target: { value: "unbound" } });
    expect(await screen.findByRole("option", { name: /gw-unbound-1.*Eligible unbound Gateway/ })).toBeTruthy();
    fireEvent.keyDown(input, { key: "Enter" });
    expect(await screen.findByText("Unbound Gateway")).toBeTruthy();
    expect(screen.getByText(/No Site is bound/)).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toContain("gateway=gateway-carrier");
  });
});

describe("Sites — URL-backed workspace state", () => {
  it("canonicalizes a stale direct operational-section URL with replace semantics", async () => {
    withAuth(<Sites />, ["/sites?section=ha&site=s1&gateway=g1&q=aws&dns=1"]);
    await waitFor(() =>
      expect(screen.getByRole("link", { name: /^Failover/ }).getAttribute("aria-current")).toBe("page"),
    );
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=ha"));
  });

  it.each(["approvals", "dns"])("canonicalizes stale direct %s URLs", async (targetSection) => {
    withAuth(<Sites />, [`/sites?section=${targetSection}&site=s1&q=aws&dns=1`]);
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe(`?section=${targetSection}`));
  });

  it("keeps the canonical operational URL through Back and Forward", async () => {
    withAuth(
      <Sites />,
      ["/sites?section=overview&site=s1", "/sites?section=dns&site=s1&dns=1"],
      1,
    );
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=dns"));
    fireEvent.click(screen.getByRole("button", { name: "History back" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=overview&site=s1"));
    fireEvent.click(screen.getByRole("button", { name: "History forward", hidden: true }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=dns"));
  });

  it("clears Overview-only context when changing to an operational section", async () => {
    withAuth(<Sites />, ["/sites?site=s1&gateway=g1&q=aws&dns=1"]);
    fireEvent.click(within(await screen.findByRole("navigation", { name: "Network breadcrumb" })).getByRole("link", { name: "Networks" }));
    fireEvent.click(await screen.findByRole("link", { name: /^Range approvals/ }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=approvals"));
  });

  it("keeps DNS forwarding out of primary navigation and exposes it as advanced Site Networking", async () => {
    withAuth(<Sites />, ["/sites"]);
    fireEvent.click(await screen.findByText("Advanced setup"));
    expect(await screen.findByRole("button", { name: "Review DNS forwarding" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "DNS overview" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Review DNS forwarding" }));
    await waitFor(() => expect(screen.getByTestId("location").textContent).toBe("?section=dns"));
    fireEvent.click(screen.getByText("About DNS forwarding"));
    expect(screen.getByText(/Private DNS Resolver remains the only primary configuration for FQDN access/)).toBeTruthy();
  });

  it("uses selected-Site approved-range guidance for the DNS resolver without prefilling it", async () => {
    withAuth(<Sites />, ["/sites?section=overview&site=s1&dns=1"]);
    const resolver = await screen.findByLabelText("Forwarding target IP");
    expect(resolver.getAttribute("placeholder")).toBe("Resolver IP inside 172.31.0.0/16");
    expect((resolver as HTMLInputElement).value).toBe("");
  });

  it("keeps the selected network in context while focused sections retain existing mutation access", async () => {
    haTopology = true;
    withAuth(<Sites />, ["/sites?site=site-primary"]);

    await waitFor(() =>
      expect(screen.getByLabelText("Selected Site: us-east-dc")).toBeTruthy(),
    );
    expect(screen.queryByRole("dialog", { name: "us-east-dc" })).toBeNull();
    const breadcrumb = screen.getByRole("navigation", { name: "Network breadcrumb" });
    expect(within(breadcrumb).getByText("us-east-dc").getAttribute("aria-current")).toBe("page");
    const sections = screen.getByRole("navigation", { name: "Network detail sections" });
    expect(within(sections).getByRole("button", { name: "Overview" }).getAttribute("aria-current")).toBe("page");
    fireEvent.click(within(sections).getByRole("button", { name: "Ranges" }));
    expect(screen.getByRole("button", { name: "Advertise subnet" })).toBeTruthy();
    expect(screen.getByRole("heading", { level: 2, name: "Ranges" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toContain("detail=ranges");
    fireEvent.click(within(sections).getByRole("button", { name: "Gateways" }));
    expect(screen.getByRole("button", { name: "Unbind gateway" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toContain("detail=gateways");
    fireEvent.click(within(sections).getByRole("button", { name: "Advanced" }));
    fireEvent.click(screen.getByText("Lifecycle actions"));
    expect(screen.getByRole("button", { name: "Delete site" })).toBeTruthy();
    expect(screen.getByText("Danger zone")).toBeTruthy();
    expect(screen.getByText("Advanced cloud routing").closest("details")?.hasAttribute("open")).toBe(false);
    expect(screen.getByText("Advanced Site DNS forwarding").closest("details")?.hasAttribute("open")).toBe(false);
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
    fireEvent.click(within(breadcrumb).getByRole("link", { name: "Networks" }));
    await waitFor(() => expect(screen.queryByRole("region", { name: "Selected Site: us-east-dc" })).toBeNull());
    expect(screen.getByTestId("location").textContent).not.toContain("site=");
    expect(screen.getByTestId("location").textContent).not.toContain("detail=");
    expect(screen.getByRole("table", { name: "Sites" })).toBeTruthy();
    expect(screen.queryByText("Select a Site")).toBeNull();
  });
});

describe("Networks — inventory paging", () => {
  it("withdraws old network data and permissions and discards a late prior-organization read", async () => {
    multiOrg = true;
    withAuth(<><Sites /><OrgControls /></>, ["/sites?site=s1"]);
    await screen.findByRole("region", { name: "Selected Site: aws-site" });
    holdOldSiteRead = true;
    fireEvent.click(screen.getByRole("button", { name: "Refresh networks" }));
    await waitFor(() => expect(finishOldSiteRead).not.toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Switch organization" }));
    expect(screen.queryByRole("region", { name: "Selected Site: aws-site" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Route a LAN" })).toBeNull();
    await screen.findByRole("button", { name: "B network" });
    await act(async () => { finishOldSiteRead?.({ data: [{ id: "late-old-site", name: "Late old network" }] }); });
    expect(screen.getByRole("button", { name: "B network" })).toBeTruthy();
    expect(screen.queryByText("aws-site")).toBeNull();
    expect(screen.queryByText("Late old network")).toBeNull();
    expect(screen.queryByRole("button", { name: "Route a LAN" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("uses real 20, 10 and 50 row limits and resets paging when the search changes", async () => {
    inventorySites = Array.from({ length: 55 }, (_, index) => ({ id: `site-${index}`, name: `Network ${String(index).padStart(3, "0")}` }));
    withAuth(<Sites />, ["/sites"]);
    const table = await screen.findByRole("table", { name: "Sites" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    expect(screen.getByRole("button", { name: "Network 000" })).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(screen.getAllByRole("row")).toHaveLength(11);
    fireEvent.click(screen.getByRole("button", { name: "Next networks" }));
    expect(screen.getByRole("button", { name: "Network 010" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Network 000" })).toBeNull();
    expect(screen.getByTestId("location").textContent).toContain("page=2");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(screen.getAllByRole("row")).toHaveLength(51);
    expect(screen.getByTestId("location").textContent).toContain("page_size=50");
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    fireEvent.click(screen.getByRole("button", { name: "Next networks" }));
    expect(screen.getAllByRole("row")).toHaveLength(6);
    expect(screen.getByText("51–55 shown")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Next networks" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("button", { name: "Previous networks" })).toHaveProperty("disabled", false);
    fireEvent.click(screen.getByRole("button", { name: "Previous networks" }));
    expect(screen.getByRole("button", { name: "Network 000" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next networks" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search networks" }), { target: { value: "Network 054" } });
    expect(screen.getAllByRole("row")).toHaveLength(2);
    expect(screen.getByRole("button", { name: "Network 054" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.change(screen.getByRole("textbox", { name: "Search networks" }), { target: { value: "" } });
    expect(screen.getAllByRole("row")).toHaveLength(51);
    expect(screen.getByRole("button", { name: "Network 000" })).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

describe("Sites — Route a LAN carrier eligibility", () => {
  it("offers only a server-declared active gateway, never an AI Agent Node", async () => {
    routeLanTopology = true;
    withAuth(<Sites />);
    await waitFor(() => expect(screen.getByRole("button", { name: "Route a LAN" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Route a LAN" }));
    expect(screen.getByRole("option", { name: "gw-unbound-1" })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "mcp-agent-prod" })).toBeNull();
  });
});

describe("Sites — failure path", () => {
  // D1(b). On this surface an empty topology reads as "this org has no sites" — a statement about the network
  // that a failed load has no standing to make.
  it("a failed sites load renders a retry, not an empty topology", async () => {
    sitesFail = true;
    withAuth(<Sites />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy(),
    );
  });
});


describe("Networks — gateway assignment is not tunnel health", () => {
  it("shows assignment without claiming a live connection when health is missing", async () => {
    haTopology = true;
    withAuth(<Sites />, ["/sites"]);
    expect(await screen.findByRole("columnheader", { name: "Gateway status" })).toBeTruthy();
    expect(screen.getAllByRole("cell", { name: "Assigned" }).length).toBeGreaterThan(0);
    expect(screen.queryByRole("cell", { name: "linked" })).toBeNull();
    expect(screen.getByRole("link", { name: /Set up a network/ }).getAttribute("href")).toBe("/network/setup");
  });
});

async function chooseRowAction(triggerName: string, action: string) {
  fireEvent.click(screen.getByRole("button", { name: triggerName }));
  fireEvent.click(within(screen.getByRole("menu", { name: triggerName })).getByRole("menuitem", { name: action }));
}

describe("Networks — Failover reports and protected candidates", () => {
  it("keeps acting roles and demotion truthful, with idle and absent counters distinct in report details", async () => {
    haTopology = true;
    servedHubSet = {
      generation: 12,
      members: [
        { node_id: "hub-primary", role: "primary", hub_priority: 2, metrics: { last_handshake_at: new Date().toISOString(), rx_bytes: 0, tx_bytes: 0 } },
        { node_id: "hub-standby", role: "standby", hub_priority: 1 },
      ],
    };
    withAuth(<Sites />, ["/sites?section=ha"]);
    const table = await screen.findByRole("table", { name: "Transit hubs" });
    const actingPrimary = within(table).getByRole("link", { name: "gw-us-east" }).closest("tr")!;
    const configuredPrimary = within(table).getByRole("link", { name: "gw-eu-west" }).closest("tr")!;
    expect(within(actingPrimary).getByRole("cell", { name: "Primary" })).toBeTruthy();
    expect(within(actingPrimary).getByRole("cell", { name: "Recent" })).toBeTruthy();
    expect(within(configuredPrimary).getByText("Configured primary · demoted")).toBeTruthy();
    expect(screen.getByText("Standby promoted to acting primary.")).toBeTruthy();
    expect(screen.queryByText("0 B")).toBeNull();

    await chooseRowAction("Hub actions for gw-us-east", "Report details");
    const reported = screen.getByRole("dialog", { name: "gw-us-east" });
    expect(within(reported).getAllByText("0 B")).toHaveLength(2);
    expect(within(reported).getByText("Received")).toBeTruthy();
    expect(within(reported).getByText("Sent")).toBeTruthy();
    fireEvent.click(within(reported).getByRole("button", { name: "Done" }));
    await chooseRowAction("Hub actions for gw-eu-west", "Report details");
    const absent = screen.getByRole("dialog", { name: "gw-eu-west" });
    expect(within(absent).getAllByText("Not reported")).toHaveLength(3);
    expect(within(absent).queryByText("0 B")).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("pages actual candidates and calculates the next pin from the full hub set after filtering", async () => {
    inventoryNodes = Array.from({ length: 55 }, (_, index) => ({ id: `candidate-${index}`, name: `Gateway ${String(index).padStart(3, "0")}`, site_id: "s1", status: "active" as const }));
    servedHubSet = { generation: 7, members: [{ node_id: "candidate-0", role: "primary", hub_priority: 1 }, { node_id: "candidate-1", role: "standby", hub_priority: 8 }] };
    withAuth(<Sites />, ["/sites?section=ha"]);
    fireEvent.click(await screen.findByRole("button", { name: "Manage candidates" }));
    const dialog = screen.getByRole("dialog", { name: "Hub candidates" });
    const candidates = () => within(dialog).getByRole("list", { name: "Hub candidates" });
    expect(within(candidates()).getAllByRole("listitem")).toHaveLength(20);
    fireEvent.click(within(dialog).getByRole("button", { name: "Next hub candidates" }));
    expect(within(candidates()).getByText("Gateway 020")).toBeTruthy();
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(candidates()).getAllByRole("listitem")).toHaveLength(50);
    fireEvent.click(within(dialog).getByRole("button", { name: "Next hub candidates" }));
    expect(within(candidates()).getAllByRole("listitem")).toHaveLength(5);
    expect(within(dialog).getByRole("button", { name: "Previous hub candidates" })).toHaveProperty("disabled", false);
    fireEvent.change(within(dialog).getByRole("textbox", { name: "Search Hub candidates" }), { target: { value: "Gateway 054" } });
    expect(within(candidates()).getAllByRole("listitem")).toHaveLength(1);
    expect(within(dialog).queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
    fireEvent.click(within(within(candidates()).getByText("Gateway 054").closest("li")!).getByRole("button", { name: "Pin #9" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority", { params: { path: { orgId: "org-1", nodeId: "candidate-54" } }, body: { priority: 9 } }));
    expect(api.PUT).toHaveBeenCalledTimes(1);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Hub candidates" })).toBeNull());
    fireEvent.click(await screen.findByRole("button", { name: "Manage candidates" }));
    const reopened = screen.getByRole("dialog", { name: "Hub candidates" });
    fireEvent.click(within(within(reopened).getByText("Gateway 000").closest("li")!).getByRole("button", { name: "Unpin" }));
    await waitFor(() => expect(api.PUT).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority", { params: { path: { orgId: "org-1", nodeId: "candidate-0" } }, body: { priority: null } }));
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("allows members to read reports without candidate mutations, even when only one gateway remains", async () => {
    viewerRole = "member";
    inventoryNodes = [{ id: "hub-primary", name: "Remaining hub", status: "active", site_id: "s1" }];
    servedHubSet = { generation: 5, members: [{ node_id: "hub-primary", role: "primary", hub_priority: 1 }] };
    withAuth(<Sites />, ["/sites?section=ha"]);
    expect(await screen.findByRole("table", { name: "Transit hubs" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Manage candidates" })).toBeNull();
    await chooseRowAction("Hub actions for Remaining hub", "Report details");
    expect(screen.getByRole("dialog", { name: "Remaining hub" })).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: /Pin|Set primary|Unpin/ })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("blocks repeated candidate writes while busy and retains the failed preference for an explicit retry", async () => {
    haTopology = true;
    servedHubSet = { generation: 4, members: [{ node_id: "hub-primary", role: "primary", hub_priority: 1 }, { node_id: "hub-standby", role: "standby", hub_priority: 2 }] };
    holdPin = true;
    withAuth(<Sites />, ["/sites?section=ha"]);
    fireEvent.click(await screen.findByRole("button", { name: "Manage candidates" }));
    const dialog = screen.getByRole("dialog", { name: "Hub candidates" });
    const append = within(dialog).getByRole("button", { name: "Pin #3" });
    fireEvent.click(append);
    expect(append).toHaveProperty("disabled", true);
    expect(within(dialog).getAllByRole("button", { name: "Unpin" }).every(button => (button as HTMLButtonElement).disabled)).toBe(true);
    expect(within(dialog).getByRole("button", { name: "Done" })).toHaveProperty("disabled", true);
    fireEvent.click(append);
    fireEvent.click(within(dialog).getAllByRole("button", { name: "Unpin" })[0]);
    expect(api.PUT).toHaveBeenCalledTimes(1);
    await act(async () => { finishPin?.({ error: { message: "Preference refused" } }); });
    expect(within(dialog).getByText("Could not set the hub priority.")).toBeTruthy();
    expect(append).toHaveProperty("disabled", false);
    holdPin = false;
    fireEvent.click(append);
    await waitFor(() => expect(screen.queryByRole("dialog", { name: "Hub candidates" })).toBeNull());
    expect(api.PUT).toHaveBeenCalledTimes(2);
    expect(api.PUT).toHaveBeenLastCalledWith("/api/v1/organizations/{orgId}/nodes/{nodeId}/hub-priority", { params: { path: { orgId: "org-1", nodeId: "spoke" } }, body: { priority: 3 } });
  });

  it("explains a lone gateway prerequisite without offering a meaningless pin action", async () => {
    inventoryNodes = [{ id: "lone", name: "Lone gateway", status: "active", site_id: "s1" }];
    withAuth(<Sites />, ["/sites?section=ha"]);
    expect(await screen.findByRole("heading", { name: "Add another gateway" })).toBeTruthy();
    expect(screen.getByRole("link", { name: "View gateways" }).getAttribute("href")).toBe("/gateways");
    expect(screen.queryByRole("button", { name: "Manage candidates" })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("does not treat a failed hub read as an unpinned set and restores controls only after a successful retry", async () => {
    haTopology = true;
    hubReadFails = true;
    withAuth(<Sites />, ["/sites?section=ha"]);
    expect(await screen.findByRole("heading", { name: "Hub configuration unavailable" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Manage candidates" })).toBeNull();
    expect(screen.queryByRole("table", { name: "Transit hubs" })).toBeNull();
    hubReadFails = false;
    fireEvent.click(screen.getByRole("button", { name: "Retry hub configuration" }));
    expect(await screen.findByRole("table", { name: "Transit hubs" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Manage candidates" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "Hub configuration unavailable" })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });
});

describe("Networks — complete DNS projection and focused handoff", () => {
  function manyForwardingNetworks() {
    inventorySites = Array.from({ length: 21 }, (_, index) => ({ id: `dns-site-${index}`, name: `Network ${String(index).padStart(3, "0")}` }));
    for (let index = 0; index < 21; index++) dnsForwards[`dns-site-${index}`] = [{ domain: "shared.test", resolver_ip: index === 20 ? "10.2.0.53" : "10.1.0.53" }];
    dnsForwards["dns-site-0"]!.push({ domain: "unique.test", resolver_ip: "10.1.0.54" });
  }

  it("detects a resolver disagreement beyond the first page and shows all zone targets independently of list filters", async () => {
    manyForwardingNetworks();
    withAuth(<Sites />, ["/sites?section=dns"]);
    const table = await screen.findByRole("table", { name: "DNS forwarding" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    expect(within(table).getAllByRole("cell", { name: "Conflict" })).toHaveLength(20);
    expect(within(table).queryByRole("cell", { name: "10.2.0.53" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next DNS forwards" }));
    expect(within(table).getAllByRole("row")).toHaveLength(3);
    expect(within(table).getByRole("cell", { name: "10.2.0.53" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Previous DNS forwards" })).toHaveProperty("disabled", false);
    fireEvent.change(screen.getByRole("textbox", { name: "Search DNS forwards" }), { target: { value: "Network 020" } });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.click(within(table).getByRole("button", { name: "shared.test" }));
    const detail = screen.getByRole("region", { name: "shared.test forwarding" });
    const targets = within(detail).getByRole("table", { name: "Zone resolver targets" });
    expect(within(targets).getAllByRole("row")).toHaveLength(21);
    expect(within(detail).getByText("Multiple resolvers for this zone. Keep one target IP across networks.")).toBeTruthy();
    expect(within(screen.getByRole("navigation", { name: "DNS forwarding breadcrumb" })).getByText("shared.test").getAttribute("aria-current")).toBe("page");
    fireEvent.click(within(detail).getByRole("button", { name: "Next resolver targets" }));
    expect(within(targets).getAllByRole("row")).toHaveLength(2);
    expect(within(targets).getByRole("cell", { name: "10.2.0.53" })).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
    await chooseRowAction("DNS actions for shared.test in Network 020", "Edit forwarding in Network 020");
    const selected = await screen.findByRole("region", { name: "Selected Site: Network 020" });
    expect(within(selected).getByRole("button", { name: "Advanced" }).getAttribute("aria-current")).toBe("page");
    expect(within(selected).getByText("Advanced Site DNS forwarding").closest("details")?.hasAttribute("open")).toBe(true);
    expect(screen.getByTestId("location").textContent).toContain("site=dns-site-20");
    expect(screen.getByTestId("location").textContent).toContain("dns=1");
    expect(screen.getByTestId("location").textContent).toContain("section=overview");
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("resets paging for status, search and page-size changes while retaining real clean and conflicting records", async () => {
    manyForwardingNetworks();
    withAuth(<Sites />, ["/sites?section=dns"]);
    const table = await screen.findByRole("table", { name: "DNS forwarding" });
    fireEvent.click(screen.getByRole("button", { name: "Next DNS forwards" }));
    expect(within(table).getByRole("cell", { name: "Configured" })).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "DNS forwarding status" }), { target: { value: "conflicts" } });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    expect(screen.getByText("Page 1")).toBeTruthy();
    expect(within(table).queryByRole("cell", { name: "Configured" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Next DNS forwards" }));
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(screen.getByText("Page 1")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Next DNS forwards" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search DNS forwards" }), { target: { value: "not-configured.test" } });
    expect(screen.getByRole("heading", { name: "No matching forwards" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "DNS forwarding" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(screen.getByRole("combobox", { name: "DNS forwarding status" })).toHaveProperty("value", "all");
    expect(screen.getByRole("textbox", { name: "Search DNS forwards" })).toHaveProperty("value", "");
    expect(screen.getByText("Page 1")).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox", { name: "Search DNS forwards" }), { target: { value: "unique.test" } });
    expect(screen.getByRole("cell", { name: "Configured" })).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Show conflicting forwards" }));
    expect(screen.getByRole("textbox", { name: "Search DNS forwards" })).toHaveProperty("value", "");
    expect(screen.getByRole("combobox", { name: "DNS forwarding status" })).toHaveProperty("value", "conflicts");
    expect(screen.getAllByRole("cell", { name: "Conflict" })).toHaveLength(10);
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("names failed reads above the remaining records and never claims an empty or conflict-free complete list", async () => {
    inventorySites = [{ id: "s1", name: "Loaded network" }, { id: "failed", name: "Unavailable network" }];
    dnsForwards = { s1: [{ domain: "corp.test", resolver_ip: "10.1.0.53" }], failed: null };
    withAuth(<Sites />, ["/sites?section=dns"]);
    const table = await screen.findByRole("table", { name: "DNS forwarding" });
    const notice = screen.getByText(/Could not read zones from Unavailable network/).closest('[role="status"]')!;
    expect(notice.textContent).toContain("conflicts cannot be ruled out");
    expect(notice.compareDocumentPosition(table) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(screen.getByText("1 loaded forwards")).toBeTruthy();
    expect(screen.queryByText(/No conflicts/)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "corp.test" }));
    expect(screen.getByRole("region", { name: "corp.test forwarding" }).textContent).toContain("conflicts cannot be ruled out");
    fireEvent.click(screen.getByRole("button", { name: "Back to DNS forwarding" }));
    dnsForwards.failed = [{ domain: "corp.test", resolver_ip: "10.2.0.53" }];
    fireEvent.click(screen.getByRole("button", { name: "Retry DNS reads" }));
    await waitFor(() => expect(screen.getAllByRole("cell", { name: "Conflict" })).toHaveLength(2));
    expect(screen.queryByText(/Could not read zones from/)).toBeNull();
    expect(screen.queryByText("1 loaded forwards")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("keeps all-failed reads distinct from a genuinely empty configuration", async () => {
    dnsForwards.s1 = null;
    withAuth(<Sites />, ["/sites?section=dns"]);
    expect(await screen.findByRole("heading", { name: "No records loaded" })).toBeTruthy();
    expect(screen.getByText(/Could not read zones from aws-site/)).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "No forwarded zones" })).toBeNull();
    dnsForwards.s1 = [];
    fireEvent.click(screen.getByRole("button", { name: "Retry DNS reads" }));
    expect(await screen.findByRole("heading", { name: "No forwarded zones" })).toBeTruthy();
    expect(screen.queryByRole("heading", { name: "No records loaded" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Retry DNS reads" })).toBeNull();
  });

  it("lets members inspect zone targets without exposing the per-network edit handoff", async () => {
    viewerRole = "member";
    dnsForwards.s1 = [{ domain: "corp.test", resolver_ip: "10.1.0.53" }];
    withAuth(<Sites />, ["/sites?section=dns"]);
    await screen.findByRole("table", { name: "DNS forwarding" });
    fireEvent.click(screen.getByRole("button", { name: "DNS actions for corp.test in aws-site" }));
    const menu = screen.getByRole("menu", { name: "DNS actions for corp.test in aws-site" });
    expect(within(menu).queryByRole("menuitem", { name: /Edit forwarding/ })).toBeNull();
    fireEvent.click(within(menu).getByRole("menuitem", { name: "Zone details" }));
    const detail = screen.getByRole("region", { name: "corp.test forwarding" });
    expect(within(detail).getByRole("cell", { name: "10.1.0.53" })).toBeTruthy();
    expect(within(detail).queryByRole("button", { name: /DNS actions for/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Back to DNS forwarding" }));
    expect(screen.getByRole("table", { name: "DNS forwarding" })).toBeTruthy();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

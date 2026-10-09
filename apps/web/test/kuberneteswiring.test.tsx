import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, cleanup, within, act } from "@testing-library/react";
import { MemoryRouter, useLocation } from "react-router-dom";

// SLICE 3 — Kubernetes. Ranked above Access by the stated criterion: both survive the redesign intact, but this
// screen CARRIES ONE OF THE FOUR WALK FINDINGS while Access's case is consequence-based.
//
// WF-S11-7 was an UNRENDERED HEALTH KIND — `k8s_endpoints_unavailable` shipped in the Go enum and the metrics
// and reached neither the spec nor the renderer, so it fell through to a generic badge and its named remedy was
// invisible. It is the canonical producer-without-consumer instance this repo cites everywhere.
//
// So the wiring test for this screen is a MIRROR CENSUS, not a page assertion: every kind the API can emit must
// reach a renderer. That is the same shape as the server-side TestEveryHealthKindReachesItsMirrorSurfaces, and
// it is the check that would have caught WF-S11-7 the day it shipped.
//
// QUERY STRATEGY (docs/UI-REDESIGN-registration.md consequence 2): role + accessible name; mocked at the
// NETWORK boundary; getByText only where no role exists today, each use a marker for the redesign.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let clustersFail = false;
let currentRole = "admin";
let operatorManaged = true;
let clusterProvider = "unknown";
let clusterPlatform = "unknown";
let poolActiveNodeId: string | null = null;
let poolUnavailable = false;
let currentVerified = true;
let multiOrg = false;
let holdOldClusterRead = false;
let finishOldClusterRead: ((value: unknown) => void) | null = null;
let clusterInventory: Array<(typeof CLUSTERS)[number] & { connector_node_id?: string | null; vip_range?: string; service_cidr?: string; dns_zone?: string; dns_vip?: string }> | null = null;
let serviceInventory: typeof SERVICES | null = null;
const CLUSTERS = [
  { id: "c1", name: "prod-cluster", site_id: "s1", provider: "unknown", platform: "unknown", managed_by_operator: false },
];
const SERVICES = [
  {
    id: "sv1",
    cluster_id: "c1",
    namespace: "default",
    name: "api",
    managed_by_operator: false,
    vip: "100.64.0.5",
    fqdn: "api.default.svc.prod-cluster.demo.test",
    protocol: "tcp",
    port_low: 443,
    port_high: 443,
  },
];

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string, options?: { params?: { path?: { orgId?: string } } }) => {
        const orgId = options?.params?.path?.orgId;
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: currentVerified } };
        if (path === "/api/v1/organizations")
          return { data: multiOrg ? [{ id: "org-1", name: "Acme" }, { id: "org-2", name: "Second organization" }] : [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: orgId === "org-2" ? "member" : currentRole, email_verified: currentVerified }],
          };
        if (path.endsWith("/k8s/clusters")) {
          if (orgId === "org-2") return { data: [{ ...CLUSTERS[0], id: "b-cluster", name: "B cluster" }] };
          if (holdOldClusterRead) return new Promise(resolve => { finishOldClusterRead = resolve; });
          if (clustersFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return {
            data: clusterInventory ?? CLUSTERS.map((cluster) => ({
              ...cluster,
              provider: clusterProvider,
              platform: clusterPlatform,
              managed_by_operator: operatorManaged,
            })),
          };
        }
        if (path.endsWith("/k8s/services")) return { data: orgId === "org-2" ? [] : serviceInventory ?? SERVICES.map((service) => ({ ...service, managed_by_operator: operatorManaged })) };
        if (path.endsWith("/sites"))
          return { data: [{ id: "s1", name: "prod-site" }] };
        if (path.endsWith("/nodes"))
          return {
            data: [{
              id: "n1",
              name: "prod-connector",
              status: "active",
              site_id: "s1",
              endpoint: "connector.internal:51820",
            }],
          };
        if (path.includes("/connector-pool")) {
          if (poolUnavailable) return { error: { error: { code: "temporarily_unavailable", message: "Pool unavailable" } } };
          return poolActiveNodeId === null
            ? { data: undefined, error: { error: { code: "connector_pool_not_found", message: "not configured" } } }
            : { data: { pool_id: "pool-1", cluster_id: "c1", active_node_id: poolActiveNodeId, preferred_node_id: poolActiveNodeId, generation: 1, membership_epoch: 0, membership_epoch_known: true, members: [{ node_id: poolActiveNodeId, admin_priority: 100 }] } };
        }
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider, useOrg } from "../src/lib/useOrg";
import { policyHealthBadge } from "../src/lib/healthview";
import Kubernetes from "../src/pages/Kubernetes";
import { AuthProvider } from "../src/lib/auth";
import { api } from "../src/lib/api";

// The REAL AuthProvider, not a stub. Kubernetes reads `useAuth()` for its role/verification gate, and stubbing
// the context would put the test's copy of the gate under assertion instead of the product's — the
// fixture-restates-production trap this branch already caught once (docs/laws.md).
const withAuth = (ui: React.ReactElement, initialEntry = "/kubernetes") =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <MemoryRouter initialEntries={[initialEntry]}>
      <AuthProvider>
        <OrgProvider>{ui}<LocationProbe /></OrgProvider>
      </AuthProvider>
    </MemoryRouter>,
  );

function LocationProbe() {
  const location = useLocation();
  return <output data-testid="location">{location.search}</output>;
}

function OrgControls() {
  const { setOrg } = useOrg();
  return <button onClick={() => setOrg("org-2")}>Switch organization</button>;
}

async function chooseKubernetesAction(trigger: string, action: string) {
  fireEvent.click(screen.getByRole("button", { name: trigger }));
  fireEvent.click(within(screen.getByRole("menu", { name: trigger })).getByRole("menuitem", { name: action }));
}

beforeEach(() => {
  clustersFail = false;
  currentRole = "admin";
  operatorManaged = true;
  clusterProvider = "unknown";
  clusterPlatform = "unknown";
  poolActiveNodeId = null;
  poolUnavailable = false;
  currentVerified = true;
  multiOrg = false;
  holdOldClusterRead = false;
  finishOldClusterRead = null;
  clusterInventory = null;
  serviceInventory = null;
  vi.clearAllMocks();
  window.localStorage.removeItem("tunnex.currentOrg");
});

// EVERY kind the OpenAPI contract allows. Kept as a literal on purpose: it is a MIRROR of the generated
// `policy_degraded_kind` union in packages/shared/src/api.d.ts, and a mirror that silently tracked its source
// would prove nothing — the whole point is that the two are maintained separately and must be shown to agree.
// When the contract gains a kind, this list is edited deliberately and the test below names what is missing.
const CONTRACT_KINDS = [
  "apply_failing",
  "stuck_enforcing",
  "converging",
  "silent_desync",
  "desync_unknown",
  "unsupported_policy_version",
  "site_hub_down",
  "site_link_down",
  "site_subnet_unreachable",
  "conntrack_flush_unavailable",
  "hub_forwarding_not_reconciling",
  "k8s_endpoints_unavailable",
  "cert_expired_cannot_reconnect",
] as const;

describe("health-kind mirror census — WF-S11-7's own check", () => {
  it("EVERY degraded kind the contract can emit reaches a renderer with a non-empty label", () => {
    const unrendered = CONTRACT_KINDS.filter(
      (k) =>
        policyHealthBadge({
          policy_degraded: true,
          policy_degraded_kind: k,
        } as never) === null,
    );
    expect(
      unrendered,
      `kinds the API can emit that render NOTHING (WF-S11-7's exact defect): ${unrendered.join(", ")}`,
    ).toEqual([]);
  });

  it("`healthy` renders no badge — absence of degradation is not a badge", () => {
    // The negative half. Without it the census above is satisfiable by returning a badge for everything,
    // which would put a "degraded" label on healthy gateways — the inverse defect, equally wrong.
    expect(
      policyHealthBadge({
        policy_degraded: false,
        policy_degraded_kind: "healthy",
      } as never),
    ).toBeNull();
  });
});

describe("Kubernetes — wiring", () => {
  it("opens a cluster's filtered services from its detail panel", async () => {
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");
    fireEvent.click(await screen.findByRole("button", { name: "View services" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect((screen.getByRole("combobox", { name: "Filter services by cluster" }) as HTMLSelectElement).value).toBe("c1");
    expect(screen.getByRole("table", { name: "Exposed Kubernetes Services" })).toBeTruthy();
  });

  it("names an unassigned connector instead of implying a same-site gateway can serve the cluster", async () => {
    withAuth(<Kubernetes />);

    await waitFor(() =>
      expect(screen.getByText("connector: not selected")).toBeTruthy(),
    );
    expect(
      screen.getByText(/no in-cluster connector is selected/i),
    ).toBeTruthy();
  });

  it("renders a pool's active owner instead of falsely marking a converted cluster unconfigured", async () => {
    operatorManaged = false;
    poolActiveNodeId = "n1";
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    expect(await screen.findByText("Pool: prod-connector")).toBeTruthy();
    expect(screen.queryByText("Connector required")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Connection" }));
    expect(screen.getByText("Pool active: prod-connector")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Select connector" })).toBeNull();
  });

  // S10.2's WITHHELD DESTRUCTIVE CONTROL. An operator-managed object must NOT offer Deregister/Unexpose: a
  // dashboard edit would be silently reverted on the next reconcile, so the product refuses and says where the
  // real control lives. `objectControls` is unit-pinned; this asserts the SCREEN honours it.
  it("an operator-managed object withholds its destructive control and names the CR instead", async () => {
    withAuth(<Kubernetes />);

    // Queried by ACCESSIBLE NAME (the aria-label carries the full guidance), not by the visible fragment.
    // The first draft used getAllByText("edit the CR") and raced the render — it passed locally and failed in
    // the gate's container. Rule 1 asked for the accessible name anyway; the gate is what made me use it.
    await waitFor(() =>
      screen.getAllByLabelText(/managed by the GitOps operator/i),
    );

    // The control is absent BY ROLE — the strongest form of this assertion.
    fireEvent.click(screen.getByRole("button", { name: "Cluster actions for prod-cluster" }));
    const clusterActions = screen.getByRole("menu", { name: "Cluster actions for prod-cluster" });
    expect(within(clusterActions).queryByRole("menuitem", { name: /Deregister|Change connector|Select connector|Correct provider metadata/ })).toBeNull();
    fireEvent.click(within(clusterActions).getByRole("menuitem", { name: "View services" }));
    fireEvent.click(screen.getByRole("button", { name: "Service actions for api.default.svc.prod-cluster.demo.test" }));
    expect(within(screen.getByRole("menu", { name: "Service actions for api.default.svc.prod-cluster.demo.test" })).queryByRole("menuitem", { name: "Unexpose" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

describe("Kubernetes — failure path", () => {
  // D1(b). This screen uses loadOne + LoadRetry, so the triad exists — the test asserts it is REACHED, because
  // a triad that is never rendered is the reassuring-empty-state defect with extra steps.
  it("a failed cluster load renders the retry affordance, not an empty cluster list", async () => {
    clustersFail = true;
    withAuth(<Kubernetes />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy(),
    );
  });
});

describe("Kubernetes — ownership, confirmation, and URL contracts", () => {
  it("registers through provider-first UI with explicit presentation metadata and no extra draft fields", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />);

    fireEvent.click(await screen.findByRole("button", { name: "Register cluster" }));
    const dialog = await screen.findByRole("dialog", { name: "Enroll a Kubernetes cluster" });
    fireEvent.click(within(dialog).getByRole("radio", { name: /Amazon Web Services/i }));
    fireEvent.change(within(dialog).getByLabelText("Kubernetes service"), { target: { value: "eks" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    fireEvent.change(within(dialog).getByLabelText("Fronting Site"), { target: { value: "s1" } });
    fireEvent.change(within(dialog).getByLabelText("In-cluster connector"), { target: { value: "n1" } });
    fireEvent.change(within(dialog).getByLabelText("Cluster name"), { target: { value: "prod-eks" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    fireEvent.change(within(dialog).getByLabelText("Synthetic VIP range"), { target: { value: "100.64.32.0/20" } });
    fireEvent.change(within(dialog).getByLabelText("Kubernetes Service CIDR"), { target: { value: "10.96.0.0/12" } });
    fireEvent.change(within(dialog).getByLabelText("DNS zone"), { target: { value: "k8s.example.test" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Enroll cluster" }));

    await waitFor(() => {
      const calls = (api.POST as unknown as {
        mock: { calls: Array<[string, unknown]> };
      }).mock.calls;
      const call = calls.find(([path]) => path.endsWith("/k8s/clusters"));
      expect(call?.[1]).toEqual({
        params: { path: { orgId: "org-1" } },
        body: {
          site_id: "s1",
          connector_node_id: "n1",
          provider: "aws",
          platform: "eks",
          name: "prod-eks",
          vip_range: "100.64.32.0/20",
          service_cidr: "10.96.0.0/12",
          dns_zone: "k8s.example.test",
        },
      });
    });
  });

  it("shows legacy metadata as unknown and corrects it through the dedicated k8s:manage call site", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    expect(await screen.findByText("Provider not recorded")).toBeTruthy();
    await chooseKubernetesAction("Cluster actions for prod-cluster", "Correct provider metadata");
    const dialog = await screen.findByRole("dialog", { name: /Correct provider metadata for prod-cluster/i });
    expect(dialog.textContent).toMatch(/does not discover a cloud resource/i);
    fireEvent.click(within(dialog).getByRole("radio", { name: /Amazon Web Services/i }));
    fireEvent.change(within(dialog).getByLabelText("Kubernetes service"), { target: { value: "eks" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save provider metadata" }));

    await waitFor(() => {
      const calls = (api.PUT as unknown as {
        mock: { calls: Array<[string, unknown]> };
      }).mock.calls;
      const call = calls.find(([path]) => path.endsWith("/provider-metadata"));
      expect(call?.[1]).toEqual({
        params: { path: { orgId: "org-1", clusterId: "c1" } },
        body: { provider: "aws", platform: "eks" },
      });
    });
  });

  it("renders an exact persisted provider/platform pair without inferring any cloud resource", async () => {
    operatorManaged = false;
    clusterProvider = "aws";
    clusterPlatform = "eks";
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    expect((await screen.findAllByText(/Amazon Web Services · Amazon Elastic Kubernetes Service \(EKS\)/i)).length).toBeGreaterThan(0);
    expect(screen.queryByText("Provider not recorded")).toBeNull();
  });

  it("does not fabricate inventory and keeps the old exposure request under Advanced manual entry", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1&detail=services");

    fireEvent.click(await screen.findByRole("button", { name: "Expose service" }));
    const dialog = await screen.findByRole("dialog", { name: "Expose a Service" });
    expect(within(dialog).getByRole("status").textContent).toContain("Authenticated inventory is unavailable");
    fireEvent.click(within(dialog).getByText("Inventory source"));
    expect(dialog.textContent).toMatch(/dropdowns are unavailable/i);
    expect(dialog.textContent).toMatch(/No cluster objects or zero counts are inferred/i);
    expect(within(dialog).queryByRole("combobox", { name: /namespace|service/i })).toBeNull();
    fireEvent.click(within(dialog).getByText("Advanced manual entry"));
    expect(within(dialog).getByLabelText("Service name")).toBeTruthy();
    expect(within(dialog).getByText(/not verified against connected-agent inventory/i)).toBeTruthy();
  });

  it("keeps org:view inventory useful while a member sees no k8s:manage caller", async () => {
    currentRole = "member";
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    expect((await screen.findAllByText("prod-cluster")).length).toBeGreaterThan(0);
    for (const name of ["Register cluster", "Manage", "Set connector", "Correct provider metadata", "Expose Service", "Unexpose", "Deregister"])
      expect(screen.queryByRole("button", { name })).toBeNull();
    expect(screen.queryByRole("button", { name: "Cluster actions for prod-cluster" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Connection" }));
    expect(screen.queryByRole("heading", { name: "Connector pool" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Select connector|Change connector/ })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Services" }));
    expect(screen.queryByRole("button", { name: "Expose service" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Service actions for api.default.svc.prod-cluster.demo.test" }));
    const actions = screen.getByRole("menu", { name: "Service actions for api.default.svc.prod-cluster.demo.test" });
    expect(within(actions).queryByRole("menuitem", { name: "Unexpose" })).toBeNull();
    fireEvent.click(within(actions).getByRole("menuitem", { name: "View service" }));
    expect(screen.getByRole("dialog", { name: "api" }).textContent).toContain("api.default.svc.prod-cluster.demo.test");
    expect(screen.queryByRole("button", { name: "Unexpose" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("opens the served Service unexpose confirmation with withdrawal and recovery truth", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=services");

    await screen.findByRole("table", { name: "Exposed Kubernetes Services" });
    await chooseKubernetesAction("Service actions for api.default.svc.prod-cluster.demo.test", "Unexpose");
    const dialog = await screen.findByRole("dialog", { name: /unexpose api/i });
    expect(dialog.textContent).toMatch(/api\.default\.svc\.prod-cluster\.demo\.test/);
    expect(dialog.textContent).toMatch(/100\.64\.0\.5/);
    expect(dialog.textContent).toMatch(/Grants to this Service identity stop compiling/i);
    fireEvent.click(within(dialog).getByText("Dependencies and audit"));
    expect(dialog.textContent).toContain("Live Agent Access requests or immutable Agent Policy Template references may refuse the change.");
    expect(dialog.textContent).toContain("Cluster-scope memberships remain as vanished, ineffective evidence.");
    expect(dialog.textContent).toMatch(/new Service identity/i);
    expect(api.DELETE).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Unexpose" }));
    await waitFor(() => expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/k8s/services/{serviceId}", { params: { path: { orgId: "org-1", serviceId: "sv1" } } }));
  });

  it("keeps deregister impact and no-rollback recovery inside the typed confirmation", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    await screen.findByRole("region", { name: "prod-cluster cluster" });
    await chooseKubernetesAction("Cluster actions for prod-cluster", "Deregister");
    const dialog = await screen.findByRole("dialog", { name: /deregister prod-cluster/i });
    expect(dialog.textContent).toMatch(/Direct Service grants are removed/);
    expect(dialog.textContent).toMatch(/VIP and DNS allocations are freed/i);
    fireEvent.click(within(dialog).getByText("Dependencies and audit"));
    expect(dialog.textContent).toContain("Live Agent Access requests, immutable Agent Policy Template references or Kubernetes cluster scopes block deletion until cleared.");
    expect(dialog.textContent).toContain("Connector-pool HA state and retained inventory are deleted with the cluster.");
    expect(dialog.textContent).toMatch(/no restore/i);
    expect(dialog.textContent).toMatch(/recreating its connector, Services, grants and scopes/i);
    const confirm = within(dialog).getByRole("button", { name: "Deregister" });
    expect(confirm).toHaveProperty("disabled", true);
    fireEvent.change(within(dialog).getByLabelText("Cluster name"), { target: { value: "prod-cluster " } });
    expect(confirm).toHaveProperty("disabled", true);
    expect(api.DELETE).not.toHaveBeenCalled();
    fireEvent.change(within(dialog).getByLabelText("Cluster name"), { target: { value: "prod-cluster" } });
    fireEvent.click(confirm);
    await waitFor(() => expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}", { params: { path: { orgId: "org-1", clusterId: "c1" } } }));
  });

  it("restores the services and Operations sections from their direct URLs", async () => {
    operatorManaged = false;
    const rendered = withAuth(<Kubernetes />, "/kubernetes?section=services");
    expect(await screen.findByRole("table", { name: "Exposed Kubernetes Services" })).toBeTruthy();
    rendered.unmount();

    withAuth(<Kubernetes />, "/kubernetes?section=operations");
    expect(await screen.findByText("Operator and connector setup")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Operations" }).getAttribute("aria-current")).toBe("page");
  });

  it("shows only real zero-touch gateway and operator install surfaces", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=operations");

    fireEvent.click(await screen.findByRole("button", { name: "View commands" }));
    const dialog = await screen.findByRole("dialog", { name: "Operator and connector setup" });
    expect(dialog.textContent).toContain("tunnex k8s plan --org org-1 --node-name <gateway-name>");
    expect(dialog.textContent).toContain("tunnex k8s install --org org-1 --node-name <gateway-name> --yes");
    fireEvent.click(within(dialog).getByRole("button", { name: "GitOps operator" }));
    expect(within(dialog).getByRole("navigation", { name: "Operator setup steps" })).toBeTruthy();
    expect(dialog.textContent).toContain("tunnex-operator-credential");
    expect(dialog.textContent).toContain('CHART_VERSION="${CLI_VERSION#v}"');
    expect(dialog.textContent).toContain('TUNNEX_ORGANIZATION_ID="org-1"');
    expect(api.POST).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(dialog.textContent).toContain("--take-ownership --wait");
    expect(dialog.textContent).toContain("Adoption accepts only an exact approved legacy Tunnex schema; unknown ownerless schemas fail before apply.");
    fireEvent.click(within(dialog).getByRole("button", { name: "Continue" }));
    expect(dialog.textContent).toContain("oci://ghcr.io/tunnexio/charts/tunnex-operator");
    expect(dialog.textContent).toContain("machineToken.existingSecret=tunnex-operator-credential");
    expect(dialog.textContent).toContain('--version "$CHART_VERSION"');
    expect(dialog.textContent).toContain("--atomic --wait");
    expect(dialog.textContent).not.toContain("joinToken.secretRef");
    expect(dialog.textContent).not.toContain("tunnex/operator");
    expect(dialog.textContent).not.toMatch(/tnx[jm]_[A-Za-z0-9_-]+/);
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

describe("Kubernetes — focused navigation and inventory paging", () => {
  it("keeps a cluster breadcrumb and focused steps while service inspection returns to its actual parent", async () => {
    operatorManaged = false;
    clusterInventory = [{ ...CLUSTERS[0], vip_range: "100.64.32.0/20", service_cidr: "10.96.0.0/12", dns_zone: "served.example.test", dns_vip: "100.64.32.1" }];
    withAuth(<Kubernetes />);
    fireEvent.click(await screen.findByRole("button", { name: "prod-cluster" }));
    const selected = screen.getByRole("region", { name: "prod-cluster cluster" });
    expect(screen.queryByRole("table", { name: "Registered Kubernetes clusters" })).toBeNull();
    expect(screen.queryByRole("dialog")).toBeNull();
    const breadcrumb = screen.getByRole("navigation", { name: "Cluster breadcrumb" });
    expect(within(breadcrumb).getByText("prod-cluster").getAttribute("aria-current")).toBe("page");
    const rail = screen.getByRole("navigation", { name: "Cluster detail sections" });
    expect(within(rail).getByRole("button", { name: "Overview" }).getAttribute("aria-current")).toBe("step");
    fireEvent.click(within(rail).getByRole("button", { name: "Network" }));
    expect(within(selected).getByText("100.64.32.0/20")).toBeTruthy();
    expect(within(selected).getByText("served.example.test")).toBeTruthy();
    expect(screen.getByTestId("location").textContent).toContain("detail=network");
    fireEvent.click(within(rail).getByRole("button", { name: "Services" }));
    fireEvent.click(within(selected).getByRole("button", { name: "api.default.svc.prod-cluster.demo.test" }));
    const inspection = screen.getByRole("dialog", { name: "api" });
    expect(within(inspection).getByText("100.64.0.5")).toBeTruthy();
    expect(within(inspection).getByText("TCP")).toBeTruthy();
    fireEvent.click(within(inspection).getByRole("button", { name: "View cluster" }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(within(screen.getByRole("navigation", { name: "Cluster detail sections" })).getByRole("button", { name: "Overview" }).getAttribute("aria-current")).toBe("step");
    fireEvent.click(within(screen.getByRole("navigation", { name: "Cluster breadcrumb" })).getByRole("button", { name: "Clusters" }));
    expect(screen.getByRole("table", { name: "Registered Kubernetes clusters" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).not.toContain("cluster=");
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("uses real cluster page limits, retains Back on a short last page and resets page for search", async () => {
    clusterInventory = Array.from({ length: 55 }, (_, index) => ({ ...CLUSTERS[0], id: `cluster-${index}`, name: `Cluster ${String(index).padStart(3, "0")}`, connector_node_id: "n1" }));
    serviceInventory = [];
    withAuth(<Kubernetes />);
    const table = await screen.findByRole("table", { name: "Registered Kubernetes clusters" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Next clusters" }));
    expect(within(table).getByRole("button", { name: "Cluster 020" })).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "10" } });
    expect(within(table).getAllByRole("row")).toHaveLength(11);
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    expect(screen.getByTestId("location").textContent).toContain("page_size=10");
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(table).getAllByRole("row")).toHaveLength(51);
    fireEvent.click(screen.getByRole("button", { name: "Next clusters" }));
    expect(within(table).getAllByRole("row")).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Previous clusters" })).toHaveProperty("disabled", false);
    expect(screen.getByRole("button", { name: "Next clusters" })).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByRole("textbox", { name: "Search clusters" }), { target: { value: "Cluster 054" } });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    fireEvent.change(screen.getByRole("textbox", { name: "Search clusters" }), { target: { value: "absent" } });
    expect(screen.getByRole("heading", { name: "No matching clusters" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Registered Kubernetes clusters" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Clear search" }));
    expect(screen.getByRole("button", { name: "Cluster 000" })).toBeTruthy();
    expect(screen.getAllByRole("row")).toHaveLength(51);
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("pages served service FQDNs and resets the page before narrowing to another cluster", async () => {
    clusterInventory = [{ ...CLUSTERS[0], connector_node_id: "n1" }, { ...CLUSTERS[0], id: "c2", name: "Other cluster", connector_node_id: "n1" }];
    serviceInventory = Array.from({ length: 55 }, (_, index) => ({ ...SERVICES[0], id: `service-${index}`, cluster_id: index === 54 ? "c2" : "c1", name: `service-${index}`, fqdn: `served-${String(index).padStart(3, "0")}.opaque.example.test` }));
    withAuth(<Kubernetes />, "/kubernetes?section=services");
    const table = await screen.findByRole("table", { name: "Exposed Kubernetes Services" });
    expect(within(table).getAllByRole("row")).toHaveLength(21);
    fireEvent.click(screen.getByRole("button", { name: "Next services" }));
    expect(within(table).getByRole("button", { name: "served-020.opaque.example.test" })).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Rows per page" }), { target: { value: "50" } });
    expect(within(table).getAllByRole("row")).toHaveLength(51);
    fireEvent.click(screen.getByRole("button", { name: "Next services" }));
    expect(within(table).getAllByRole("row")).toHaveLength(6);
    expect(screen.getByRole("button", { name: "Previous services" })).toHaveProperty("disabled", false);
    fireEvent.change(screen.getByRole("combobox", { name: "Filter services by cluster" }), { target: { value: "c2" } });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).getByRole("button", { name: "served-054.opaque.example.test" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter services by cluster" }), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Next services" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search services" }), { target: { value: "served-054" } });
    expect(within(table).getAllByRole("row")).toHaveLength(2);
    expect(within(table).getByRole("button", { name: "served-054.opaque.example.test" })).toBeTruthy();
    expect(screen.getByTestId("location").textContent).not.toContain("page=2");
    fireEvent.change(screen.getByRole("combobox", { name: "Filter services by cluster" }), { target: { value: "c1" } });
    expect(screen.getByRole("heading", { name: "No matching services" })).toBeTruthy();
    expect(screen.queryByRole("table", { name: "Exposed Kubernetes Services" })).toBeNull();
    fireEvent.change(screen.getByRole("textbox", { name: "Search services" }), { target: { value: "served-053" } });
    const narrowed = screen.getByRole("table", { name: "Exposed Kubernetes Services" });
    expect(within(narrowed).getAllByRole("row")).toHaveLength(2);
    fireEvent.click(within(narrowed).getByRole("button", { name: "prod-cluster" }));
    await chooseKubernetesAction("Cluster actions for prod-cluster", "Deregister");
    expect(screen.getByRole("dialog", { name: "Deregister prod-cluster" }).textContent).toContain("54 exposed services");
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("withdraws old organization details and permissions while a late old cluster read is discarded", async () => {
    operatorManaged = false;
    multiOrg = true;
    withAuth(<><Kubernetes /><OrgControls /></>, "/kubernetes?section=clusters&cluster=c1");
    await screen.findByRole("region", { name: "prod-cluster cluster" });
    holdOldClusterRead = true;
    fireEvent.click(screen.getByRole("button", { name: "Refresh Kubernetes" }));
    await waitFor(() => expect(finishOldClusterRead).not.toBeNull());
    fireEvent.click(screen.getByRole("button", { name: "Switch organization" }));
    expect(screen.queryByRole("region", { name: "prod-cluster cluster" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Register cluster" })).toBeNull();
    await screen.findByRole("button", { name: "B cluster" });
    await act(async () => { finishOldClusterRead?.({ data: [{ ...CLUSTERS[0], id: "late-old", name: "Late old cluster" }] }); });
    expect(screen.getByRole("button", { name: "B cluster" })).toBeTruthy();
    expect(screen.queryByText("Late old cluster")).toBeNull();
    expect(screen.queryByText("prod-cluster")).toBeNull();
    expect(screen.queryByRole("button", { name: "Register cluster" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Cluster actions for B cluster" }));
    expect(within(screen.getByRole("menu", { name: "Cluster actions for B cluster" })).queryByRole("menuitem", { name: /Deregister|Correct provider metadata|Select connector|Change connector/ })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });

  it("keeps unavailable pool reads distinct from a missing direct connector", async () => {
    operatorManaged = false;
    poolUnavailable = true;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");
    expect(await screen.findByText("Connector pool state unavailable")).toBeTruthy();
    expect(screen.queryByText("Connector required")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Cluster actions for prod-cluster" }));
    expect(within(screen.getByRole("menu", { name: "Cluster actions for prod-cluster" })).queryByRole("menuitem", { name: /Select connector|Change connector/ })).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("keeps an unverified administrator's inventory readable while withholding every mutation caller", async () => {
    currentVerified = false;
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1&detail=services");
    expect(await screen.findByRole("table", { name: "Exposed Kubernetes Services" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Register cluster" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Expose service" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Cluster actions for prod-cluster" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Service actions for api.default.svc.prod-cluster.demo.test" }));
    const menu = screen.getByRole("menu", { name: "Service actions for api.default.svc.prod-cluster.demo.test" });
    expect(within(menu).queryByRole("menuitem", { name: "Unexpose" })).toBeNull();
    fireEvent.click(within(menu).getByRole("menuitem", { name: "View service" }));
    expect(screen.getByRole("dialog", { name: "api" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Unexpose" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
    expect(api.PUT).not.toHaveBeenCalled();
    expect(api.DELETE).not.toHaveBeenCalled();
  });
});

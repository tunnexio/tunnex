import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { fireEvent, render, screen, waitFor, cleanup, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

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
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: currentRole, email_verified: true }],
          };
        if (path.endsWith("/k8s/clusters")) {
          if (clustersFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return {
            data: CLUSTERS.map((cluster) => ({
              ...cluster,
              provider: clusterProvider,
              platform: clusterPlatform,
              managed_by_operator: operatorManaged,
            })),
          };
        }
        if (path.endsWith("/k8s/services")) return { data: SERVICES.map((service) => ({ ...service, managed_by_operator: operatorManaged })) };
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
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
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
        <OrgProvider>{ui}</OrgProvider>
      </AuthProvider>
    </MemoryRouter>,
  );

beforeEach(() => {
  clustersFail = false;
  currentRole = "admin";
  operatorManaged = true;
  clusterProvider = "unknown";
  clusterPlatform = "unknown";
  vi.clearAllMocks();
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
  it("names an unassigned connector instead of implying a same-site gateway can serve the cluster", async () => {
    withAuth(<Kubernetes />);

    await waitFor(() =>
      expect(screen.getByText("connector: not selected")).toBeTruthy(),
    );
    expect(
      screen.getByText(/no in-cluster connector is selected/i),
    ).toBeTruthy();
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
    expect(screen.queryByRole("button", { name: "Unexpose" })).toBeNull();
    expect(screen.queryByRole("button", { name: /Deregister/i })).toBeNull();
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
    fireEvent.change(within(dialog).getByLabelText("Fronting Site"), { target: { value: "s1" } });
    fireEvent.change(within(dialog).getByLabelText("In-cluster connector"), { target: { value: "n1" } });
    fireEvent.change(within(dialog).getByLabelText("Cluster name"), { target: { value: "prod-eks" } });
    fireEvent.click(within(dialog).getByText("Advanced network values"));
    fireEvent.change(within(dialog).getByLabelText("Synthetic VIP range"), { target: { value: "100.64.32.0/20" } });
    fireEvent.change(within(dialog).getByLabelText("Kubernetes Service CIDR"), { target: { value: "10.96.0.0/12" } });
    fireEvent.change(within(dialog).getByLabelText("DNS zone"), { target: { value: "k8s.example.test" } });
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

    expect(await screen.findByText(/Unknown \(legacy registration; not inferred\)/i)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Correct provider metadata" }));
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
    expect(screen.queryByText(/Unknown \(legacy registration; not inferred\)/i)).toBeNull();
  });

  it("does not fabricate inventory and keeps the old exposure request under Advanced manual entry", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    fireEvent.click(await screen.findByRole("button", { name: "Expose service" }));
    const dialog = await screen.findByRole("dialog", { name: "Expose a Service" });
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
  });

  it("opens the served Service unexpose confirmation with withdrawal and recovery truth", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=services");

    fireEvent.click(await screen.findByRole("button", { name: "Unexpose" }));
    const dialog = await screen.findByRole("dialog", { name: /unexpose api/i });
    expect(dialog.textContent).toMatch(/api\.default\.svc\.prod-cluster\.demo\.test/);
    expect(dialog.textContent).toMatch(/100\.64\.0\.5/);
    expect(dialog.textContent).toMatch(/next compile/i);
    expect(dialog.textContent).toContain("live Agent Access requests or immutable Agent Policy Template references may refuse the change.");
    expect(dialog.textContent).toContain("Cluster-scope memberships do not refuse it: they are retained as vanished, ineffective evidence.");
    expect(dialog.textContent).toMatch(/new Service identity/i);
  });

  it("keeps deregister impact and no-rollback recovery inside the typed confirmation", async () => {
    operatorManaged = false;
    withAuth(<Kubernetes />, "/kubernetes?section=clusters&cluster=c1");

    fireEvent.click(await screen.findByRole("button", { name: "Deregister" }));
    const dialog = await screen.findByRole("dialog", { name: /deregister prod-cluster/i });
    expect(dialog.textContent).toMatch(/dependent policy rules/i);
    expect(dialog.textContent).toMatch(/reserved DNS VIP/i);
    expect(dialog.textContent).toContain("Live Agent Access requests, immutable Agent Policy Template references, or any Kubernetes cluster scopes refuse deregistration until those references are cleared.");
    expect(dialog.textContent).toContain("Connector-pool HA state and retained inventory are cascade-deleted with the cluster; they do not preserve evidence or block the delete.");
    expect(dialog.textContent).toMatch(/no rollback or restore/i);
    expect(dialog.textContent).toMatch(/recreating grants/i);
  });

  it("restores the services and Setup & diagnostics sections from their direct URLs", async () => {
    operatorManaged = false;
    const rendered = withAuth(<Kubernetes />, "/kubernetes?section=services");
    expect(await screen.findByText(/Exposed Services \(1\)/)).toBeTruthy();
    rendered.unmount();

    withAuth(<Kubernetes />, "/kubernetes?section=operations");
    expect(await screen.findByText("Operator and connector setup")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Setup & diagnostics" }).getAttribute("aria-current")).toBe("page");
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

let role: "admin" | "member" = "admin";
let enabled = true;
let entitlementUnlocked = true;
let queueFails = false;
let clusterInventoryFails = false;
let scopeExpiresAt: string | null = null;
let policyManageAllowed = true;
let candidateTotal = 1;
let membershipTotal = 1;
const now = "2026-08-28T10:00:00Z";

const scope = {
  rule_id: "50000000-0000-4000-8000-000000000001",
  cluster_id: "20000000-0000-4000-8000-000000000001",
  source: { kind: "group", id: "30000000-0000-4000-8000-000000000001" },
  active: true,
  revision: 3,
  initial_candidate_count: 2,
  created_by_user_id: "10000000-0000-4000-8000-000000000001",
  created_at: now,
  updated_at: now,
};

const pending = {
  rule_id: scope.rule_id,
  cluster_id: scope.cluster_id,
  service_child_id: "40000000-0000-4000-8000-000000000003",
  namespace: "payments",
  service: "ledger",
  protocol: "tcp",
  port: 8443,
  origin: "later",
  status: "pending",
  current: true,
  created_at: now,
};

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: { id: "org-a", name: "Acme" }, orgs: [], loading: false, failed: false }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: "10000000-0000-4000-8000-000000000001" } } }),
}));

vi.mock("../src/lib/rbac", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/rbac")>("../src/lib/rbac");
  return {
    ...actual,
    can: (nextRole: Parameters<typeof actual.can>[0], permission: Parameters<typeof actual.can>[1]) =>
      permission === "policy:manage" && !policyManageAllowed ? false : actual.can(nextRole, permission),
  };
});

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, options?: { params?: { query?: { cursor?: string } } }) => {
        if (path.endsWith("/members")) return { data: [{ user_id: "10000000-0000-4000-8000-000000000001", name: "Asha", email: "asha@example.test", role, status: "active", email_verified: true, joined_at: now }] };
        if (path.endsWith("/cluster-scope-settings")) return { data: { enabled, revision: 2, entitlement_unlocked: entitlementUnlocked, effective: enabled && entitlementUnlocked } };
        if (path.endsWith("/cluster-scopes")) return { data: [{ ...scope, expires_at: scopeExpiresAt }] };
        if (path.endsWith("/cluster-scope-review-queue")) return queueFails ? { error: { error: { code: "inventory_unavailable", message: "Review queue unavailable." } } } : { data: { items: [pending] } };
        if (path.endsWith("/k8s/clusters")) return clusterInventoryFails ? { error: { error: { message: "Cluster inventory failed." } } } : { data: [{ id: scope.cluster_id, site_id: "site-a", name: "prod-eks", provider: "aws", platform: "eks", vip_range: "100.64.0.0/20", service_cidr: "10.96.0.0/12", dns_zone: "k8s.test", managed_by_operator: false }] };
        if (path.endsWith("/k8s/services")) return { data: [
          { id: "40000000-0000-4000-8000-000000000001", cluster_id: scope.cluster_id, name: "api", namespace: "payments", protocol: "tcp", port_low: 443, port_high: 443, vip: "100.64.0.2", fqdn: "api.payments.svc.prod.k8s.test", managed_by_operator: false },
          { id: "40000000-0000-4000-8000-000000000002", cluster_id: scope.cluster_id, name: "dns", namespace: "platform", protocol: "udp", port_low: 53, port_high: 53, vip: "100.64.0.3", fqdn: "dns.platform.svc.prod.k8s.test", managed_by_operator: false },
        ] };
        if (path.endsWith("/groups")) return { data: [{ id: "30000000-0000-4000-8000-000000000001", org_id: "org-a", name: "Payments team", description: "", member_count: 2, created_at: now, updated_at: now }] };
        if (path.endsWith("/sites")) return { data: [] };
        if (path.endsWith("/agents")) return { data: { items: [] } };
        if (path.endsWith("/initial-candidates")) {
          const start = Number(options?.params?.query?.cursor?.split(":")[1] ?? 0);
          const end = Math.min(start + 100, candidateTotal);
          return { data: {
            items: Array.from({ length: end - start }, (_, offset) => ({ service_child_id: `candidate-${start + offset}`, namespace: "candidate", service: `candidate-${start + offset}`, protocol: "tcp", port: 443, selected: true, current: true })),
            next_cursor: end < candidateTotal ? `candidate:${end}` : undefined,
          } };
        }
        if (path.endsWith("/memberships")) {
          const start = Number(options?.params?.query?.cursor?.split(":")[1] ?? 0);
          const end = Math.min(start + 100, membershipTotal);
          return { data: {
            items: Array.from({ length: end - start }, (_, offset) => ({ ...pending, service_child_id: `membership-${start + offset}`, namespace: "membership", service: `membership-${start + offset}` })),
            next_cursor: end < membershipTotal ? `membership:${end}` : undefined,
          } };
        }
        return { data: [] };
      }),
      POST: vi.fn(async (path: string) => path.endsWith("/cluster-scopes") ? { data: scope } : { data: { ...pending, status: "approved", decided_at: now } }),
      PUT: vi.fn(async () => ({ data: { ...scope, revision: 4 } })),
      DELETE: vi.fn(async () => ({ data: undefined })),
      PATCH: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { api } from "../src/lib/api";
import AccessKubernetesScopes from "../src/pages/AccessKubernetesScopes";

function renderPage() {
  return render(<MemoryRouter initialEntries={["/access/kubernetes-scopes"]}><AccessKubernetesScopes /></MemoryRouter>);
}

beforeEach(() => {
  role = "admin";
  enabled = true;
  entitlementUnlocked = true;
  queueFails = false;
  clusterInventoryFails = false;
  scopeExpiresAt = null;
  policyManageAllowed = true;
  candidateTotal = 1;
  membershipTotal = 1;
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.POST).mockClear();
  vi.mocked(api.PUT).mockClear();
  vi.mocked(api.DELETE).mockClear();
});

afterEach(() => cleanup());

describe("S20.4 Access-owned Kubernetes scope governance", () => {
  it("removes protected scope DOM and calls when named permissions are absent", async () => {
    role = "member";
    renderPage();
    await screen.findByText("Kubernetes scope governance is available only to authorized Access administrators.");
    expect(screen.queryByText("Organization opt-in")).toBeNull();
    const calls = vi.mocked(api.GET).mock.calls as unknown as Array<[string]>;
    expect(calls.some(([path]) => path.includes("cluster-scope"))).toBe(false);
  });

  it("keeps queue failure distinct from an empty-success state", async () => {
    queueFails = true;
    renderPage();
    await screen.findByText("Review queue unavailable.");
    expect(screen.queryByText("No later-exposure decisions are pending.")).toBeNull();
  });

  it("creates from actual cluster/source/exact children with no default selection", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Create scope" }));
    fireEvent.change(screen.getByLabelText("Enrolled cluster"), { target: { value: scope.cluster_id } });
    fireEvent.change(screen.getByLabelText("Group"), { target: { value: "30000000-0000-4000-8000-000000000001" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    const boxes = await screen.findAllByRole("checkbox");
    expect(boxes.every((box) => !(box as HTMLInputElement).checked)).toBe(true);
    fireEvent.click(boxes[0]);
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByText("1 exact child")).toBeTruthy();
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Create scope" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/cluster-scopes",
      expect.objectContaining({ body: expect.objectContaining({ cluster_id: scope.cluster_id, source: { kind: "group", id: "30000000-0000-4000-8000-000000000001" }, initial_service_child_ids: ["40000000-0000-4000-8000-000000000001"] }) }),
    ));
  });

  it("requires explicit permanent-rejection confirmation before deciding", async () => {
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: "Review rejection" }));
    expect(screen.getByRole("heading", { name: "Reject this exact child?" })).toBeTruthy();
    expect(screen.getByText(/Rejection is permanent for this membership/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Reject permanently" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/cluster-scopes/{ruleId}/memberships/{serviceChildId}/decision",
      expect.objectContaining({ body: { decision: "rejected" } }),
    ));
  });

  it("keeps preserved scopes readable when create-only inventory fails", async () => {
    clusterInventoryFails = true;
    renderPage();
    expect(await screen.findByText(/Cluster 20000000/)).toBeTruthy();
    expect(screen.getByText(/Preserved scopes remain readable/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Create scope" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("allows opt-out after entitlement loss and labels active state ineffective", async () => {
    entitlementUnlocked = false;
    renderPage();
    expect(await screen.findByText("Active · ineffective")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Disable for organization" }));
    fireEvent.click(screen.getByRole("button", { name: "Disable and withdraw" }));
    await waitFor(() => expect(api.PUT).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/k8s/cluster-scope-settings",
      expect.objectContaining({ body: { enabled: false, expected_revision: 2 } }),
    ));
  });

  it("shows expiry and expired ineffective state in list and detail", async () => {
    scopeExpiresAt = "2020-01-01T00:00:00Z";
    renderPage();
    expect(await screen.findByText("Expired · ineffective")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: /prod-eks Expired/ }));
    expect(await screen.findByText("Expired and ineffective")).toBeTruthy();
    expect(screen.getByText(/scope has expired/)).toBeTruthy();
  });

  it("keeps 50 exhausted candidates unique while memberships continue from 100 to 150", async () => {
    candidateTotal = 50;
    membershipTotal = 150;
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /prod-eks/ }));
    await screen.findByText("membership/membership-99");
    fireEvent.click(screen.getByRole("button", { name: "Load more history" }));
    await screen.findByText("membership/membership-149");

    const candidates = screen.getAllByText(/^candidate\/candidate-/).map((node) => node.textContent);
    const memberships = screen.getAllByText(/^membership\/membership-/).map((node) => node.textContent);
    expect(candidates).toHaveLength(50);
    expect(new Set(candidates).size).toBe(50);
    expect(memberships).toHaveLength(150);
    expect(new Set(memberships).size).toBe(150);
    const candidateCalls = (vi.mocked(api.GET).mock.calls as unknown as Array<[string]>).filter(([path]) => path.endsWith("/initial-candidates"));
    expect(candidateCalls).toHaveLength(1);
  });

  it("keeps 50 exhausted memberships unique while candidates continue from 100 to 150", async () => {
    candidateTotal = 150;
    membershipTotal = 50;
    renderPage();
    fireEvent.click(await screen.findByRole("button", { name: /prod-eks/ }));
    await screen.findByText("candidate/candidate-99");
    fireEvent.click(screen.getByRole("button", { name: "Load more history" }));
    await screen.findByText("candidate/candidate-149");

    const candidates = screen.getAllByText(/^candidate\/candidate-/).map((node) => node.textContent);
    const memberships = screen.getAllByText(/^membership\/membership-/).map((node) => node.textContent);
    expect(candidates).toHaveLength(150);
    expect(new Set(candidates).size).toBe(150);
    expect(memberships).toHaveLength(50);
    expect(new Set(memberships).size).toBe(50);
    const membershipCalls = (vi.mocked(api.GET).mock.calls as unknown as Array<[string]>).filter(([path]) => path.endsWith("/memberships"));
    expect(membershipCalls).toHaveLength(1);
  });

  it("keeps manage actions without exposing create when policy manage is absent", async () => {
    policyManageAllowed = false;
    renderPage();
    expect(await screen.findByText("prod-eks")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create scope" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: /prod-eks/ }));
    expect(await screen.findByRole("button", { name: "Disable scope" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Delete scope" })).toBeTruthy();
  });
});

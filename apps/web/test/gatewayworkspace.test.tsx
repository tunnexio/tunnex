import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter, Route, Routes, useLocation } from "react-router-dom";

const { apiPost, apiPatch, apiDelete } = vi.hoisted(() => ({
  apiPost: vi.fn(async () => ({ data: undefined, error: undefined })),
  apiPatch: vi.fn(async () => ({ data: undefined, error: undefined })),
  apiDelete: vi.fn(async () => ({ data: undefined, error: undefined })),
}));
const reload = vi.fn(async () => undefined);

const readyState = {
  kind: "ready" as const,
  nodes: [
    {
      id: "gw-1",
      name: "edge-london",
      status: "active",
      agent_version: "1.4.0",
      enrolled_at: "2026-08-01T00:00:00Z",
      last_seen_at: "2099-08-24T00:00:00Z",
      site_id: "site-1",
      egress_mode: "dual_stack",
    },
    {
      id: "gw-2",
      name: "edge-paris",
      status: "revoked",
      agent_version: "1.3.0",
      enrolled_at: "2026-07-01T00:00:00Z",
    },
  ],
  siteNames: { "site-1": "London" },
  homedCounts: { "gw-1": 0, "gw-2": 0 },
  licence: {
    tier: "community",
    gateway_ceiling: 5,
    gateways_in_use: 2,
  },
  role: "owner" as const,
};

let hookResult: any = {
  org: { id: "org-1", name: "Acme" },
  state: readyState,
  reload,
  canEnroll: true,
  canManage: true,
  canTransfer: true,
  canRestore: true,
};

vi.mock("../src/lib/useGatewayInventory", () => ({
  useGatewayInventory: () => hookResult,
}));
vi.mock("../src/components/Gateways", () => ({
  Gateways: () => <p>Enrollment details</p>,
}));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: { ...actual.api, POST: apiPost, PATCH: apiPatch, DELETE: apiDelete },
    apiErrorMessage: (_error: unknown, fallback: string) => fallback,
  };
});

import Gateways from "../src/pages/Gateways";
import GatewayDetail from "../src/pages/GatewayDetail";

function Location() {
  return <output aria-label="location">{useLocation().pathname}{useLocation().search}</output>;
}

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  hookResult = {
    org: { id: "org-1", name: "Acme" },
    state: readyState,
    reload,
    canEnroll: true,
    canManage: true,
    canTransfer: true,
    canRestore: true,
  };
});

describe("S20 Gateway inventory", () => {
  it("uses URL-backed search/filter/sort state and links every row to detail", () => {
    render(
      <MemoryRouter initialEntries={["/gateways?q=london&health=healthy&sort=seen&dir=desc"]}>
        <Routes><Route path="/gateways" element={<><Gateways /><Location /></>} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByDisplayValue("london")).toBeTruthy();
    expect(screen.getByRole("link", { name: "edge-london" }).getAttribute("href")).toBe("/gateways/gw-1");
    expect(screen.queryByText("edge-paris")).toBeNull();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter gateway health" }), { target: { value: "all" } });
    expect(screen.getByLabelText("location").textContent).toContain("q=london");
    expect(screen.getByLabelText("location").textContent).not.toContain("health=");
  });

  it("uses deployment-wide licence values and withholds enrollment at the ceiling", () => {
    hookResult = {
      ...hookResult,
      state: {
        ...readyState,
        licence: { tier: "starter", gateway_ceiling: 5, gateways_in_use: 5 },
      },
    };
    render(<MemoryRouter><Gateways /></MemoryRouter>);
    expect(screen.getByText(/Deployment usage: 5 \/ 5 gateways/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Enroll gateway" })).toHaveProperty("disabled", true);
  });

  it("renders a durable load error rather than an honest-looking empty fleet", () => {
    hookResult = { ...hookResult, state: { ...readyState, kind: "error", error: "nodes unavailable", nodes: [] } };
    render(<MemoryRouter><Gateways /></MemoryRouter>);
    expect(screen.getByText("nodes unavailable")).toBeTruthy();
    expect(screen.queryByText(/No gateways are enrolled/)).toBeNull();
  });

  it("renders server-owned egress modes and an explicit stable detail affordance for every row", () => {
    const nodes = [
      { ...readyState.nodes[0], id: "gw-dual", name: "gw-us-east", egress_mode: "dual_stack" },
      { ...readyState.nodes[0], id: "gw-v4", name: "gw-eu-west", egress_mode: "ipv4_only" },
      { ...readyState.nodes[0], id: "gw-checking", name: "gw-unreported", egress_mode: "checking" },
    ];
    hookResult = { ...hookResult, state: { ...readyState, nodes } };
    render(<MemoryRouter><Gateways /></MemoryRouter>);

    expect(screen.getByText("Dual-stack")).toBeTruthy();
    expect(screen.getByText("IPv4-only")).toBeTruthy();
    expect(screen.getByText("Checking")).toBeTruthy();
    for (const node of nodes) {
      expect(screen.getByRole("link", { name: node.name }).getAttribute("href")).toBe(`/gateways/${node.id}`);
      expect(screen.getByRole("link", { name: `Open details for ${node.name}` }).getAttribute("href")).toBe(`/gateways/${node.id}`);
    }
    expect(screen.queryByRole("button", { name: /rename gateway/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /revoke gateway/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /delete gateway/i })).toBeNull();
    expect(apiPatch).not.toHaveBeenCalled();
    expect(apiPost).not.toHaveBeenCalled();
    expect(apiDelete).not.toHaveBeenCalled();
  });

  it("renders an active never-connected gateway as awaiting and excludes it from Healthy", () => {
    hookResult = {
      ...hookResult,
      state: {
        ...readyState,
        nodes: [{ ...readyState.nodes[0], id: "gw-new", name: "never-connected", last_seen_at: null }],
      },
    };
    render(<MemoryRouter><Gateways /></MemoryRouter>);
    expect(screen.getByText("awaiting first connection")).toBeTruthy();
    expect(screen.getByText("Never connected")).toBeTruthy();
    fireEvent.change(screen.getByRole("combobox", { name: "Filter gateway health" }), { target: { value: "healthy" } });
    expect(screen.queryByText("never-connected")).toBeNull();
  });

  it("renders revoked egress as historical or terminally unreported", () => {
    hookResult = {
      ...hookResult,
      state: {
        ...readyState,
        nodes: [
          { ...readyState.nodes[1], id: "gw-revoked-unknown", name: "revoked-unknown", egress_mode: null },
          { ...readyState.nodes[1], id: "gw-revoked-known", name: "revoked-known", egress_mode: "dual_stack" },
        ],
      },
    };
    render(<MemoryRouter><Gateways /></MemoryRouter>);
    expect(screen.getByText("Not reported before revocation")).toBeTruthy();
    expect(screen.getByText("Last reported: Dual-stack")).toBeTruthy();
    expect(screen.queryByText("Checking")).toBeNull();
  });
});

describe("S20 Gateway detail lifecycle", () => {
  it("explains dual-stack, IPv4-only, and unreported egress from the Node projection", () => {
    const cases = [
      ["dual_stack", "IPv4 and IPv6 verified"],
      ["ipv4_only", "IPv4 verified; IPv6 not available"],
      ["checking", "Waiting for a verified capability report"],
    ] as const;
    for (const [egressMode, explanation] of cases) {
      hookResult = {
        ...hookResult,
        state: {
          ...readyState,
          nodes: [{ ...readyState.nodes[0], egress_mode: egressMode }],
        },
      };
      render(
        <MemoryRouter initialEntries={["/gateways/gw-1?tab=health"]}>
          <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
        </MemoryRouter>,
      );
      expect(screen.getByText(explanation)).toBeTruthy();
      cleanup();
    }
  });

  it("uses awaiting-first-connection truth in the detail header", () => {
    hookResult = {
      ...hookResult,
      state: {
        ...readyState,
        nodes: [{ ...readyState.nodes[0], last_seen_at: null }],
      },
    };
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText("awaiting first connection")).toBeTruthy();
    expect(screen.getByText("Never connected")).toBeTruthy();
    expect(screen.queryByText("healthy")).toBeNull();
  });

  it("renders revoked Health egress as terminally unknown or historical", () => {
    for (const [egressMode, expected] of [
      [null, "Not reported before revocation. This terminal gateway cannot provide a future capability report."],
      ["dual_stack", "Last reported: Dual-stack. This historical capability report will not refresh after revocation."],
    ] as const) {
      hookResult = {
        ...hookResult,
        state: { ...readyState, nodes: [{ ...readyState.nodes[1], egress_mode: egressMode }] },
      };
      render(
        <MemoryRouter initialEntries={["/gateways/gw-2?tab=health"]}>
          <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
        </MemoryRouter>,
      );
      expect(screen.getByText(expected)).toBeTruthy();
      expect(screen.queryByText("Waiting for a verified capability report")).toBeNull();
      cleanup();
    }
  });

  it("exposes rename/revoke only for an authorized active gateway", () => {
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByRole("button", { name: "Rename" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete gateway record" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    expect(screen.getByRole("button", { name: "Revoke gateway" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Delete gateway record" })).toBeNull();
  });

  it("exposes restore and delete, but never rename or revoke, for an authorized revoked gateway", () => {
    render(
      <MemoryRouter initialEntries={["/gateways/gw-2"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: "Rename" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    expect(screen.getByRole("button", { name: "Restore cascaded devices" })).toBeTruthy();
    expect(screen.getByRole("button", { name: "Delete gateway record" })).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke gateway" })).toBeNull();
  });

  it("keeps the tab in the URL and confirms before the authoritative revoke mutation", async () => {
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<><GatewayDetail /><Location /></>} /></Routes>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    expect(screen.getByLabelText("location").textContent).toContain("tab=lifecycle");
    fireEvent.click(screen.getByRole("button", { name: "Revoke gateway" }));
    expect(apiPost).not.toHaveBeenCalled();
    expect(screen.getByText(/server checks again transactionally/i)).toBeTruthy();
    fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: "Revoke gateway" }));
    await waitFor(() => expect(apiPost).toHaveBeenCalledTimes(1));
    expect((apiPost.mock.calls[0] as unknown as [string])[0]).toContain("/revoke");
  });

  it("keeps authoritative mutation failures visible inside the open confirmation", async () => {
    apiPost.mockResolvedValueOnce({ error: { error: { code: "devices_still_homed" } } } as never);
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1?tab=lifecycle"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Revoke gateway" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.click(within(dialog).getByRole("button", { name: "Revoke gateway" }));
    expect(await within(dialog).findByText("Could not revoke the gateway.")).toBeTruthy();
    expect(screen.getByRole("dialog")).toBeTruthy();
  });

  it("rejects incomplete transfer impact responses instead of fabricating zero counts", async () => {
    hookResult = {
      ...hookResult,
      state: {
        ...readyState,
        homedCounts: { "gw-1": 2, "gw-3": 0 },
        nodes: [
          readyState.nodes[0],
          { ...readyState.nodes[0], id: "gw-3", name: "edge-berlin", site_id: "site-2" },
        ],
      },
    };
    apiPost.mockResolvedValueOnce({ data: { moved: 2 } } as never);
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1?tab=lifecycle"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Move devices" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Destination gateway" }), { target: { value: "gw-3" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Move devices" }));
    expect(await within(dialog).findByText(/incomplete impact response/i)).toBeTruthy();
    expect(within(dialog).queryByText(/0 require/)).toBeNull();
  });

  it("rejects incomplete restore impact responses instead of fabricating zero counts", async () => {
    apiPost.mockResolvedValueOnce({ data: { restored: 1 } } as never);
    render(
      <MemoryRouter initialEntries={["/gateways/gw-2?tab=lifecycle"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    fireEvent.click(screen.getByRole("button", { name: "Restore cascaded devices" }));
    const dialog = screen.getByRole("dialog");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Replacement gateway" }), { target: { value: "gw-1" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Restore devices" }));
    expect(await within(dialog).findByText(/incomplete impact response/i)).toBeTruthy();
    expect(within(dialog).queryByText(/0 require/)).toBeNull();
  });

  it("removes mutation affordances when generated RBAC says no", () => {
    hookResult = { ...hookResult, canManage: false, canTransfer: false, canRestore: false };
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: "Rename" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Lifecycle" }));
    expect(screen.queryByRole("button", { name: "Revoke gateway" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Move devices" })).toBeNull();
    cleanup();
    render(
      <MemoryRouter initialEntries={["/gateways/gw-2?tab=lifecycle"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.queryByRole("button", { name: "Restore cascaded devices" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Delete gateway record" })).toBeNull();
  });

  it("withholds destructive actions when the bounded impact read is unavailable", () => {
    hookResult = { ...hookResult, state: { ...readyState, homedCounts: null } };
    render(
      <MemoryRouter initialEntries={["/gateways/gw-1?tab=lifecycle"]}>
        <Routes><Route path="/gateways/:gatewayId" element={<GatewayDetail />} /></Routes>
      </MemoryRouter>,
    );
    expect(screen.getByText(/Impact count unavailable/)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Revoke gateway" })).toBeNull();
  });
});

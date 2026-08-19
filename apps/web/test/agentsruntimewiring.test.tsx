import { createElement, useState, type ReactNode } from "react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";

const get = vi.fn();
const put = vi.fn();
const patch = vi.fn();
const post = vi.fn();
let currentOrg = { id: "org-a", name: "Enterprise A", max_agent_identities: null as number | null, managed_agent_runtime_enabled: false };
let viewerId = "user-a";
let authStatus: "authed" | "unauthenticated" = "authed";
let issuedCommand = "";

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({ org: currentOrg }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => authStatus === "authed"
    ? { state: { status: "authed", user: { id: viewerId, email: "owner@example.com", email_verified: true } } }
    : { state: { status: "unauthenticated" } },
}));

vi.mock("../src/lib/api", () => ({
  api: {
    GET: get,
    PUT: put,
    POST: post,
    PATCH: patch,
    DELETE: vi.fn(),
  },
  loadOne: async (fn: () => Promise<unknown>) => {
    const result = await fn();
    if ((result as { error?: unknown }).error) {
      return { ok: false, error: "Could not load gateways." };
    }
    return { ok: true, data: (result as { data: unknown }).data };
  },
}));

vi.mock("react-router-dom", () => ({
  Link: ({ children, ...props }: { children: ReactNode; [key: string]: unknown }) =>
    createElement("a", props, children),
}));

vi.mock("../src/components/ui", () => {
  const primitive = (tag: string) =>
    ({ children, ...props }: { children?: ReactNode; [key: string]: unknown }) =>
      createElement(tag, props, children);
  return {
    // The page header is a real component now, not markup each page hand-rolls. Mocked to an h1 so the
    // route's heading stays assertable — a `primitive("header")` would spread `title` onto the DOM node
    // and the text would vanish from the tree.
    PageHeader: ({
      title,
      subtitle,
      actions,
    }: {
      title: string;
      subtitle?: ReactNode;
      actions?: ReactNode;
    }) =>
      createElement(
        "header",
        null,
        createElement("h1", null, title),
        subtitle ?? null,
        actions ?? null,
      ),
    Badge: primitive("span"),
    Button: primitive("button"),
    Card: primitive("section"),
    Field: primitive("label"),
    Input: primitive("input"),
    Select: primitive("select"),
    StatusDot: () => null,
    // This is the released route's table seam: opening a row must render the
    // route-owned expandable panel, not a fixture-only runtime component.
    DataTable: ({ rows, columns, expandable }: { rows: Array<{ name: string; device_id: string }>; columns: Array<{ key: string; header: string; cell?: (row: { name: string; device_id: string }, ctx: { expanded: boolean; toggle: () => void }) => ReactNode }>; expandable?: (row: { name: string; device_id: string }) => ReactNode }) => {
      const [expanded, setExpanded] = useState<string | null>(null);
      return createElement(
        "div",
        null,
        createElement("div", { role: "columnheader" }, ...columns.map((column) => createElement("span", { key: column.key }, column.header))),
        ...rows.map((row) => {
          const isExpanded = expanded === row.device_id;
          return createElement(
            "section",
            { key: row.name },
            ...columns.map((column) => createElement("div", { key: column.key }, column.cell?.(row, { expanded: isExpanded, toggle: () => setExpanded(isExpanded ? null : row.device_id) }))),
            isExpanded ? expandable?.(row) : null,
          );
        }),
      );
    },
  };
});

vi.mock("../src/components/OneTimeSecret", () => ({
  OneTimeSecretModal: () => null,
}));

vi.mock("../src/lib/agentview", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/agentview")>("../src/lib/agentview");
  return {
    ...actual,
    agentBootstrapCommand: (token: string, release: Parameters<typeof actual.agentBootstrapCommand>[1]) => {
      issuedCommand = actual.agentBootstrapCommand(token, release, "https://cp.example");
      return issuedCommand;
    },
    AGENT_PREREQ: "",
    livenessLabel: () => ({ label: "never connected", detail: "never", tone: "warn" }),
    agentLiveness: () => "never",
  };
});

const agent = {
  device_id: "device-a",
  name: "builder-a",
  owner_email: "owner@example.com",
  unattributable: false,
  address: "10.99.0.7",
  gateway_name: "gateway-a",
  node_id: "node-a",
  config_issued: true,
  online: true,
  last_handshake_at: "2026-08-14T10:00:00Z",
  gateway_reporting: true,
  rx_bytes: 12,
  tx_bytes: 34,
  status: "active",
};

const profile = {
  device_id: "device-a",
  name: "builder-a",
  environment: "prod",
  runtime: "python",
  labels: { team: "sec" },
  owner_id: "user-a",
  owner_email: "owner@example.com",
  managing_group_id: null,
  managing_group_name: null,
  permissions: {
    view_privileged: true,
    manage: true,
    assign: true,
    grant_access: true,
    revoke: true,
    rotate_credentials: true,
  },
  status: "active",
  last_handshake_at: "2026-08-14T10:00:00Z",
  rx_bytes: 12,
  tx_bytes: 34,
};

const runtime = {
  desired_revision: 7,
  applied_revision: 5,
  last_attempted_revision: 6,
  client_version: "agent-1.2.3",
  last_seen_at: "2026-08-14T10:01:00Z",
  connectivity: "connected",
  health: "last_good",
  stale: false,
  last_error_code: "apply_failed",
};

function seedListResponses() {
  get.mockImplementation(async (path: string) => {
    if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
    if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
    if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
    if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }], response: { status: 200 } };
    return { data: undefined, error: { error: { code: "not_implemented" } }, response: { status: 404 } };
  });
}

afterEach(() => {
  cleanup();
  get.mockReset();
  put.mockReset();
  patch.mockReset();
  post.mockReset();
  issuedCommand = "";
  currentOrg = { id: "org-a", name: "Enterprise A", max_agent_identities: null, managed_agent_runtime_enabled: false };
  viewerId = "user-a";
  authStatus = "authed";
});

describe("released Agents route — F04 runtime facts", () => {
  it("requests credential rotation and renders only the refetched secret-free status", async () => {
    let status: { device_id: string; current_revision: number; state: string; requested_revision: number | null; deadline: string | null; wireguard_current_revision: number; wireguard_state: string; wireguard_requested_revision: number | null } = {
      device_id: "device-a", current_revision: 1, state: "current", requested_revision: null, deadline: null,
      wireguard_current_revision: 1, wireguard_state: "current", wireguard_requested_revision: null,
    };
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      if (path.endsWith("/credential-rotation")) return { data: status, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    post.mockImplementation(async (path: string) => {
      if (path.endsWith("/credential-rotation")) {
        status = { device_id: "device-a", current_revision: 1, state: "requested", requested_revision: 2, deadline: "2026-08-15T12:00:00Z", wireguard_current_revision: 1, wireguard_state: "requested", wireguard_requested_revision: 2 };
        return { data: status, response: { status: 200 } };
      }
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    fireEvent.click(await screen.findByRole("button", { name: "Rotate credential" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/{deviceId}/credential-rotation",
      { params: { path: { orgId: "org-a", deviceId: "device-a" } } },
    ));
    await waitFor(() => expect(screen.getAllByText("Revision 1 · requested")).toHaveLength(2));
    const rotationGets = get.mock.calls.filter(([path]) => String(path).endsWith("/credential-rotation"));
    expect(rotationGets.length).toBeGreaterThanOrEqual(2);
    expect(document.body.textContent).not.toMatch(/tnx_runtime_|token_hash|[0-9a-f]{64}/i);
  });

  it("shows rotation status read-only to the accountable member-owner", async () => {
    viewerId = "member-b";
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [], response: { status: 200 } };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "member-b", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: {
        ...profile,
        owner_id: "member-b",
        owner_email: "member@example.com",
        permissions: { ...profile.permissions, assign: false, grant_access: false, rotate_credentials: false },
      }, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      if (path.endsWith("/credential-rotation")) return { data: {
        device_id: "device-a", current_revision: 2, state: "current", requested_revision: null, deadline: null,
        wireguard_current_revision: 3, wireguard_state: "current", wireguard_requested_revision: null,
      }, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.queryByTestId("agent-profile")).not.toBeNull());
    expect(screen.getByTestId("agent-credential-rotation")).toBeTruthy();
    expect(screen.getByText("Revision 2 · current")).toBeTruthy();
    expect(screen.getByText("Revision 3 · current")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Rotate credential" })).toBeNull();
    expect(screen.queryByTestId("agent-assignment-editor")).toBeNull();
    expect(screen.getByRole("button", { name: "Remove" })).toBeTruthy();
    expect(get.mock.calls.some(([path]) => String(path).endsWith("/credential-rotation"))).toBe(true);
  });

  it("changes owner and managing team through one server-refetched profile PATCH", async () => {
    const members = [
      { user_id: "user-a", email: "owner@example.com", name: "Owner", role: "owner", status: "active", email_verified: true, joined_at: "2026-08-14T10:00:00Z" },
      { user_id: "user-b", email: "next@example.com", name: "Next", role: "member", status: "active", email_verified: true, joined_at: "2026-08-14T10:00:00Z" },
    ];
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [], response: { status: 200 } };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: members, response: { status: 200 } };
      if (path.endsWith("/groups")) return { data: [{ id: "group-a", org_id: "org-a", name: "Platform", description: "", created_at: "2026-08-14T10:00:00Z", updated_at: "2026-08-14T10:00:00Z" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    patch.mockResolvedValue({ data: { ...profile, owner_id: "user-b", owner_email: "next@example.com", managing_group_id: "group-a", managing_group_name: "Platform" }, response: { status: 200 } });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    const editor = await screen.findByTestId("agent-assignment-editor");
    const [ownerSelect, groupSelect] = within(editor).getAllByRole("combobox");
    fireEvent.change(ownerSelect, { target: { value: "user-b" } });
    fireEvent.change(groupSelect, { target: { value: "group-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Save assignment" }));
    await waitFor(() => expect(patch).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/{deviceId}",
      {
        params: { path: { orgId: "org-a", deviceId: "device-a" } },
        body: { owner_id: "user-b", managing_group_update: { group_id: "group-a" } },
      },
    ));
    expect(screen.getByText(/does not change the tunnel or access grants/i)).toBeTruthy();
    expect(screen.getByText(/cannot grant access, rotate credentials, or revoke it/i)).toBeTruthy();
  });

  it("passes the server-owned immutable release DTO into the real enrollment command", async () => {
    seedListResponses();
    const release = {
      tag: "v0.4.0",
      source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      manifest_url: "https://github.com/tunnexio/tunnex/releases/download/v0.4.0/release.json",
      verifier_key_id: "release-2026-01",
      runtime: {
        binary: "tunnex-agent-runtime",
        version: "v0.4.0",
        linux_amd64: {
          name: "tunnex-agent-runtime-linux-amd64",
          sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
          source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        linux_arm64: {
          name: "tunnex-agent-runtime-linux-arm64",
          sha256: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
          source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
        unit: {
          name: "tunnex-agent-runtime.service",
          sha256: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
          source_sha: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        },
      },
    };
    post.mockImplementation(async (path: string) => {
      if (path.endsWith("/agents/bootstrap-token")) {
        return { data: { bootstrap_token: "tnx_one_time_test", release }, response: { status: 200 } };
      }
      return { data: undefined, error: { error: { code: "not_implemented" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));

    await screen.findByRole("button", { name: "Enrol agent" });
    fireEvent.change(screen.getByPlaceholderText("mcp-agent-prod"), { target: { value: "runtime-a" } });
    fireEvent.click(screen.getByRole("button", { name: "Enrol agent" }));

    await waitFor(() => expect(post).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/bootstrap-token",
      {
        params: { path: { orgId: "org-a" } },
        body: { name: "runtime-a", gateway_id: "node-a" },
      },
    ));
    await waitFor(() => expect(issuedCommand).toMatch(/release_tag=.*v0\.4\.0/));
    expect(issuedCommand).toMatch(/source_sha=.*aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/);
    expect(issuedCommand).toContain("https://github.com/tunnexio/tunnex/releases/download/v0.4.0/release.json");
    expect(issuedCommand).toMatch(/verifier_key_id=.*release-2026-01/);
    expect(issuedCommand).toContain("tunnex-agent-runtime-linux-amd64");
    expect(issuedCommand).toContain("tunnex-agent-runtime.service");
    expect(issuedCommand).not.toMatch(/-----BEGIN|runtime-secret-test|public-key-test|token_hash/i);
  });

  it("lets an authorized owner persist the explicit runtime opt-in and resets it on org switch", async () => {
    seedListResponses();
    put.mockImplementation(async (path: string, request: { body: { enabled?: boolean } }) => {
      if (path.endsWith("/agent-runtime-settings")) return { data: { enabled: request.body.enabled }, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    const { rerender } = render(createElement(Agents));
    const enable = await screen.findByRole("button", { name: "Enable runtime synchronization" });
    fireEvent.click(enable);
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agent-runtime-settings",
      { params: { path: { orgId: "org-a" } }, body: { enabled: true } },
    ));
    await waitFor(() => expect(screen.getByRole("button", { name: "Disable runtime synchronization" })).toBeTruthy());

    currentOrg = { id: "org-b", name: "Enterprise B", max_agent_identities: null, managed_agent_runtime_enabled: false };
    rerender(createElement(Agents));
    await waitFor(() => expect(screen.getByRole("button", { name: "Enable runtime synchronization" })).toBeTruthy());
  });

  it("keeps the runtime opt-in control absent for a plain member", async () => {
    viewerId = "member-b";
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [], response: { status: 200 } };
      if (path.endsWith("/agents")) return { data: [], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "member-b", role: "member" }], response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    await waitFor(() => expect(screen.queryByText("AI agents")).not.toBeNull());
    expect(screen.queryByTestId("agent-runtime-setting-card")).toBeNull();
    expect(screen.queryByText("Runtime synchronization")).toBeNull();
  });

  it("saves value and null quotas from the scoped response across refetch and org switch", async () => {
    seedListResponses();
    put.mockImplementation(async (_path: string, request: { body: { max_agent_identities: number | null } }) => ({
      data: { ...currentOrg, max_agent_identities: request.body.max_agent_identities },
      response: { status: 200 },
    }));
    const { default: Agents } = await import("../src/pages/Agents");
    const { rerender } = render(createElement(Agents));
    const input = await screen.findByLabelText("Maximum agent identities");

    fireEvent.change(input, { target: { value: "2" } });
    fireEvent.click(screen.getByRole("button", { name: "Save quota" }));
    await waitFor(() => expect(put).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agent-quota",
      { params: { path: { orgId: "org-a" } }, body: { max_agent_identities: 2 } },
    ));
    await waitFor(() => expect((input as HTMLInputElement).value).toBe("2"));
    expect(get).not.toHaveBeenCalledWith("/api/v1/organizations");

    currentOrg = { id: "org-b", name: "Enterprise B", max_agent_identities: null, managed_agent_runtime_enabled: false };
    rerender(createElement(Agents));
    await waitFor(() => expect((screen.getByLabelText("Maximum agent identities") as HTMLInputElement).value).toBe(""));

    currentOrg = { id: "org-a", name: "Enterprise A", max_agent_identities: 2, managed_agent_runtime_enabled: false };
    rerender(createElement(Agents));
    await waitFor(() => expect((screen.getByLabelText("Maximum agent identities") as HTMLInputElement).value).toBe("2"));

    fireEvent.change(screen.getByLabelText("Maximum agent identities"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "Save quota" }));
    await waitFor(() => expect(put).toHaveBeenLastCalledWith(
      "/api/v1/organizations/{orgId}/agent-quota",
      { params: { path: { orgId: "org-a" } }, body: { max_agent_identities: null } },
    ));
    await waitFor(() => expect((screen.getByLabelText("Maximum agent identities") as HTMLInputElement).value).toBe(""));
  });

  it("authorized enterprise operator opens an agent and calls the real org/device runtime endpoint", async () => {
    seedListResponses();
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));

    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));

    // The released route's DataTable row/expand seam is backed by the
    // canonical generated operation:
    // GET /api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status
    await waitFor(() => {
      expect(get).toHaveBeenCalledWith(
        "/api/v1/organizations/{orgId}/agents/{deviceId}/runtime-status",
        { params: { path: { orgId: "org-a", deviceId: "device-a" } } },
      );
    });
  });

  it("renders only server runtime facts and replaces them on org switch/refetch", async () => {
    seedListResponses();
    let releaseOrgBAgents!: () => void;
    let releaseOrgBNodes!: () => void;
    const orgBAgents = new Promise<void>((resolve) => { releaseOrgBAgents = resolve; });
    const orgBNodes = new Promise<void>((resolve) => { releaseOrgBNodes = resolve; });
    get.mockImplementation(async (path: string, options?: { params?: { path?: { orgId?: string } } }) => {
      if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) {
        return options?.params?.path?.orgId === "org-a"
          ? { data: runtime, response: { status: 200 } }
          : { data: { ...runtime, desired_revision: 9, applied_revision: 9, connectivity: "disconnected", health: "inconclusive", last_seen_at: null, stale: true, last_error_code: null }, response: { status: 200 } };
      }
      if (path.endsWith("/nodes")) {
        if (options?.params?.path?.orgId === "org-b") {
          await orgBNodes;
          return { data: [{ id: "node-b", name: "gateway-b", status: "active", endpoint: "gw-b.example:51820" }] };
        }
        return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      }
      if (path.endsWith("/agents")) {
        if (options?.params?.path?.orgId === "org-b") await orgBAgents;
        return { data: [agent], response: { status: 200 } };
      }
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }], response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_implemented" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    const { rerender } = render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));

    await waitFor(() => expect(screen.queryByText("Desired revision")).not.toBeNull());
    expect(screen.getByText("7")).toBeTruthy();
    expect(screen.getByText("5")).toBeTruthy();
    expect(screen.getByText("apply_failed")).toBeTruthy();
    expect(screen.getByText("Last-good configuration")).toBeTruthy();
    expect(screen.getByText("Fresh report")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/tnx_|bootstrap_token|runtime_credential|private_key|token_hash/i);

    currentOrg = { id: "org-b", name: "Enterprise B", max_agent_identities: null, managed_agent_runtime_enabled: false };
    rerender(createElement(Agents));
    await waitFor(() => expect(screen.queryByText("builder-a")).toBeNull());
    expect(screen.queryByRole("option", { name: "gateway-a" })).toBeNull();
    expect(screen.queryByText("Loading…")).not.toBeNull();
    releaseOrgBNodes();
    releaseOrgBAgents();
    await waitFor(() => expect(screen.queryByText("7")).toBeNull());
    expect(screen.getByRole("option", { name: /gateway-b/ })).toBeTruthy();
    expect(screen.queryByRole("option", { name: "gateway-a" })).toBeNull();
    expect(screen.queryByText("5")).toBeNull();
    expect(screen.queryByText("apply_failed")).toBeNull();
    expect(document.body.textContent).not.toMatch(/tnx_|bootstrap_token|runtime_credential|private_key|token_hash/i);
  });

  it.each(["forbidden", "edition_required", "member_no_permission", "loading_failure"])(
    "%s leaves runtime facts absent from the released route DOM",
    async (mode) => {
      seedListResponses();
      get.mockImplementation(async (path: string) => {
        if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
        if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
        if (path.endsWith("/agents/{deviceId}")) return { data: undefined, error: { error: { code: mode === "loading_failure" ? "unavailable" : mode } }, response: { status: 403 } };
        if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }], response: { status: 200 } };
        if (mode === "edition_required") return { data: undefined, error: { error: { code: "edition_required" } }, response: { status: 403 } };
        if (mode === "forbidden" || mode === "member_no_permission") return { data: undefined, error: { error: { code: "forbidden" } }, response: { status: 403 } };
        if (mode === "loading_failure") return { data: undefined, error: { error: { code: "unavailable" } }, response: { status: 503 } };
        return { data: runtime, response: { status: 200 } };
      });
      const { default: Agents } = await import("../src/pages/Agents");
      render(createElement(Agents));
      fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
      await waitFor(() => {
        expect(screen.queryByTestId("agent-runtime-status")).toBeNull();
      });
    },
  );

  it("renders stale last-good server facts instead of hiding the runtime panel", async () => {
    seedListResponses();
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "owner" }], response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: { ...runtime, connectivity: "disconnected", health: "last_good", stale: true }, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.getByTestId("agent-runtime-status")).toBeTruthy());
    expect(screen.getByText("Last-good configuration")).toBeTruthy();
    expect(screen.getByText("Stale report")).toBeTruthy();
    expect(screen.getByText("disconnected")).toBeTruthy();
    expect(screen.getByText("apply_failed")).toBeTruthy();
  });

  it.each([
    ["member", "forbidden"],
    ["unauthorized", "unauthorized"],
  ])("renders no released Agents route for %s list refusal", async (viewer, code) => {
    if (viewer === "member") viewerId = "member-b";
    if (viewer === "unauthorized") authStatus = "unauthenticated";
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "member-b", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents")) return { data: undefined, error: { error: { code } }, response: { status: code === "unauthorized" ? 401 : 403 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    await waitFor(() => expect(screen.queryByText("AI agents")).toBeNull());
    expect(screen.queryByTestId("agent-quota-card")).toBeNull();
    expect(document.body.textContent).not.toMatch(/builder-a|10\.99\.0\.7|owner@example\.com|Managed-agent quota/i);
  });

  it("lets the owner save metadata through PATCH, then refetches server persistence without lifecycle fields", async () => {
    let serverProfile = { ...profile };
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: serverProfile, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    patch.mockImplementation(async (_path: string, request: { body: Record<string, unknown> }) => {
      serverProfile = { ...serverProfile, ...request.body };
      return { data: serverProfile, response: { status: 200 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.getByLabelText("Environment")).toBeTruthy());

    fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "staging" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    await waitFor(() => expect(patch).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/{deviceId}",
      { params: { path: { orgId: "org-a", deviceId: "device-a" } }, body: { environment: "staging", runtime: "python", labels: { team: "sec" } } },
    ));
    expect(patch.mock.calls[0][1].body).not.toHaveProperty("status");
    await waitFor(() => expect((screen.getByLabelText("Environment") as HTMLInputElement).value).toBe("staging"));
  });

  it("resets a failed metadata PATCH to the last server snapshot without partial state", async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: profile, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    patch.mockResolvedValue({ data: undefined, error: { error: { code: "unavailable" } }, response: { status: 503 } });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.getByLabelText("Environment")).toBeTruthy());
    fireEvent.change(screen.getByLabelText("Environment"), { target: { value: "broken-local-draft" } });
    fireEvent.click(screen.getByRole("button", { name: "Save metadata" }));
    await waitFor(() => expect((screen.getByLabelText("Environment") as HTMLInputElement).value).toBe("prod"));
    expect(screen.queryByText("broken-local-draft")).toBeNull();
  });

  it("confirms admin suspend/resume and does not show terminal state before the server response", async () => {
    let serverProfile = { ...profile };
    let releasePatch!: (value: unknown) => void;
    const patchResponse = new Promise((resolve) => { releasePatch = resolve; });
    let lifecycleCalls = 0;
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "admin" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: serverProfile, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    patch.mockImplementation(async (_path: string, request: { body: { status: "active" | "suspended" } }) => {
      serverProfile = { ...serverProfile, status: request.body.status };
      lifecycleCalls += 1;
      return lifecycleCalls === 1 ? patchResponse : { data: serverProfile, response: { status: 200 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.getByRole("button", { name: "Suspend agent" })).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Suspend agent" }));
    expect(screen.getByRole("alertdialog")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Confirm suspension" }));
    expect(screen.getByText("Lifecycle: active")).toBeTruthy();
    expect(patch).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/agents/{deviceId}",
      { params: { path: { orgId: "org-a", deviceId: "device-a" } }, body: { status: "suspended" } },
    );
    releasePatch({ data: serverProfile, response: { status: 200 } });
    await waitFor(() => expect(screen.getByText("Lifecycle: suspended")).toBeTruthy());
    fireEvent.click(screen.getByRole("button", { name: "Resume agent" }));
    fireEvent.click(screen.getByRole("button", { name: "Confirm resume" }));
    await waitFor(() => expect(screen.getByText("Lifecycle: active")).toBeTruthy());
    expect(patch).toHaveBeenLastCalledWith(
      "/api/v1/organizations/{orgId}/agents/{deviceId}",
      { params: { path: { orgId: "org-a", deviceId: "device-a" } }, body: { status: "active" } },
    );
  });

  it("keeps profile identity, metadata, telemetry, lifecycle, and controls absent when profile access is refused", async () => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: undefined, error: { error: { code: "forbidden" } }, response: { status: 403 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    await waitFor(() => expect(screen.queryByTestId("agent-profile")).toBeNull());
    expect(document.body.textContent).not.toMatch(/owner@example\.com|Managing team|Environment|Runtime|Telemetry|Lifecycle|Save assignment|Suspend agent|Resume agent|runtime_credential|bootstrap_token|private_key|token_hash/i);
  });

  it("removes the owner column and owner email for a plain member even when the list payload contains it", async () => {
    viewerId = "member-b";
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "member-b", role: "member" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: undefined, error: { error: { code: "forbidden" } }, response: { status: 403 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    await waitFor(() => expect(screen.queryByText("AI agents")).not.toBeNull());
    expect(screen.queryByText("Authorised by")).toBeNull();
    expect(screen.queryByText("owner@example.com")).toBeNull();
    expect(screen.queryByText("Actions")).toBeNull();
    expect(screen.queryByRole("button", { name: "Remove" })).toBeNull();
    // Basic roster health is organization-viewable. The permission boundary is
    // owner attribution plus the privileged profile/runtime and lifecycle facts.
    expect(screen.getByText("Status")).toBeTruthy();
    expect(screen.getByText("never connected")).toBeTruthy();
    expect(screen.getByText("Traffic")).toBeTruthy();
    expect(screen.getByText("↓ 12 B · ↑ 34 B")).toBeTruthy();
    expect(screen.queryByText("Telemetry")).toBeNull();
  });

  it("keeps the owner column for a server-authorized manager", async () => {
    seedListResponses();
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    await waitFor(() => expect(screen.queryByText("Authorised by")).not.toBeNull());
    expect(screen.getAllByText("owner@example.com").length).toBeGreaterThan(0);
    expect(screen.queryByText("Actions")).not.toBeNull();
    expect(screen.getByRole("button", { name: "Remove" })).toBeTruthy();
  });

  it.each([
    ["pending", /awaiting approval/i, /suspend agent|resume agent/i],
    ["revoked", /revoked is terminal/i, /suspend agent|resume agent/i],
  ])("renders %s as a non-bypassable lifecycle state", async (status, message, forbiddenControls) => {
    get.mockImplementation(async (path: string) => {
      if (path.endsWith("/nodes")) return { data: [{ id: "node-a", name: "gateway-a", status: "active", endpoint: "gw.example:51820" }] };
      if (path.endsWith("/agents")) return { data: [agent], response: { status: 200 } };
      if (path.endsWith("/members")) return { data: [{ user_id: "user-a", role: "admin" }], response: { status: 200 } };
      if (path.endsWith("/agents/{deviceId}")) return { data: { ...profile, status }, response: { status: 200 } };
      if (path.endsWith("/runtime-status")) return { data: runtime, response: { status: 200 } };
      return { data: undefined, error: { error: { code: "not_found" } }, response: { status: 404 } };
    });
    const { default: Agents } = await import("../src/pages/Agents");
    render(createElement(Agents));
    fireEvent.click(await screen.findByRole("button", { name: "Open builder-a" }));
    expect(await screen.findByText(message)).toBeTruthy();
    expect(screen.queryByRole("button", { name: forbiddenControls })).toBeNull();
  });
});

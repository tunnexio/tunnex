import { afterEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { Profiler } from "react";

let currentOrg = { id: "org-a", name: "Organization A" };
let releaseOrgBMembers: (() => void) | null = null;
let currentUser = { id: "admin-a", email: "admin@example.com", email_verified: true };
let policyReadDelay: Promise<void> | undefined;
let currentMode: "off" | "enforcing" = "enforcing";

vi.mock("../src/lib/useOrg", () => ({
  useOrg: () => ({
    org: currentOrg,
    orgs: [currentOrg],
    setOrg: vi.fn(),
    loading: false,
    failed: false,
  }),
}));

vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({
    state: {
      status: "authed",
      user: currentUser,
    },
  }),
}));

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { orgId?: string } } }) => {
        const orgId = request?.params?.path?.orgId ?? currentOrg.id;
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path.endsWith("/members")) {
          if (orgId === "org-b") {
            await new Promise<void>((resolve) => {
              releaseOrgBMembers = resolve;
            });
          }
          return {
            data: [{
              user_id: currentUser.id,
              role: orgId === "org-c" || currentUser.id !== "admin-a" ? "member" : "admin",
              email_verified: true,
            }],
          };
        }
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: currentMode } };
        if (path.endsWith("/policies")) {
          if (policyReadDelay) await policyReadDelay;
          return orgId === "org-a"
            ? {
                data: [{
                  id: "old-agent-rule",
                  enabled: true,
                  src_kind: "agent",
                  src_device_id: "old-agent-id",
                  dst_kind: "resource",
                  dst_resource_id: "resource-a",
                }],
              }
            : { data: [] };
        }
        if (path.endsWith("/agents")) {
          return orgId === "org-a"
            ? { data: [{ device_id: "old-agent-id", name: "old-org-agent", gateway_name: "gw-a" }] }
            : { data: [] };
        }
        if (path.endsWith("/resources")) {
          return orgId === "org-a"
            ? { data: [{ id: "resource-a", name: "old-org-resource" }] }
            : { data: [] };
        }
        if (path.endsWith("/groups") || path.endsWith("/sites")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import Access from "../src/pages/Access";
import { NetworkFeatureControl } from "../src/components/NetworkFeatureControl";
import { api } from "../src/lib/api";

const page = () => <MemoryRouter><Access /></MemoryRouter>;

afterEach(() => {
  releaseOrgBMembers?.();
  releaseOrgBMembers = null;
  currentOrg = { id: "org-a", name: "Organization A" };
  currentUser = { id: "admin-a", email: "admin@example.com", email_verified: true };
  policyReadDelay = undefined;
  currentMode = "enforcing";
  vi.mocked(api.POST).mockClear();
  vi.mocked(api.PUT).mockClear();
  vi.mocked(api.DELETE).mockClear();
  cleanup();
});

describe("released Access route organization isolation", () => {
  it("withdraws old facts and ignores an out-of-order admin response after A to B to C", async () => {
    const view = render(page());
    await screen.findAllByText("old-org-agent");
    expect(screen.getAllByText("old-org-resource").length).toBeGreaterThan(0);

    currentOrg = { id: "org-b", name: "Organization B" };
    view.rerender(page());

    expect(screen.queryAllByText("old-org-agent")).toHaveLength(0);
    expect(screen.queryAllByText("old-org-resource")).toHaveLength(0);
    expect(screen.getByText("Loading rules…")).toBeTruthy();

    await waitFor(() => expect(releaseOrgBMembers).not.toBeNull());
    currentOrg = { id: "org-c", name: "Organization C" };
    view.rerender(page());
    await waitFor(() =>
      expect(screen.getByText("Access policies are managed by owners and admins.")).toBeTruthy(),
    );

    releaseOrgBMembers?.();
    await waitFor(() =>
      expect(screen.getByText("Access policies are managed by owners and admins.")).toBeTruthy(),
    );
    expect(screen.queryByRole("button", { name: "Add rule" })).toBeNull();
    expect(screen.queryAllByText("old-org-agent")).toHaveLength(0);
  });

  it("withdraws prior-admin rules and central feature access at every actor-switch commit", async () => {
    const leakedCommits: boolean[] = [];
    const workspace = () => <MemoryRouter><Profiler id="policy-scope" onRender={() => {
      if (currentUser.id !== "admin-a") leakedCommits.push(Boolean(screen.queryByRole("button", { name: "Add rule" }) || screen.queryByRole("dialog") || screen.queryByText("old-org-agent")));
    }}><Access /></Profiler></MemoryRouter>;
    const view = render(workspace());
    await screen.findByRole("checkbox", { name: "Select old-org-agent" });
    expect(within(screen.getByRole("region", { name: "Policy enforcement" })).getByRole("link", { name: "Manage in Features" }).getAttribute("href")).toBe("/settings?section=features&feature=zero-trust");
    expect(screen.queryByRole("button", { name: "Disable" })).toBeNull();
    currentUser = { ...currentUser, id: "member-b" };
    view.rerender(workspace());
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByText("Access policies are managed by owners and admins.");
    expect(leakedCommits.length).toBeGreaterThan(0);
    expect(leakedCommits).not.toContain(true);
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("ignores a pending enabling count after the organization changes", async () => {
    currentMode = "off";
    const central = () => <MemoryRouter><NetworkFeatureControl feature="zero-trust" orgId={currentOrg.id} roles={currentOrg.id === "org-a" ? ["admin"] : ["member"]} canEdit={currentOrg.id === "org-a"} /></MemoryRouter>;
    const view = render(central());
    const enable = await screen.findByRole("button", { name: "Enable enforcing" });
    let release!: () => void;
    policyReadDelay = new Promise<void>(resolve => { release = resolve; });
    fireEvent.click(enable);
    currentOrg = { id: "org-c", name: "Organization C" };
    view.rerender(central());
    expect(screen.queryByRole("button", { name: "Enable enforcing" })).toBeNull();
    await act(async () => release());
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(api.PUT).not.toHaveBeenCalled();
  });

  it("does not remove an old rule after a pending replacement succeeds in a superseded editor scope", async () => {
    const view = render(page());
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select old-org-agent" }));
    fireEvent.click(screen.getByRole("button", { name: "Edit" }));
    const dialog = screen.getByRole("dialog", { name: "Edit rule" });
    fireEvent.click(within(dialog).getByRole("button", { name: "Review rule" }));
    let complete!: (value: unknown) => void;
    vi.mocked(api.POST).mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }) as never);
    fireEvent.click(within(dialog).getByRole("button", { name: "Save" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(1));
    expect(api.DELETE).not.toHaveBeenCalled();
    currentOrg = { id: "org-c", name: "Organization C" };
    view.rerender(page());
    await screen.findByText("Access policies are managed by owners and admins.");
    await act(async () => complete({ data: { id: "replacement-in-old-org" } }));
    expect(api.DELETE).not.toHaveBeenCalled();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByText(/New rule created, but the old rule/)).toBeNull();
  });
});

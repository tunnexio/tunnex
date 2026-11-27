import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const { get, post } = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn() }));
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: { GET: get, POST: post, PUT: vi.fn(), PATCH: vi.fn(), DELETE: vi.fn() } };
});

import { AgentAccessPanel, portsText } from "../src/components/AgentAccess";

const summaryPath = "/api/v1/organizations/{orgId}/agents/{deviceId}/access-summary";
const previewPath = "/api/v1/organizations/{orgId}/agents/{deviceId}/owner-access-preview";
const createPath = "/api/v1/organizations/{orgId}/agents/{deviceId}/owner-access-rules";
const params = { params: { path: { orgId: "org-a", deviceId: "device-1" } } };
const destination = (over: Record<string, unknown> = {}) => ({ kind: "resource", id: "res-1", name: "Billing database", address: "10.20.0.5/32", protocol: "tcp", port_low: 5432, port_high: 5432, ...over });
const rule = (over: Record<string, unknown> = {}) => ({ rule_id: "rule-1", via: "agent", group_id: null, group_name: null, destination: destination(), expires_at: null, enabled: true, ...over });
const candidate = (over: Record<string, unknown> = {}) => ({ key: "k1", destination: destination(), via: "user", via_group_name: null, source_rule_id: "src-1", copyable: true, already_covered: false, ...over });
let summary: Record<string, unknown> = {};
let preview: unknown = {};
const show = (props: { ownerEmail?: string | null; canGrant?: boolean } = {}) => render(<MemoryRouter><AgentAccessPanel orgId="org-a" deviceId="device-1" agentName="billing-runner" ownerEmail={props.ownerEmail === undefined ? "dana@example.test" : props.ownerEmail} canGrant={props.canGrant ?? true} /></MemoryRouter>);

beforeEach(() => {
  summary = { rules: [rule(), rule({ rule_id: "rule-2", via: "agent_group", group_id: "g1", group_name: "Finance agents", destination: destination({ kind: "site", name: "Head office", address: "10.30.0.0/16", protocol: "any", port_low: null, port_high: null }) }), rule({ rule_id: "rule-3", enabled: false, destination: destination({ name: "Old API", port_low: 8000, port_high: 8100 }) })], refusals: { available: true, required_plan: null, items: [{ dst: "10.20.0.9", port: 22, protocol: "tcp", count: 14, last_seen: "2026-11-27T09:58:00Z" }] } };
  preview = { data: { owner_email: "dana@example.test", candidates: [candidate(), candidate({ key: "k2", destination: destination({ name: "Reports", address: "10.20.0.8/32", port_low: 443, port_high: 443 }), via: "group", via_group_name: "Finance" }), candidate({ key: "k3", destination: destination({ name: "Head office", kind: "site" }), already_covered: true }), candidate({ key: "k4", destination: destination({ name: "Wiki", kind: "app" }), copyable: false })] } };
  get.mockImplementation(async () => ({ data: summary }));
  post.mockImplementation(async (path: string) => path === previewPath ? preview : { data: { rule_ids: ["new-1", "new-2"] } });
});
afterEach(() => { cleanup(); get.mockReset(); post.mockReset(); });

describe("agent Access tab", () => {
  it("lists what the agent can reach: each rule with its destination, port, who it is given to and its status", async () => {
    show();
    const table = within(await screen.findByRole("table", { name: "What this agent can reach" }));
    expect(get).toHaveBeenCalledWith(summaryPath, params);
    expect(table.getAllByRole("columnheader").map((header) => header.textContent)).toEqual(["Destination", "Protocol and port", "Given to", "Status"]);
    const first = within(table.getByText("Billing database").closest("tr") as HTMLElement);
    expect(first.getByText("Resource · 10.20.0.5/32")).toBeTruthy();
    expect(first.getByText("TCP 5432")).toBeTruthy();
    expect(first.getByText("This agent")).toBeTruthy();
    expect(first.getByText("Active")).toBeTruthy();
    const second = within(table.getByText("Head office").closest("tr") as HTMLElement);
    expect(second.getByText("Any protocol, any port")).toBeTruthy();
    expect(second.getByText("Agent group Finance agents")).toBeTruthy();
    const third = within(table.getByText("Old API").closest("tr") as HTMLElement);
    expect(third.getByText("TCP 8000 to 8100")).toBeTruthy();
    expect(third.getByText("Turned off")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Add or change rules for this agent" }).getAttribute("href")).toBe("/access?agent=device-1");
    expect(portsText({ protocol: "udp", port_low: 53, port_high: null })).toBe("UDP 53");
  });

  it("lists what the agent was refused recently", async () => {
    show();
    const table = within(await screen.findByRole("table", { name: "Recently refused" }));
    const row = within(table.getByText("10.20.0.9").closest("tr") as HTMLElement);
    expect(row.getByText("TCP 22")).toBeTruthy();
    expect(row.getByText("14")).toBeTruthy();
  });

  it("says nothing was refused when that is so", async () => {
    summary = { ...summary, refusals: { available: true, required_plan: null, items: [] } };
    show();
    expect(await screen.findByText("Nothing this agent tried to reach was refused recently.")).toBeTruthy();
  });

  it("names the plan where refusals are not available, instead of an empty list", async () => {
    summary = { ...summary, refusals: { available: false, required_plan: "scale", items: [] } };
    show();
    expect((await screen.findByRole("note")).textContent).toContain("Seeing what an agent was refused is included in the Scale plan.");
    expect(screen.getByRole("link", { name: "See your plan" }).getAttribute("href")).toBe("/settings?section=licence");
    expect(screen.queryByRole("table", { name: "Recently refused" })).toBeNull();
    expect(screen.queryByText("Nothing this agent tried to reach was refused recently.")).toBeNull();
    // The list of what it can reach is still shown.
    expect(screen.getByRole("table", { name: "What this agent can reach" })).toBeTruthy();
  });

  it("does not show a failed read as an agent with no access", async () => {
    get.mockResolvedValueOnce({ error: { error: { code: "agent_ux_not_implemented", message: "Not available yet." } } });
    show();
    expect((await screen.findByRole("alert")).textContent).toBe("What this agent can reach could not be loaded: Not available yet.");
    expect(screen.queryByText("This agent cannot reach anything yet")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry access" }));
    expect(await screen.findByRole("table", { name: "What this agent can reach" })).toBeTruthy();
  });

  it("tells an agent with no rule that it cannot reach anything and offers the owner's access as a start", async () => {
    summary = { ...summary, rules: [] };
    show();
    expect(await screen.findByRole("heading", { name: "This agent cannot reach anything yet" })).toBeTruthy();
    expect(screen.getByText(/You can start from what its owner, dana@example\.test, can reach/)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Create rules from the owner's access" })).toBeTruthy();
    expect(post).not.toHaveBeenCalled();
  });

  it("offers no owner shortcut for an agent with no owner, or to a person who cannot grant access", async () => {
    summary = { ...summary, rules: [] };
    show({ ownerEmail: null });
    expect(await screen.findByText(/It has no owner to start from, so add rules for it directly\./)).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Create rules from the owner's access" })).toBeNull();
    cleanup();
    show({ canGrant: false });
    await screen.findByRole("heading", { name: "This agent cannot reach anything yet" });
    expect(screen.queryByRole("button", { name: "Create rules from the owner's access" })).toBeNull();
    expect(screen.queryByRole("link", { name: "Add a rule for this agent" })).toBeNull();
  });

  it("previews the owner's destinations with tick boxes and creates nothing until confirmed", async () => {
    summary = { ...summary, rules: [] };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Create rules from the owner's access" }));
    await dialog.findByRole("list", { name: "The owner's destinations" });
    expect(post).toHaveBeenCalledTimes(1);
    expect(post).toHaveBeenCalledWith(previewPath, params);
    expect(dialog.getByText(/Nothing is created until you confirm\./)).toBeTruthy();
    const boxes = dialog.getAllByRole("checkbox") as HTMLInputElement[];
    expect(boxes.map((box) => box.checked)).toEqual([false, false, false, false]);
    expect(boxes.map((box) => box.disabled)).toEqual([false, false, true, true]);
    expect(dialog.getByText("The agent already has a rule for this.")).toBeTruthy();
    expect(dialog.getByText("A rule for an agent cannot name this kind of destination.")).toBeTruthy();
    expect(dialog.getByText(/the owner has it through the group Finance/)).toBeTruthy();
    const confirm = dialog.getByRole("button", { name: "Create rules" }) as HTMLButtonElement;
    expect(confirm.disabled).toBe(true);
    fireEvent.click(confirm);
    fireEvent.click(dialog.getByRole("checkbox", { name: "Reports" }));
    // Ticking is still only a choice on the page.
    expect(post).toHaveBeenCalledTimes(1);
    fireEvent.click(dialog.getByRole("button", { name: "Cancel" }));
    expect(post).toHaveBeenCalledTimes(1);
    expect(post.mock.calls.some(([path]) => path === createPath)).toBe(false);
  });

  it("creates rules only for the ticked destinations, then shows the agent's new access", async () => {
    summary = { ...summary, rules: [] };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog"));
    fireEvent.click(await dialog.findByRole("button", { name: "Tick all" }));
    fireEvent.click(dialog.getByRole("checkbox", { name: "Billing database" }));
    summary = { ...summary, rules: [rule({ destination: destination({ name: "Reports" }) })] };
    fireEvent.click(dialog.getByRole("button", { name: "Create 1 rule" }));
    await waitFor(() => expect(post).toHaveBeenCalledWith(createPath, { ...params, body: { keys: ["k2"] } }));
    expect(await screen.findByText("2 rules were created for this agent.")).toBeTruthy();
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(await screen.findByRole("table", { name: "What this agent can reach" })).toBeTruthy();
  });

  it("creates nothing and reads the list again when the owner's access changed meanwhile", async () => {
    post.mockImplementation(async (path: string) => path === previewPath ? preview : { error: { error: { code: "owner_access_preview_stale", message: "stale" } } });
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog"));
    fireEvent.click(await dialog.findByRole("checkbox", { name: "Reports" }));
    fireEvent.click(dialog.getByRole("button", { name: "Create 1 rule" }));
    expect((await dialog.findByRole("alert")).textContent).toBe("The owner's access changed while you were choosing. The list was read again and nothing was created: check it and choose again.");
    await waitFor(() => expect(post.mock.calls.filter(([path]) => path === previewPath)).toHaveLength(2));
    await waitFor(() => expect((dialog.getByRole("checkbox", { name: "Reports" }) as HTMLInputElement).checked).toBe(false));
  });

  it("offers only Close when the owner has nothing to copy", async () => {
    summary = { ...summary, rules: [] };
    preview = { data: { owner_email: "dana@example.test", candidates: [] } };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog", { name: "Create rules from the owner's access" }));
    expect(await dialog.findByText("The owner cannot reach anything right now, so there is nothing to copy.")).toBeTruthy();
    expect(dialog.queryByRole("button", { name: /^Create/ })).toBeNull();
    expect(dialog.queryByRole("button", { name: "Cancel" })).toBeNull();
    // The dialog's own corner control is also named Close; the action is the one in the footer.
    const close = dialog.getAllByRole("button", { name: "Close" });
    fireEvent.click(close[close.length - 1]);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(post.mock.calls.some(([path]) => path === createPath)).toBe(false);
  });

  it("offers only Close when nothing the owner reaches can be given to the agent", async () => {
    summary = { ...summary, rules: [] };
    preview = { data: { owner_email: "dana@example.test", candidates: [candidate({ key: "k3", already_covered: true }), candidate({ key: "k4", destination: destination({ name: "Wiki", kind: "app" }), copyable: false })] } };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog"));
    await dialog.findByRole("list", { name: "The owner's destinations" });
    expect(dialog.getByText("None of these can be added: the agent already has a rule for each, or a rule for an agent cannot name it.")).toBeTruthy();
    expect(dialog.queryByRole("button", { name: /^Create/ })).toBeNull();
    expect(dialog.getAllByRole("button", { name: "Close" }).length).toBeGreaterThan(0);
  });

  it("shows no create button while the owner's access is being read or could not be read", async () => {
    summary = { ...summary, rules: [] };
    preview = { error: { error: { code: "internal", message: "boom" } } };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    const dialog = within(await screen.findByRole("dialog"));
    await dialog.findByRole("alert");
    expect(dialog.queryByRole("button", { name: /^Create/ })).toBeNull();
    expect(dialog.getByRole("button", { name: "Retry" })).toBeTruthy();
  });

  it("explains an owner whose access cannot be looked up", async () => {
    preview = { error: { error: { code: "agent_owner_unattributable", message: "no owner" } } };
    show();
    fireEvent.click(await screen.findByRole("button", { name: "Create rules from the owner's access" }));
    expect((await within(await screen.findByRole("dialog")).findByRole("alert")).textContent).toContain("This agent has no owner whose access can be looked up.");
  });
});

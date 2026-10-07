import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { BeamCliPublisher } from "../src/components/BeamCliPublisher";
import { beamApi, type BeamPolicy } from "../src/lib/beam";
import { beamPublishCommand } from "../src/lib/beam-cli";

vi.mock("../src/lib/beam", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam");
  return { ...actual, beamApi: Object.fromEntries(Object.keys(actual.beamApi).map(key => [key, vi.fn()])) };
});
const org = "11111111-1111-4111-8111-111111111111";
const reviewer = "22222222-2222-4222-8222-222222222222";
const group = "33333333-3333-4333-8333-333333333333";
const audience = { users: [{ id: reviewer, name: "Alice", email: "alice@example.com" }], groups: [{ id: group, name: "Review team" }] };
const policy: BeamPolicy = { version: 1, enabled: true, domain_ready: true, base_domain: "example.net", max_duration_seconds: 3600, max_shares: 5, require_mfa: false, publisher_group_ids: [], reviewer_user_ids: [reviewer], reviewer_group_ids: [group], can_publish: true, can_manage_policy: false, protocol_version: 1, capabilities: ["path_routes_v1"], min_client_version: "0.1.7" };
const copy = vi.fn();
const clipboardDescriptor = Object.getOwnPropertyDescriptor(navigator, "clipboard");
beforeEach(() => { vi.clearAllMocks(); copy.mockResolvedValue(undefined); Object.defineProperty(navigator, "clipboard", { configurable: true, value: { writeText: copy } }); vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: audience }); });
afterEach(() => { cleanup(); if (clipboardDescriptor) Object.defineProperty(navigator, "clipboard", clipboardDescriptor); else Reflect.deleteProperty(navigator, "clipboard"); });
async function open() { render(<BeamCliPublisher orgId={org} policy={policy} />); fireEvent.click(screen.getByRole("button", { name: "Publish using CLI" })); await screen.findByRole("checkbox", { name: /Alice/ }); }
describe("Beam CLI command generation", () => {
  it("generates and copies a command for a specific named user without publishing or granting access", async () => {
    await open();
    expect(beamApi.audience).toHaveBeenCalledWith(org);
    expect(screen.queryByRole("button", { name: "Copy command" })).toBeNull();
    fireEvent.change(screen.getByRole("textbox", { name: "App name" }), { target: { value: "Design review" } });
    fireEvent.change(screen.getByRole("spinbutton", { name: "Local HTTP port" }), { target: { value: "5173" } });
    fireEvent.change(screen.getByRole("spinbutton", { name: "Link lifetime (minutes)" }), { target: { value: "30" } });
    fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ }));
    fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    const command = (screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value;
    expect(command).toMatch(new RegExp(`^tunnex login --server '${window.location.origin}' && \\\\\n`));
    expect(command).toContain(`--org ${org}`); expect(command).toContain("--port 5173"); expect(command).toContain("--name 'Design review'"); expect(command).toContain("--duration 1800s"); expect(command).toContain(`--reviewer-user ${reviewer}`); expect(command).not.toContain("--reviewer-group");
    fireEvent.click(screen.getByRole("button", { name: "Copy command" }));
    await screen.findByRole("status"); expect(copy).toHaveBeenCalledWith(command);
    expect(beamApi.launch).not.toHaveBeenCalled(); expect(beamApi.action).not.toHaveBeenCalled(); expect(beamApi.grants).not.toHaveBeenCalled();
  });
  it("supports named groups alongside users and clears a generated command after an audience edit", async () => {
    await open(); fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); fireEvent.click(screen.getByRole("checkbox", { name: /Review team/ })); fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    const command = (screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value;
    expect(command).toContain(`--reviewer-user ${reviewer}`); expect(command).toContain(`--reviewer-group ${group}`);
    fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); expect(screen.queryByRole("button", { name: "Copy command" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Generate command" })); expect((screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value).not.toContain("--reviewer-user");
  });
  it("lets an already signed-in publisher omit login and clears the previously generated block", async () => {
    await open(); expect((screen.getByRole("checkbox", { name: "Include login command" }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Include login command" })); expect(screen.queryByRole("button", { name: "Copy command" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Generate command" })); const command = (screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value;
    expect(command.startsWith("tunnex beam publish")).toBe(true); expect(command).not.toContain("tunnex login");
    fireEvent.click(screen.getByRole("button", { name: "Copy command" })); await waitFor(() => expect(copy).toHaveBeenCalledWith(command));
  });
  it("does not invent reviewer choices when the scoped audience fails to load", async () => {
    vi.mocked(beamApi.audience).mockResolvedValue({ ok: false, error: "Audience unavailable" });
    render(<BeamCliPublisher orgId={org} policy={policy} />); fireEvent.click(screen.getByRole("button", { name: "Publish using CLI" })); await screen.findByText("Audience unavailable"); expect(screen.queryByRole("checkbox")).toBeNull(); expect(screen.queryByRole("button", { name: "Generate command" })).toBeNull();
    vi.mocked(beamApi.audience).mockResolvedValue({ ok: true, data: audience }); fireEvent.click(screen.getByRole("button", { name: "Retry reviewer choices" })); await screen.findByRole("checkbox", { name: /Alice/ });
  });
  it("keeps a manually selectable command when clipboard permission is refused", async () => {
    copy.mockRejectedValue(new Error("Clipboard refused")); await open(); fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); fireEvent.click(screen.getByRole("button", { name: "Generate command" })); fireEvent.click(screen.getByRole("button", { name: "Copy command" })); await screen.findByText("Could not copy. Select and copy the command below."); expect((screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).readOnly).toBe(true);
  });
  it("withdraws command generation when publishing permission is lost", async () => {
    const rendered = render(<BeamCliPublisher orgId={org} policy={policy} />); fireEvent.click(screen.getByRole("button", { name: "Publish using CLI" })); await screen.findByRole("checkbox", { name: /Alice/ }); fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ })); fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    rendered.rerender(<BeamCliPublisher orgId={org} policy={{ ...policy, can_publish: false }} />); await waitFor(() => expect(screen.queryByRole("button", { name: "Copy command" })).toBeNull()); expect(copy).not.toHaveBeenCalled();
  });
  it("reuses a saved project and selects only currently permitted reviewers", async () => {
    const project = { id: "55555555-5555-4555-8555-555555555555", name: "Checkout", target: { protocol: "http", address: "127.0.0.1", port: 5173, routes: [{ path_prefix: "/api", target: { protocol: "http", address: "127.0.0.1", port: 8080 } }] }, duration_seconds: 1800, grants: [{ subject_kind: "user" as const, subject_id: reviewer }, { subject_kind: "user" as const, subject_id: "44444444-4444-4444-8444-444444444444" }] };
    render(<BeamCliPublisher orgId={org} policy={policy} project={project} label="Publish Checkout" />);
    fireEvent.click(screen.getByRole("button", { name: "Publish Checkout" }));
    await screen.findByText(/Some saved reviewers are no longer permitted/);
    expect((screen.getByRole("checkbox", { name: /Alice/ }) as HTMLInputElement).checked).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    const command = (screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value;
    expect(command).toContain(`--project ${project.id}`);
    expect(command).toContain("--port 5173"); expect(command).toContain("--route '/api=8080'");
    expect(command).not.toContain("44444444-4444-4444-8444-444444444444");
  });
  it("generates multiple API routes and clears a command when a port shortcut changes", async () => {
    await open(); fireEvent.click(screen.getByRole("checkbox", { name: /Alice/ }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Include a local API" }));
    fireEvent.click(screen.getByRole("button", { name: "Add API route" }));
    fireEvent.change(screen.getByRole("textbox", { name: "API path 2" }), { target: { value: "/auth" } });
    fireEvent.change(screen.getByRole("spinbutton", { name: "API port 2" }), { target: { value: "9000" } });
    fireEvent.click(screen.getByRole("button", { name: "Generate command" }));
    const command = (screen.getByRole("textbox", { name: "Publish command" }) as HTMLTextAreaElement).value;
    expect(command).toContain("--route '/api=8080'"); expect(command).toContain("--route '/auth=9000'");
    fireEvent.click(screen.getByRole("button", { name: "Vite · 5173" }));
    expect(screen.queryByRole("button", { name: "Copy command" })).toBeNull();
  });
});
describe("Beam shell command boundaries", () => {
  const input = { serverOrigin: "https://tunnex.app", orgId: org, name: "Local demo", port: 3000, lifetimeMinutes: 30, maxDurationSeconds: 3600, audience, grants: [{ subject_kind: "user" as const, subject_id: reviewer }] };
  it("uses the control-plane origin for login before publishing", () => { expect(beamPublishCommand(input).split("\n").slice(0, 2)).toEqual(["tunnex login --server 'https://tunnex.app' && \\", "tunnex beam publish \\"]); });
  it("retains the local development control-plane port", () => { expect(beamPublishCommand({ ...input, serverOrigin: "http://127.0.0.1:15173" })).toContain("tunnex login --server 'http://127.0.0.1:15173' &&"); });
  it("generates publish only when reusing the current CLI login", () => { const command = beamPublishCommand({ ...input, includeLogin: false }); expect(command.startsWith("tunnex beam publish")).toBe(true); expect(command).not.toContain("tunnex login"); });
  it.each(["https://example.com/path", "https://user:password@example.com", "file:///tmp/cp"])("refuses a non-origin control-plane address %s", serverOrigin => { expect(() => beamPublishCommand({ ...input, serverOrigin })).toThrow(); });
  it("quotes shell substitutions and apostrophes as app-name data", () => { const command = beamPublishCommand({ ...input, name: "Alice's $(echo injected); demo" }); expect(command).toContain("--name 'Alice'\"'\"'s $(echo injected); demo'"); });
  it.each([[[{ path_prefix: "/api;echo", port: 8080 }]], [[{ path_prefix: "/api", port: 0 }]], [[{ path_prefix: "/api", port: 8080 }, { path_prefix: "/api", port: 9000 }]], [[{ path_prefix: "/../private", port: 8080 }]]])("refuses unsafe or ambiguous API routes %o", routes => {
    expect(() => beamPublishCommand({ ...input, routes })).toThrow();
  });
  it.each([{ port: 0 }, { port: 65536 }, { lifetimeMinutes: 61 }, { name: "App\ncommand" }, { grants: [] }, { grants: [{ subject_kind: "user" as const, subject_id: "44444444-4444-4444-8444-444444444444" }] }])("refuses invalid or out-of-policy input %o", patch => { expect(() => beamPublishCommand({ ...input, ...patch })).toThrow(); });
});

import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
const mock = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: mock }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "actor-a", email_verified: true } } }) }));
vi.mock("../src/lib/sandboxProduct", () => ({ SANDBOX_PRODUCT_SHELVED: false }));
vi.mock("../src/lib/deploymentMeta", () => ({ useSandboxModuleState: () => "enabled" }));
import { WorkspaceFeatureControl } from "../src/components/WorkspaceFeatureControl";
const setup = { settings: { enabled: false, max_per_user: 2, max_total: 20 }, policy_mode: "enforcing", creation_status: { can_admin: true, runtime_ready: true, blocked_reasons: ["organization_disabled"] }, catalog: [{ enabled: true, runtime_compatible: true }] };
function view() { return <MemoryRouter><WorkspaceFeatureControl feature="sandboxes" orgId="org-a" roles={["admin"]} canEdit serverAdmin={false} /></MemoryRouter>; }
beforeEach(() => { vi.resetAllMocks(); mock.GET.mockResolvedValue({ data: setup }); mock.PUT.mockResolvedValue({ data: {} }); });
afterEach(cleanup);

describe("sandbox activation when the product and module are available", () => {
  it("uses the exact saved limits as a compare-and-swap and waits for readback", async () => {
    let finish!: (value: unknown) => void;
    mock.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    render(view()); const toggle = await screen.findByRole("switch", { name: "Sandboxes" });
    fireEvent.click(toggle); fireEvent.click(toggle);
    expect(mock.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/sandbox-setup", { params: { path: { orgId: "org-a" } }, body: { expected: setup.settings, settings: { ...setup.settings, enabled: true } } });
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    mock.GET.mockResolvedValue({ data: { ...setup, settings: { ...setup.settings, enabled: true } } });
    await act(async () => finish({ data: {} }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Sandboxes" }).getAttribute("aria-checked")).toBe("true"));
  });

  it.each([
    { policy_mode: "off" },
    { creation_status: { ...setup.creation_status, runtime_ready: false } },
    { catalog: [{ enabled: false, runtime_compatible: true }] },
    { catalog: [{ enabled: true, runtime_compatible: false }] },
    { creation_status: { ...setup.creation_status, blocked_reasons: ["historical_reservation_invalid"] } },
  ])("refuses enablement without the saved prerequisite (%j)", async patch => {
    mock.GET.mockResolvedValue({ data: { ...setup, ...patch } }); render(view());
    const toggle = await screen.findByRole("switch", { name: "Sandboxes" });
    expect(toggle).toHaveProperty("disabled", true); fireEvent.click(toggle); expect(mock.PUT).not.toHaveBeenCalled();
  });

  it.each([undefined, false])("does not invent an enrollment requirement for qualified legacy runtimes (%s)", async required => {
    mock.GET.mockResolvedValue({ data: { ...setup, creation_status: { ...setup.creation_status, runner_enrollment_required: required } } });
    render(view()); const toggle = await screen.findByRole("switch", { name: "Sandboxes" }); expect(toggle).toHaveProperty("disabled", false);
    expect(mock.GET.mock.calls.some(([path]) => path.endsWith("/sandbox-runner-enrollments"))).toBe(false);
  });

  it.each(["unavailable", "offline"])("requires a fresh Ready enrollment when the deployment requires one (%s)", async state => {
    mock.GET.mockImplementation(async (path: string) => path.endsWith("/sandbox-runner-enrollments") ? state === "unavailable" ? { error: {} } : { data: { enrollments: [{ state }] } } : { data: { ...setup, creation_status: { ...setup.creation_status, runner_enrollment_required: true } } });
    render(view()); const toggle = await screen.findByRole("switch", { name: "Sandboxes" });
    expect(toggle).toHaveProperty("disabled", true); fireEvent.click(toggle); expect(mock.PUT).not.toHaveBeenCalled();
  });

  it("allows withdrawal despite lost activation prerequisites while retaining limits", async () => {
    const enabled = { ...setup, settings: { ...setup.settings, enabled: true }, policy_mode: "off", creation_status: { ...setup.creation_status, runtime_ready: false } };
    mock.GET.mockResolvedValue({ data: enabled }); render(view());
    fireEvent.click(await screen.findByRole("switch", { name: "Sandboxes" }));
    await waitFor(() => expect(mock.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sandbox-setup", { params: { path: { orgId: "org-a" } }, body: { expected: enabled.settings, settings: { ...enabled.settings, enabled: false } } }));
  });
});

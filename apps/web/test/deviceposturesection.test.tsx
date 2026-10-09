import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MemoryRouter } from "react-router-dom";
import type { HealthCheck } from "../src/lib/api";

const state = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), DELETE: vi.fn(), checks: [] as HealthCheck[] }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api"), api: state }));
import { PostureChecksSection } from "../src/components/DevicePostureSection";
import { POSTURE_HONESTY_LINE } from "../src/lib/postureview";

type Request = { params: { path: { orgId: string; checkKind: HealthCheck["kind"] } }; body?: { mode: HealthCheck["mode"]; param?: HealthCheck["param"] } };
const osCheck = (minimum = "14.0"): HealthCheck => ({ kind: "os_version", mode: "warn", param: { min: { macos: minimum } } as unknown as HealthCheck["param"] });
const workspace = (orgId = "org-a", canManage = true) => <MemoryRouter><PostureChecksSection orgId={orgId} canManage={canManage} /></MemoryRouter>;
beforeEach(() => {
  vi.resetAllMocks();
  state.checks = [{ kind: "disk_encryption", mode: "warn" }, osCheck()];
  state.GET.mockImplementation(async () => ({ data: state.checks }));
  state.PUT.mockImplementation(async (_path: string, request: Request) => {
    const check = { kind: request.params.path.checkKind, ...request.body! };
    state.checks = [...state.checks.filter(value => value.kind !== check.kind), check];
    return { data: { ...check, would_fail_count: 2 } };
  });
  state.DELETE.mockImplementation(async (_path: string, request: Request) => {
    state.checks = state.checks.filter(value => value.kind !== request.params.path.checkKind);
    return { data: {} };
  });
});
afterEach(cleanup);
const savedRow = (table: HTMLElement, name: string) => within(table).getByText(name).closest("tr")!;
async function edit(name: string) {
  fireEvent.click(await screen.findByRole("button", { name }));
  return screen.getByRole("dialog", { name });
}

describe("Saved device posture policy", () => {
  it("keeps local mode edits separate from the saved policy and cancel performs no write", async () => {
    render(workspace());
    const table = await screen.findByRole("table", { name: "Posture checks" });
    const row = savedRow(table, "Disk encryption");
    expect(within(row).getByText("Warn")).toBeTruthy();
    const dialog = await edit("Disk encryption");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Mode" }), { target: { value: "require" } });
    expect(state.PUT).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
    expect(within(row).getByText("Warn")).toBeTruthy();
    fireEvent.click(within(dialog).getByRole("button", { name: "Cancel" }));
    expect(within(savedRow(table, "Disk encryption")).getByText("Warn")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Disk encryption" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Edit check" }));
    expect(screen.getByRole("combobox", { name: "Mode" })).toHaveProperty("value", "warn");
    expect(state.PUT).not.toHaveBeenCalled();
  });

  it("saves the exact OS floors without silently constraining an unset platform and reports real next-report impact", async () => {
    render(workspace()); const dialog = await edit("Minimum OS version");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Mode" }), { target: { value: "require" } });
    fireEvent.change(within(dialog).getByRole("textbox", { name: "macOS minimum" }), { target: { value: "15.0" } });
    expect(within(dialog).getByRole("list", { name: "Draft platform coverage" }).textContent).toContain("Windows: not constrained by this check");
    expect(state.PUT).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save check" }));
    await waitFor(() => expect(state.PUT).toHaveBeenCalledTimes(1));
    expect(state.PUT).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/health-checks/{checkKind}", { params: { path: { orgId: "org-a", checkKind: "os_version" } }, body: { mode: "require", param: { min: { macos: "15.0" } } } });
    await screen.findByText("Minimum OS version saved.");
    expect(screen.getByRole("table", { name: "Posture checks" }).textContent).toContain("macOS: 15.0 or newer required");
    expect(screen.getByRole("table", { name: "Posture checks" }).textContent).toContain("Windows: not constrained by this check");
    expect(screen.getByText(/2.*next.*report/).textContent).toContain("block");
    expect(screen.getByText(POSTURE_HONESTY_LINE)).toBeTruthy();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it("refuses an enabled OS check with no minimum and persists Off only through the explicit save", async () => {
    render(workspace()); const dialog = await edit("Minimum OS version");
    fireEvent.change(within(dialog).getByRole("textbox", { name: "macOS minimum" }), { target: { value: "" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save check" }));
    expect(within(dialog).getByText("Set a minimum version for at least one platform, or turn the check off.")).toBeTruthy();
    expect(state.PUT).not.toHaveBeenCalled();
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Mode" }), { target: { value: "off" } });
    expect(state.DELETE).not.toHaveBeenCalled();
    fireEvent.click(within(dialog).getByRole("button", { name: "Save check" }));
    await waitFor(() => expect(state.DELETE).toHaveBeenCalledTimes(1));
    expect(state.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/health-checks/{checkKind}", { params: { path: { orgId: "org-a", checkKind: "os_version" } } });
    await screen.findByText("Minimum OS version saved.");
    expect(within(savedRow(screen.getByRole("table"), "Minimum OS version")).getByText("Off")).toBeTruthy();
  });

  it("retains a refused draft in its editor without presenting it as the saved state", async () => {
    state.PUT.mockResolvedValueOnce({ error: { error: { message: "This policy change was refused" } } });
    render(workspace()); const table = await screen.findByRole("table"); const dialog = await edit("Disk encryption");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Mode" }), { target: { value: "require" } });
    fireEvent.click(within(dialog).getByRole("button", { name: "Save check" }));
    await within(dialog).findByText("This policy change was refused");
    expect(within(dialog).getByRole("combobox", { name: "Mode" })).toHaveProperty("value", "require");
    expect(within(savedRow(table, "Disk encryption")).getByText("Warn")).toBeTruthy();
    expect(screen.queryByText("Disk encryption saved.")).toBeNull();
  });

  it.each(["failed", "malformed"])("keeps %s inventory unavailable instead of claiming all checks are off", async (failure) => {
    state.GET.mockResolvedValueOnce(failure === "failed" ? { error: { error: { message: "Policy read unavailable" } } } : { data: [{ kind: "disk_encryption", mode: "invalid" }] });
    render(workspace()); await screen.findByRole("alert");
    expect(screen.queryByRole("table", { name: "Posture checks" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Disk encryption" })).toBeNull();
    expect(screen.queryByText("Off")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Retry" }));
    await screen.findByRole("table", { name: "Posture checks" });
    expect(state.PUT).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });

  it("withdraws a pending save on org change and ignores its late success without reading the old policy again", async () => {
    let complete!: (value: unknown) => void;
    state.PUT.mockImplementationOnce(() => new Promise(resolve => { complete = resolve; }));
    const view = render(workspace()); const dialog = await edit("Disk encryption");
    fireEvent.change(within(dialog).getByRole("combobox", { name: "Mode" }), { target: { value: "require" } });
    const apply = within(dialog).getByRole("button", { name: "Save check" });
    fireEvent.click(apply); fireEvent.click(apply);
    expect(state.PUT).toHaveBeenCalledTimes(1);
    expect(within(dialog).getByRole("combobox", { name: "Mode" })).toHaveProperty("disabled", true);
    state.checks = [];
    view.rerender(workspace("org-b"));
    expect(screen.queryByRole("dialog")).toBeNull();
    const current = await screen.findByRole("table", { name: "Posture checks" });
    await act(async () => complete({ data: { kind: "disk_encryption", mode: "require", would_fail_count: 2 } }));
    expect(within(savedRow(current, "Disk encryption")).getByText("Off")).toBeTruthy();
    expect(screen.queryByText("Disk encryption saved.")).toBeNull();
    expect(state.GET.mock.calls.filter(([, request]) => request.params.path.orgId === "org-a")).toHaveLength(1);
    expect(state.PUT).toHaveBeenCalledTimes(1);
  });

  it("removes the editor and its mutations immediately when management permission is withdrawn", async () => {
    const view = render(workspace()); await edit("Disk encryption");
    view.rerender(workspace("org-a", false));
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByRole("table", { name: "Posture checks" });
    expect(screen.queryByRole("button", { name: "Disk encryption" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Actions for Disk encryption" })).toBeNull();
    expect(state.PUT).not.toHaveBeenCalled();
    expect(state.DELETE).not.toHaveBeenCalled();
  });
});

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const pending = [
  { id: "device-a", user_id: "00000000-0000-0000-0000-000000000001", owner_email: "phone.owner@example.test", name: "Phone A", assigned_ip: "10.99.0.10", status: "pending", created_at: "2026-08-23T10:00:00Z" },
  { id: "device-b", user_id: "00000000-0000-0000-0000-000000000002", owner_email: "laptop.owner@example.test", name: "Laptop B", assigned_ip: null, status: "pending", created_at: "2026-08-23T10:01:00Z" },
];
let failures = new Set<string>();
let requests = pending;

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => ({ data: path.endsWith("device-approval") ? { mode: "on" } : requests })),
      POST: vi.fn(async (_path: string, request: { params: { path: { deviceId: string } } }) => failures.has(request.params.path.deviceId) ? { error: { code: "conflict", message: "already decided" } } : { data: {} }),
    },
  };
});

import { api } from "../src/lib/api";
import { DeviceApprovalSection } from "../src/components/DeviceApprovalSection";

afterEach(() => { failures = new Set(); vi.clearAllMocks(); cleanup(); });
beforeEach(() => { requests = pending; });

function renderSection(canManage = true) {
  return render(<MemoryRouter><DeviceApprovalSection orgId="org-a" canManage={canManage} /></MemoryRouter>);
}
async function selectPending() {
  for (const device of pending) fireEvent.click(await screen.findByRole("checkbox", { name: `Select ${device.name}` }));
}

describe("DeviceApprovalSection confirmation", () => {
  it("cancels without a mutation and names every pending target", async () => {
    renderSection();
    await selectPending();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect((await screen.findByRole("dialog")).textContent).toContain("Phone A");
    expect(screen.getByRole("dialog").textContent).toContain("Laptop B");
    expect(screen.getByRole("dialog").textContent).toContain("phone.owner@example.test");
    expect(screen.getByRole("dialog").textContent).not.toContain("00000000-0000-0000-0000-000000000001");
    fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
    expect(vi.mocked(api.POST)).not.toHaveBeenCalled();
  });

  it("mutates only confirmed targets and reports partial failure with recovery", async () => {
    failures = new Set(["device-b"]);
    renderSection();
    await selectPending();
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(screen.getByRole("dialog").textContent).toContain("new enrollment request");
    fireEvent.click(screen.getByRole("button", { name: "Reject device" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.POST)).toHaveBeenCalledWith(expect.stringContaining("reject"), expect.objectContaining({ params: { path: { orgId: "org-a", deviceId: "device-a" } } }));
    expect((await screen.findByText(/1 of 2 devices rejected/)).textContent).toContain("Laptop B");
  });

  it("does not render approval mutations for a restricted viewer", async () => {
    renderSection(false);
    await screen.findByRole("table", { name: "Pending devices" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Actions for Phone A" }));
    expect(screen.getByRole("menuitem", { name: "Review device" })).toBeTruthy();
    expect(screen.queryByRole("menuitem", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("menuitem", { name: "Reject" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Approve" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Reject" })).toBeNull();
  });

  it("retains off-page pending targets and confirms exactly the selected IDs", async () => {
    requests = Array.from({ length: 45 }, (_, index) => ({ ...pending[0], id: `device-${index + 1}`, name: `Pending ${index + 1}`, created_at: new Date(Date.UTC(2026, 7, 23, 10, index)).toISOString() }));
    renderSection();
    fireEvent.click(await screen.findByRole("checkbox", { name: "Select Pending 1" }));
    fireEvent.click(screen.getByRole("button", { name: "Next page" }));
    fireEvent.click(screen.getByRole("checkbox", { name: "Select Pending 21" }));
    fireEvent.change(screen.getByRole("textbox", { name: "Search approval requests" }), { target: { value: "Pending 45" } });
    expect(screen.getByRole("button", { name: "Pending 45" })).toBeTruthy();
    expect(screen.queryByRole("navigation", { name: "Table pagination" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    const confirm = screen.getByRole("dialog", { name: "Approve pending devices?" });
    expect(confirm.textContent).toContain("Pending 1");
    expect(confirm.textContent).toContain("Pending 21");
    expect(confirm.textContent).not.toContain("Pending 45");
    fireEvent.click(within(confirm).getByRole("button", { name: "Approve device" }));
    await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
    expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}/approve", { params: { path: { orgId: "org-a", deviceId: "device-1" } } });
    expect(api.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/devices/{deviceId}/approve", { params: { path: { orgId: "org-a", deviceId: "device-21" } } });
  });

  it("withdraws a staged decision when management permission is removed", async () => {
    const view = renderSection();
    await selectPending();
    fireEvent.click(screen.getByRole("button", { name: "Approve" }));
    expect(screen.getByRole("dialog")).toBeTruthy();
    view.rerender(<MemoryRouter><DeviceApprovalSection orgId="org-a" canManage={false} /></MemoryRouter>);
    expect(screen.queryByRole("dialog")).toBeNull();
    await screen.findByRole("table", { name: "Pending devices" });
    expect(screen.queryByRole("checkbox")).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });

  it("locks repeated confirmation and reports a transport-uncertain decision individually", async () => {
    let reject!: (reason: Error) => void;
    vi.mocked(api.POST).mockImplementationOnce(() => new Promise((_resolve, fail) => { reject = fail; }) as ReturnType<typeof api.POST>);
    renderSection();
    fireEvent.click(await screen.findByRole("button", { name: "Actions for Phone A" }));
    fireEvent.click(screen.getByRole("menuitem", { name: "Approve" }));
    const apply = screen.getByRole("button", { name: "Approve device" });
    fireEvent.click(apply); fireEvent.click(apply);
    expect(api.POST).toHaveBeenCalledTimes(1);
    expect(screen.getByRole("button", { name: "Applying…" })).toHaveProperty("disabled", true);
    await act(async () => reject(new Error("connection lost")));
    const result = await screen.findByText(/0 of 1 devices confirmed approved/);
    expect(result.textContent).toContain("Phone A");
    expect(result.textContent).toContain("Reload request state before retrying");
    expect(api.POST).toHaveBeenCalledTimes(1);
  });

  it("does not turn malformed pending data into an empty approval queue", async () => {
    vi.mocked(api.GET).mockImplementationOnce(async () => ({ data: { mode: "on" } }) as Awaited<ReturnType<typeof api.GET>>);
    vi.mocked(api.GET).mockImplementationOnce(async () => ({ data: { items: [] } }) as unknown as Awaited<ReturnType<typeof api.GET>>);
    renderSection();
    await screen.findByRole("alert");
    expect(screen.queryByText("No approvals waiting")).toBeNull();
    expect(screen.queryByRole("table", { name: "Pending devices" })).toBeNull();
    expect(api.POST).not.toHaveBeenCalled();
  });
});

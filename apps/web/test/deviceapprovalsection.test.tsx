import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

const pending = [
  { id: "device-a", user_id: "00000000-0000-0000-0000-000000000001", owner_email: "phone.owner@example.test", name: "Phone A", assigned_ip: "10.99.0.10", created_at: "2026-08-23T10:00:00Z" },
  { id: "device-b", user_id: "00000000-0000-0000-0000-000000000002", owner_email: "laptop.owner@example.test", name: "Laptop B", assigned_ip: null, created_at: "2026-08-23T10:01:00Z" },
];
let failures = new Set<string>();

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    loadOne: async (call: () => Promise<{ data?: unknown; error?: unknown }>) => {
      const result = await call();
      return result.error ? { ok: false as const, error: String(result.error) } : { ok: true as const, data: result.data };
    },
    api: {
      GET: vi.fn(async (path: string) => ({ data: path.endsWith("device-approval") ? { mode: "on" } : pending })),
      POST: vi.fn(async (_path: string, request: { params: { path: { deviceId: string } } }) => failures.has(request.params.path.deviceId) ? { error: { code: "conflict", message: "already decided" } } : { data: {} }),
    },
  };
});

vi.mock("../src/components/ui", async () => {
  const actual = await vi.importActual<typeof import("../src/components/ui")>("../src/components/ui");
  return {
    ...actual,
    DataTable: ({ rows, rowActions }: { rows: typeof pending; rowActions?: Array<{ label: string; run: (rows: typeof pending) => void }> }) => <div>{rowActions?.map((action) => <button key={action.label} onClick={() => action.run(rows)}>{action.label}</button>)}</div>,
  };
});

import { api } from "../src/lib/api";
import { DeviceApprovalSection } from "../src/components/DeviceApprovalSection";

afterEach(() => { failures = new Set(); vi.clearAllMocks(); cleanup(); });

function renderSection(canManage = true) {
  return render(<MemoryRouter><DeviceApprovalSection orgId="org-a" canManage={canManage} /></MemoryRouter>);
}

describe("DeviceApprovalSection confirmation", () => {
  it("cancels without a mutation and names every pending target", async () => {
    renderSection();
    await screen.findByRole("button", { name: "Approve" });
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
    await screen.findByRole("button", { name: "Reject" });
    fireEvent.click(screen.getByRole("button", { name: "Reject" }));
    expect(screen.getByRole("dialog").textContent).toContain("new enrollment request");
    fireEvent.click(screen.getByRole("button", { name: "Reject device" }));
    await waitFor(() => expect(vi.mocked(api.POST)).toHaveBeenCalledTimes(2));
    expect(vi.mocked(api.POST)).toHaveBeenCalledWith(expect.stringContaining("reject"), expect.objectContaining({ params: { path: { orgId: "org-a", deviceId: "device-a" } } }));
    expect((await screen.findByText(/1 of 2 devices rejected/)).textContent).toContain("Laptop B");
  });

  it("does not render approval mutations for a restricted viewer", async () => {
    renderSection(false);
    await waitFor(() => expect(screen.queryByRole("button", { name: "Approve" })).toBeNull());
    expect(screen.queryByRole("button", { name: "Reject" })).toBeNull();
  });
});

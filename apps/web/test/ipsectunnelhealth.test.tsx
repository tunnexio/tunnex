import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
const mock = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: { GET: mock.get } }));
import { IPsecTunnelHealth } from "../src/components/IPsecTunnelHealth";
const tunnels = [1, 2].map(i => ({ outside_address: `198.51.100.${i}`, inside_cidr: `169.254.${i}.0/30`, customer_inside_address: `169.254.${i}.1`, cloud_inside_address: `169.254.${i}.2`, psk: "" }));
const report = () => ({ observed_at: new Date().toISOString(), tunnels: [{ id: "tunnel-a", slot: 1, status: "up", selected: true }, { id: "tunnel-b", slot: 2, status: "down", selected: false }] });
const view = () => <IPsecTunnelHealth orgId="org-a" connectionId="connection-a" tunnels={tunnels} />;
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mock.get.mockResolvedValue({ data: report() }); });
it("shows independent tunnel health and keeps configured path separate from Up", async () => {
 render(view());
 expect(await screen.findByRole("status", { name: "Tunnel 1 Up" })).toBeTruthy();
 expect(screen.getByRole("status", { name: "Tunnel 2 Down" })).toBeTruthy();
 expect(screen.getByText("Selected path")).toBeTruthy();
 expect(screen.getByText("198.51.100.2")).toBeTruthy();
 expect(screen.queryByRole("button", { name: /make.*up|enable tunnel/i })).toBeNull();
});
it("never turns an absent or stale report into Up", async () => {
 mock.get.mockResolvedValue({ data: { ...report(), observed_at: new Date(Date.now() - 91_000).toISOString() } });
 render(view());
 await waitFor(() => expect(mock.get).toHaveBeenCalled());
 expect(screen.getByRole("status", { name: "Tunnel 1 Unknown" })).toBeTruthy();
 expect(screen.getByRole("status", { name: "Tunnel 2 Unknown" })).toBeTruthy();
 expect(screen.queryByRole("status", { name: / Up$/ })).toBeNull();
});
it("clears previous Up when a refresh cannot verify the report", async () => {
 render(view()); await screen.findByRole("status", { name: "Tunnel 1 Up" });
 mock.get.mockRejectedValue(new Error("offline"));
 fireEvent.click(screen.getByRole("button", { name: "Refresh tunnel status" }));
 await screen.findByRole("status", { name: "Tunnel 1 Unknown" });
 expect(screen.getByText("Status unavailable")).toBeTruthy();
});
it("rejects duplicate slots instead of attaching health to the wrong tunnel", async () => {
 const data = report(); data.tunnels[1].slot = 1; mock.get.mockResolvedValue({ data });
 render(view()); await waitFor(() => expect(mock.get).toHaveBeenCalled());
 expect(screen.queryByRole("status", { name: / Up$/ })).toBeNull();
});
it("ignores an old connection response after the selected connection changes", async () => {
 let resolve!: (value: unknown) => void;
 mock.get.mockImplementationOnce(() => new Promise(r => { resolve = r; })).mockResolvedValue({ data: { ...report(), tunnels: report().tunnels.map(v => ({ ...v, status: "down" })) } });
 const result = render(view());
 result.rerender(<IPsecTunnelHealth orgId="org-b" connectionId="connection-b" tunnels={tunnels} />);
 await screen.findByRole("status", { name: "Tunnel 1 Down" });
 resolve({ data: report() });
 await waitFor(() => expect(screen.getByRole("status", { name: "Tunnel 1 Down" })).toBeTruthy());
 expect(screen.queryByRole("status", { name: / Up$/ })).toBeNull();
});
it.each([null, { id: "tunnel-a", slot: 1, status: "__proto__", selected: true }])("refuses malformed successful reports without rendering invalid status: %j", async value => {
 mock.get.mockResolvedValue({ data: { ...report(), tunnels: [value, report().tunnels[1]] } });
 render(view());
 await screen.findByText("Status unavailable");
 expect(screen.getByRole("status", { name: "Tunnel 1 Unknown" })).toBeTruthy();
});

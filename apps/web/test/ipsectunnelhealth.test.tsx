import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), patch: vi.fn(), delete: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put, PATCH: mock.patch, DELETE: mock.delete } }));
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
 expect(screen.getByText("Preferred path")).toBeTruthy();
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

it("offers distinct collapsed read-only troubleshooting for each fresh tunnel status", async () => {
 render(view());
 await screen.findByRole("status", { name: "Tunnel 1 Up" });
 const upSummary = screen.getByLabelText("Tunnel 1 troubleshooting");
 const downSummary = screen.getByLabelText("Tunnel 2 troubleshooting");
 const up = upSummary.closest("details")!;
 const down = downSummary.closest("details")!;
 expect(up.open).toBe(false);
 expect(down.open).toBe(false);
 expect(within(up).getByText("Encrypted tunnel established. Application access needs separate checks.")).toBeTruthy();
 expect(within(up).getByText("Check access policies and return routes.")).toBeTruthy();
 expect(within(down).getByText("Check the remote VPN endpoint and IKE reachability (UDP 500/4500).")).toBeTruthy();
 expect(within(down).getByText("Confirm matching PSK and IKE/IPsec proposals on both ends.")).toBeTruthy();
 fireEvent.click(upSummary);
 fireEvent.click(downSummary);
 expect(mock.get).toHaveBeenCalledTimes(1);
 for (const write of [mock.post, mock.put, mock.patch, mock.delete]) expect(write).not.toHaveBeenCalled();
 expect(within(up).queryByRole("button")).toBeNull();
 expect(within(down).queryByRole("button")).toBeNull();
});
it.each(["stale", "unknown", "invalid"])("shows only Unknown troubleshooting for %s reports", async kind => {
 const data = report();
 if (kind === "stale") data.observed_at = new Date(Date.now() - 91_000).toISOString();
 if (kind === "unknown") data.tunnels.forEach(t => { t.status = "unknown"; });
 if (kind === "invalid") data.tunnels[1].slot = 1;
 mock.get.mockResolvedValue({ data });
 render(view());
 await screen.findByText(kind === "invalid" ? "Status unavailable" : kind === "unknown" ? "Live gateway report · updates every 10s" : "Waiting for a fresh gateway report");
 for (const slot of [1, 2]) {
  const details = screen.getByLabelText(`Tunnel ${slot} troubleshooting`).closest("details")!;
  expect(details.open).toBe(false);
  expect(within(details).getByText("Refresh status and check gateway connectivity to the control plane.")).toBeTruthy();
  expect(within(details).getByText("No fresh tunnel evidence yet.")).toBeTruthy();
  expect(within(details).queryByText(/PSK|established|return routes/)).toBeNull();
 }
});

it("shows observed Active path separately from configured Preferred path", async () => {
 const data=report(); data.tunnels[1].status="up";
 mock.get.mockResolvedValue({data:{...data,recovery_version:1,selection_sequence:7,active_slot:2}});
 render(view());await screen.findByText("Active path");
 expect(screen.getByText("Preferred path")).toBeTruthy();
 const active=screen.getByText("Active path").parentElement!;
 expect(within(active).getByRole("heading",{name:"Tunnel 2"})).toBeTruthy();
});
it.each([
 {recovery_version:1,selection_sequence:3,active_slot:null},
 {recovery_version:1,selection_sequence:3,active_slot:2,stale:true},
 {active_slot:2},
 {recovery_version:9,selection_sequence:3,active_slot:2},
 {recovery_version:1,selection_sequence:0,active_slot:2},
 {recovery_version:1,selection_sequence:3,active_slot:2},
])("never invents active forwarding from missing or invalid selection evidence %j",async extra=>{
 const data=report();
 if('stale' in extra)data.observed_at=new Date(Date.now()-91_000).toISOString();
 mock.get.mockResolvedValue({data:{...data,...extra}});
 render(view());await waitFor(()=>expect(mock.get).toHaveBeenCalled());
 expect(screen.queryByText("Active path")).toBeNull();
});

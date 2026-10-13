import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
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
 const active=screen.getByText("Active path").closest("tr")!;
 expect(within(active).getByRole("rowheader",{name:"Tunnel 2"})).toBeTruthy();
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

const approvedRemotePrefixes = ["10.20.0.0/24", "10.21.0.0/24"];
const bgpReport = () => ({
 ...report(),
 tunnels: report().tunnels.map(t => ({ ...t, selected: false, status: "up" })),
 bgp: { version: 1, sequence: 7,
  peers: [{ slot: 1, state: "established", accepted_prefixes: 2, installed_prefixes: 1 }, { slot: 2, state: "established", accepted_prefixes: 2, installed_prefixes: 1, rejected_prefixes: 4 }],
  routes: [{ prefix: approvedRemotePrefixes[0], slot: 1 }, { prefix: approvedRemotePrefixes[1], slot: 2 }],
 },
});
const bgpView = () => <IPsecTunnelHealth orgId="org-a" connectionId="connection-a" tunnels={tunnels} mode="ipv4-bgp" approvedRemotePrefixes={approvedRemotePrefixes} />;
it("reports BGP peers and installed routes per prefix without a global path preference", async () => {
 mock.get.mockResolvedValue({ data: bgpReport() });
 render(bgpView());
 await screen.findByRole("status", { name: "Tunnel 1 BGP Established" });
 expect(screen.getByRole("status", { name: "Tunnel 2 BGP Established" })).toBeTruthy();
 const rows = within(screen.getByRole("table", { name: "IPsec tunnel state" })).getAllByRole("row").slice(1);
 expect(within(rows[0]).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["2", "1", "-"]);
 expect(within(rows[1]).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["2", "1", "4"]);
 const routes = screen.getByRole("table", { name: "BGP routes" });
 for (const [i, prefix] of approvedRemotePrefixes.entries()) {
  const row = within(routes).getByRole("rowheader", { name: prefix }).closest("tr")!;
  expect(within(row).getByText(`Tunnel ${i + 1}`)).toBeTruthy();
 }
 expect(screen.queryByText(/Active path|Preferred path|Not selected/)).toBeNull();
 expect(screen.getByText(/IPsec health, BGP peer state, and application reachability are separate/)).toBeTruthy();
});
it("keeps valid IPsec evidence when BGP evidence is absent", async () => {
 const { bgp: _bgp, ...data } = bgpReport();
 mock.get.mockResolvedValue({ data }); render(bgpView());
 await screen.findByRole("status", { name: "Tunnel 1 Up" });
 expect(screen.getByRole("status", { name: "Tunnel 1 BGP Unknown" })).toBeTruthy();
 const row = screen.getByRole("rowheader", { name: "Tunnel 1" }).closest("tr")!;
 expect(within(row).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["-", "-", "-"]);
 expect(within(screen.getByRole("table", { name: "BGP routes" })).queryByText(/Tunnel [12]|No installed route/)).toBeNull();
});
it.each(["stale", "future", "unknown"])("never presents stale or unknown BGP counts as measured zero: %s", async kind => {
 const data = bgpReport();
 if (kind === "stale") data.observed_at = new Date(Date.now() - 91_000).toISOString();
 if (kind === "future") data.observed_at = new Date(Date.now() + 6_000).toISOString();
 if (kind === "unknown") {
  data.bgp.peers = data.bgp.peers.map(p => ({ ...p, state: "unknown", accepted_prefixes: 0, installed_prefixes: 0, rejected_prefixes: 0 }));
  data.bgp.routes = [];
 }
 mock.get.mockResolvedValue({ data }); render(bgpView());
 await screen.findByText(kind === "unknown" ? "Live gateway report · updates every 10s" : "Waiting for a fresh gateway report");
 const rows = within(screen.getByRole("table", { name: "IPsec tunnel state" })).getAllByRole("row").slice(1);
 for (const row of rows) expect(within(row).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["-", "-", "-"]);
 expect(screen.queryByRole("status", { name: /BGP Established/ })).toBeNull();
 expect(within(screen.getByRole("table", { name: "BGP routes" })).queryByText(/Tunnel [12]|No installed route/)).toBeNull();
 expect(screen.getAllByText("No fresh BGP peer or route evidence yet. Refresh status and check gateway connectivity.")).toHaveLength(2);
});
it("shows measured zero for a known idle peer and absent rejected counts as unavailable", async () => {
 const data = bgpReport(); data.bgp.routes = [];
 data.bgp.peers = data.bgp.peers.map(p => ({ slot: p.slot, state: "idle", accepted_prefixes: 0, installed_prefixes: 0 }));
 mock.get.mockResolvedValue({ data }); render(bgpView());
 await screen.findByRole("status", { name: "Tunnel 1 BGP Idle" });
 const row = screen.getByRole("rowheader", { name: "Tunnel 1" }).closest("tr")!;
 expect(within(row).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["0", "0", "-"]);
 expect(screen.getAllByText("No installed route")).toHaveLength(2);
});
const invalidBGPReports = [
 ["unsupported version", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, version: 2 } })],
 ["zero sequence", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, sequence: 0 } })],
 ["unsafe sequence", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, sequence: Number.MAX_SAFE_INTEGER + 1 } })],
 ["null BGP", () => ({ ...bgpReport(), bgp: null })],
 ["null peer", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: [null, bgpReport().bgp.peers[1]] } })],
 ["missing peer", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: [bgpReport().bgp.peers[0]] } })],
 ["unordered slots", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: [...bgpReport().bgp.peers].reverse() } })],
 ["array FSM", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, state: ["idle"], accepted_prefixes: 0, installed_prefixes: 0 })), routes: [] } })],
 ["invalid FSM", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, state: "__proto__" })) } })],
 ["unapproved subprefix", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, routes: [{ prefix: "10.20.0.0/25", slot: 1 }] } })],
 ["duplicate prefix", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, routes: [bgpReport().bgp.routes[0], bgpReport().bgp.routes[0]] } })],
 ["invalid route slot", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, routes: [{ prefix: approvedRemotePrefixes[0], slot: 3 }] } })],
 ["null route", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, routes: [null] } })],
 ["route tally mismatch", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, installed_prefixes: 0 })) } })],
 ["unaccepted install", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, accepted_prefixes: 0 })) } })],
 ["too many accepted", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, accepted_prefixes: 65 })) } })],
 ["fractional count", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, accepted_prefixes: 1.5 })) } })],
 ["negative rejected", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, rejected_prefixes: -1 })) } })],
 ["oversized rejected", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, rejected_prefixes: 1_000_000_001 })) } })],
 ["installed on idle", () => ({ ...bgpReport(), bgp: { ...bgpReport().bgp, peers: bgpReport().bgp.peers.map(p => ({ ...p, state: "idle" })) } })],
 ["established with IPsec down", () => ({ ...bgpReport(), tunnels: bgpReport().tunnels.map(t => ({ ...t, status: "down" })) })],
 ["static preference", () => ({ ...bgpReport(), tunnels: bgpReport().tunnels.map(t => ({ ...t, selected: true })) })],
 ["recovery fields", () => ({ ...bgpReport(), recovery_version: 1, selection_sequence: 7, active_slot: 1 })],
 ["nonnull active path", () => ({ ...bgpReport(), active_slot: 2 })],
] as const;
it.each(invalidBGPReports)("refuses malformed BGP reports: %s", async (_name, fixture) => {
 mock.get.mockResolvedValue({ data: fixture() }); render(bgpView());
 await screen.findByText("Status unavailable");
 expect(screen.queryByRole("status", { name: / Up$|BGP Established/ })).toBeNull();
 expect(within(screen.getByRole("table", { name: "BGP routes" })).queryByText(/Tunnel [12]|No installed route/)).toBeNull();
});
it("clears BGP counts and routes after a failed refresh without issuing writes", async () => {
 mock.get.mockResolvedValue({ data: bgpReport() }); render(bgpView());
 await screen.findByRole("status", { name: "Tunnel 1 BGP Established" });
 mock.get.mockRejectedValue(new Error("offline"));
 fireEvent.click(screen.getByRole("button", { name: "Refresh tunnel status" }));
 await screen.findByText("Status unavailable");
 expect(screen.queryByRole("status", { name: /BGP Established/ })).toBeNull();
 expect(within(screen.getByRole("table", { name: "BGP routes" })).queryByText(/Tunnel [12]|No installed route/)).toBeNull();
 for (const write of [mock.post, mock.put, mock.patch, mock.delete]) expect(write).not.toHaveBeenCalled();
});
it("ignores a late BGP response after connection or approved prefixes change", async () => {
 let resolve!: (value: unknown) => void;
 mock.get.mockImplementationOnce(() => new Promise(r => { resolve = r; })).mockResolvedValue({ data: { ...bgpReport(), bgp: undefined } });
 const result = render(bgpView());
 result.rerender(<IPsecTunnelHealth orgId="org-a" connectionId="connection-b" tunnels={tunnels} mode="ipv4-bgp" approvedRemotePrefixes={["10.30.0.0/24"]} />);
 await screen.findByRole("status", { name: "Tunnel 1 Up" });
 resolve({ data: bgpReport() });
 await waitFor(() => expect(screen.getByRole("status", { name: "Tunnel 1 BGP Unknown" })).toBeTruthy());
 expect(screen.queryByText("10.20.0.0/24")).toBeNull();
 expect(screen.queryByRole("status", { name: /BGP Established/ })).toBeNull();
});

it("does not accept static preference metadata even when BGP evidence is absent", async () => {
 const { bgp: _bgp, ...data } = bgpReport();
 data.tunnels[0].selected = true;
 mock.get.mockResolvedValue({ data }); render(bgpView());
 await screen.findByText("Status unavailable");
 expect(screen.queryByRole("status", { name: / Up$/ })).toBeNull();
});
it("clears an old BGP response when only the approved prefix list changes", async () => {
 let resolve!: (value: unknown) => void;
 mock.get.mockImplementationOnce(() => new Promise(r => { resolve = r; })).mockResolvedValue({ data: { ...bgpReport(), bgp: undefined } });
 const result = render(bgpView());
 result.rerender(<IPsecTunnelHealth orgId="org-a" connectionId="connection-a" tunnels={tunnels} mode="ipv4-bgp" approvedRemotePrefixes={["10.30.0.0/24"]} />);
 await screen.findByRole("status", { name: "Tunnel 1 Up" });
 resolve({ data: bgpReport() });
 await waitFor(() => expect(screen.getByRole("status", { name: "Tunnel 1 BGP Unknown" })).toBeTruthy());
 expect(screen.queryByText("10.20.0.0/24")).toBeNull();
 expect(screen.queryByRole("status", { name: /BGP Established/ })).toBeNull();
});

it("accepts the public wire's null active_slot before any BGP observation", async () => {
 const data = {
  observed_at: null, active_slot: null,
  tunnels: report().tunnels.map(t => ({ ...t, selected: false, status: "unknown" })),
 };
 let resolve!: (value: unknown) => void;
 mock.get.mockImplementationOnce(() => new Promise(r => { resolve = r; })); render(bgpView());
 await waitFor(() => expect(mock.get).toHaveBeenCalled());
 await act(async () => { resolve({ data }); });
 expect(screen.queryByText("Status unavailable")).toBeNull();
 expect(screen.getByText("Waiting for a fresh gateway report")).toBeTruthy();
 for (const slot of [1, 2]) {
  expect(screen.getByRole("status", { name: `Tunnel ${slot} Unknown` })).toBeTruthy();
  expect(screen.getByRole("status", { name: `Tunnel ${slot} BGP Unknown` })).toBeTruthy();
  const row = screen.getByRole("rowheader", { name: `Tunnel ${slot}` }).closest("tr")!;
  expect(within(row).getAllByRole("cell").slice(4, 7).map(cell => cell.textContent)).toEqual(["-", "-", "-"]);
 }
 expect(within(screen.getByRole("table", { name: "BGP routes" })).queryByText(/Tunnel [12]|No installed route/)).toBeNull();
});
it("accepts fresh public BGP evidence with null active_slot without displaying a global path", async () => {
 mock.get.mockResolvedValue({ data: { ...bgpReport(), active_slot: null } }); render(bgpView());
 await screen.findByRole("status", { name: "Tunnel 1 BGP Established" });
 expect(screen.getByRole("status", { name: "Tunnel 2 BGP Established" })).toBeTruthy();
 expect(screen.queryByText("Status unavailable")).toBeNull();
 expect(screen.queryByText(/Active path|Preferred path|Not selected/)).toBeNull();
 const routes = screen.getByRole("table", { name: "BGP routes" });
 for (const [i, prefix] of approvedRemotePrefixes.entries()) {
  const row = within(routes).getByRole("rowheader", { name: prefix }).closest("tr")!;
  expect(within(row).getByText(`Tunnel ${i + 1}`)).toBeTruthy();
 }
});

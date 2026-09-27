import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put, DELETE: mock.del } }));
import { IPsecWorkspace } from "../src/components/IPsecWorkspace";
import type { Site } from "../src/lib/api";
const sites = [{ id: "site-a", name: "Office" }] as Site[];
const record = { id: "connection-a", name: "Office to cloud", desired_intent: "disabled", desired_revision: 1 };
const view = () => <IPsecWorkspace orgId="org-a" userId="user-a" emailVerified role="owner" sites={sites} />;
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mock.get.mockImplementation(async (path: string) => {
 if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
 if (path.endsWith("/connections")) return { data: { items: [record] } };
 if (path.endsWith("/nodes")) return { data: [{ id: "gateway-a", name: "Office gateway", site_id: "site-a", status: "active" }] };
 if (path.endsWith("/subnets")) return { data: [{ id: "sub-a", site_id: "site-a", cidr: "10.10.0.0/16", status: "approved" }] };
 if (path.endsWith("/eligibility")) return { data: { eligible: true, reason: "eligible" } };
 if (path.endsWith("/configuration")) return { data: { profile_id: "aws-static-ipv4-v1", configuration_revision: 1, configuration: { mode: "ipv4-static", customer_outside_address: "9.9.9.9", local_prefixes: ["10.10.0.0/16"], remote_prefixes: ["10.20.0.0/16"], tunnels: [] } } };
 return { data: record };
 }); });
it("loads stored disabled configurations and nonsecret readback", async () => {
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Office to cloud" }));
 await screen.findByText("9.9.9.9"); expect(screen.getByText("10.20.0.0/16")).toBeTruthy();
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
});
it("enables opt-in only through explicit current-revision action", async () => {
 mock.get.mockImplementation(async (path: string) => path.endsWith("/settings") ? { data: { enabled: false, revision: 4 } } : { data: { items: [] } });
 mock.put.mockResolvedValue({ data: { enabled: true, revision: 5 } });
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Enable IPsec" }));
 await waitFor(() => expect(mock.put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/settings", expect.objectContaining({ body: { enabled: true, expected_revision: 4 } })));
});
it("preflights then saves a disabled configuration with explicit inputs", async () => {
 mock.post.mockImplementation(async (path: string, opts: { body: { id: string } }) => path.endsWith("configuration-check") ? { data: { valid: true } } : { data: { ...record, id: opts.body.id } });
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Office cloud" } });
 fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
 fireEvent.change(await screen.findByLabelText("Gateway"), { target: { value: "gateway-a" } });
 fireEvent.click(await screen.findByLabelText("10.10.0.0/16"));
 fireEvent.change(screen.getByLabelText("Customer public IP"), { target: { value: "9.9.9.9" } });
 fireEvent.change(screen.getByLabelText("Remote network ranges"), { target: { value: "10.20.0.0/16" } });
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" }));
 for (const n of [1, 2]) for (const [field, value] of Object.entries({ "outside IP": n === 1 ? "8.8.8.8" : "1.1.1.1", "inside CIDR": n === 1 ? "169.254.10.0/30" : "169.254.10.4/30", "customer IP": n === 1 ? "169.254.10.1" : "169.254.10.5", "cloud IP": n === 1 ? "169.254.10.2" : "169.254.10.6", PSK: `Synthetic.PSK_${n}` })) fireEvent.change(screen.getByLabelText(`Tunnel ${n} ${field}`), { target: { value } });
 fireEvent.click(await screen.findByRole("button", { name: "Save disabled connection" }));
 await waitFor(() => expect(mock.post.mock.calls.some(([path]) => path.endsWith("/connections"))).toBe(true));
 const saved = mock.post.mock.calls.find(([path]) => path.endsWith("/connections"))![1].body;
 expect(saved.configuration.tunnels[0].psk).toBe("Synthetic.PSK_1"); expect(saved.tunnel_ids).toHaveLength(2); expect(saved.tunnel_ids[0]).not.toBe(saved.tunnel_ids[1]);
 await waitFor(() => expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull());
});
it("loads the next page with its cursor and deduplicates records", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: opts.params.query.after ? { items: [record, { ...record, id: "second", name: "Second connection" }], next_cursor: null } : { items: [record], next_cursor: record.id } } : original(path, opts));
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Load more" }));
 await screen.findByRole("button", { name: "Second connection" });
 expect(screen.getAllByRole("button", { name: "Office to cloud" })).toHaveLength(1);
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"), expect.objectContaining({ params: { path: { orgId: "org-a" }, query: { limit: 50, after: record.id } } }));
 expect(screen.queryByRole("button", { name: "Load more" })).toBeNull();
});
it("deletes only after confirmation using the displayed revision", async () => {
 mock.del.mockResolvedValue({ data: { ...record, desired_intent: "deleted", desired_revision: 2 } });
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Delete Office to cloud" }));
 expect(mock.del).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole("button", { name: "Delete connection" }));
 await waitFor(() => expect(mock.del).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}", { params: { path: { orgId: "org-a", connectionId: record.id }, header: { "If-Match": '"1"' } } }));
 await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
});
it("shows unsupported gateway readiness without enabling a save", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/eligibility") ? { data: { eligible: false, reason: "unsupported" } } : original(path, opts));
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Office cloud" } });
 fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
 fireEvent.change(await screen.findByLabelText("Gateway"), { target: { value: "gateway-a" } });
 fireEvent.click(await screen.findByLabelText("10.10.0.0/16"));
 fireEvent.change(screen.getByLabelText("Customer public IP"), { target: { value: "9.9.9.9" } });
 fireEvent.change(screen.getByLabelText("Remote network ranges"), { target: { value: "10.20.0.0/16" } });
 await screen.findByText("This gateway does not support IPsec yet.");
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" }));
 expect((screen.getByRole("button", { name: "Save disabled connection" }) as HTMLButtonElement).disabled).toBe(true);
 expect(mock.post).not.toHaveBeenCalled();
});
it("reconciles an uncertain create before readiness even when gateway support disappears", async () => {
 const original=mock.get.getMockImplementation()!; let unsupported=false;let found=false;
 mock.get.mockImplementation(async(path:string,opts:any)=>{
  if(path.endsWith("/eligibility")&&unsupported)return {data:{eligible:false,reason:"unsupported"}};
  if(path.endsWith("/{connectionId}"))return found?{data:{...record,id:opts.params.path.connectionId}}:{error:{}};
  return original(path,opts);
 });
 mock.post.mockImplementation(async(path:string)=>path.endsWith("/configuration-check")?{data:{valid:true}}:{error:{},response:{status:503}});
 render(view());fireEvent.click(await screen.findByRole("button",{name:"New connection"}));
 for(const [label,value]of [["Name","Office cloud"],["Local network","site-a"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});
 fireEvent.change(await screen.findByLabelText("Gateway"),{target:{value:"gateway-a"}});fireEvent.click(await screen.findByLabelText("10.10.0.0/16"));
 for(const[label,value]of [["Customer public IP","9.9.9.9"],["Remote network ranges","10.20.0.0/16"]])fireEvent.change(screen.getByLabelText(label),{target:{value}});
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));
 for(const n of [1,2])for(const[field,value]of Object.entries({"outside IP":n===1?"8.8.8.8":"1.1.1.1","inside CIDR":n===1?"169.254.10.0/30":"169.254.10.4/30","customer IP":n===1?"169.254.10.1":"169.254.10.5","cloud IP":n===1?"169.254.10.2":"169.254.10.6",PSK:`Synthetic.PSK_${n}`}))fireEvent.change(screen.getByLabelText(`Tunnel ${n} ${field}`),{target:{value}});
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));await screen.findByRole("button",{name:"Retry save"});
 unsupported=true;found=true;fireEvent.click(screen.getByRole("button",{name:"Check support"}));await screen.findByText("This gateway does not support IPsec yet.");
 expect((screen.getByRole("button",{name:"Retry save"})as HTMLButtonElement).disabled).toBe(false);
 fireEvent.click(screen.getByRole("button",{name:"Retry save"}));await screen.findByText("Stored configuration");
 expect(mock.post.mock.calls.filter(([path])=>path.endsWith("/connections"))).toHaveLength(1);
 expect(mock.post.mock.calls.filter(([path])=>path.endsWith("/configuration-check"))).toHaveLength(1);
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
});

it("distinguishes pending deletion from retained safety ownership", async () => {
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[
 {...record,id:"pending",name:"Pending removal",desired_intent:"deleted",application_state:"not_applied",cleanup_state:"pending",finalized_at:null},
 {...record,id:"retained",name:"Removed tunnel",desired_intent:"deleted",application_state:"not_applied",cleanup_state:"retained_guard",finalized_at:"2026-09-24T10:00:00Z"}
 ]}}:original(path,opts));
 render(view());await screen.findByText("Cleanup pending");await screen.findByText("Removed · guard retained");
 expect(screen.queryByRole("button",{name:"Delete Removed tunnel"})).toBeNull();
 expect(screen.getByText("Removed · guard retained").getAttribute("title")).toContain("reserved");
});
it("disables active intent with its exact revision without claiming connected traffic",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,desired_intent:"enabled",desired_revision:7,application_state:"applied",cleanup_state:"not_required"}]}}:original(path,opts));
 mock.put.mockResolvedValue({data:{...record,desired_revision:8,cleanup_state:"pending"}});
 render(view());await screen.findByText("Applied");expect(screen.queryByText("Connected")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Disable Office to cloud"}));expect(mock.put).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole("button",{name:"Disable connection"}));
 await waitFor(()=>expect(mock.put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/intent",{params:{path:{orgId:"org-a",connectionId:"connection-a"},header:{"If-Match":'"7"'}},body:{intent:"disabled"}}));
});
it("does not offer enable while cleanup is pending or ownership is read-only",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,cleanup_state:"pending",application_state:"not_applied",site_id:"site-a",gateway_node_id:"gateway-a"}]}}:original(path,opts));
 render(view());await screen.findByText("Cleanup pending");expect(screen.queryByRole("button",{name:"Enable Office to cloud"})).toBeNull();expect(mock.put).not.toHaveBeenCalled();
});
it("retains a failed intent dialog and requires refresh after conflict",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,desired_intent:"enabled",application_state:"pending",cleanup_state:"not_required"}]}}:original(path,opts));
 mock.put.mockResolvedValue({error:{},response:{status:409}});render(view());
 fireEvent.click(await screen.findByRole("button",{name:"Disable Office to cloud"}));fireEvent.click(screen.getByRole("button",{name:"Disable connection"}));
 await screen.findByText("Could not confirm the change. Close and refresh before retrying.");expect(screen.getByRole("dialog")).toBeTruthy();
});
it("rechecks support before enabling and refuses a gateway that became unsupported",async()=>{
 const original=mock.get.getMockImplementation()!;let supported=true;
 mock.get.mockImplementation(async(path:string,opts:any)=>{
  if(path.endsWith("/connections"))return {data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a",cleanup_state:"not_required",application_state:"not_applied"}]}};
  if(path.endsWith("/eligibility"))return {data:{eligible:supported,reason:supported?"eligible":"unsupported"}};
  return original(path,opts);
 });
 render(view());fireEvent.click(await screen.findByRole("button",{name:"Enable Office to cloud"}));supported=false;
 fireEvent.click(screen.getByRole("button",{name:"Enable connection"}));
 await screen.findByText("Gateway readiness changed. Close and refresh before enabling.");expect(mock.put).not.toHaveBeenCalled();
});
it("offers no lifecycle writes to a viewer",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,desired_intent:"enabled",application_state:"applied",cleanup_state:"not_required"}]}}:original(path,opts));
 render(<IPsecWorkspace orgId="org-a" userId="viewer-a" emailVerified role="member" sites={sites}/>);
 await screen.findByText("Applied");expect(screen.queryByRole("button",{name:"Disable Office to cloud"})).toBeNull();expect(screen.queryByRole("button",{name:"Delete Office to cloud"})).toBeNull();expect(screen.queryByRole("button",{name:"New connection"})).toBeNull();
});

it("combines intent filters with network search and clears unmatched filters", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { items: [
  { ...record, site_id: "site-a" },
  { ...record, id: "active", name: "Production AWS", site_id: "site-a", desired_intent: "enabled", application_state: "applied" },
 ] } } : original(path, opts));
 render(view());
 fireEvent.change(await screen.findByRole("combobox", { name: "Connection status" }), { target: { value: "enabled" } });
 expect(screen.queryByRole("button", { name: "Office to cloud" })).toBeNull();
 fireEvent.change(screen.getByLabelText("Search VPN connections"), { target: { value: " office " } });
 expect(screen.getByRole("button", { name: "Production AWS" })).toBeTruthy();
 fireEvent.change(screen.getByLabelText("Search VPN connections"), { target: { value: "missing" } });
 expect(screen.getByText("No connections match your filters.")).toBeTruthy();
 fireEvent.click(screen.getByRole("button", { name: "Clear filters" }));
 expect(screen.getByRole("button", { name: "Office to cloud" })).toBeTruthy();
 expect(screen.getByRole("button", { name: "Production AWS" })).toBeTruthy();
});
it("shows all server-loaded connections without a second client pagination layer", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { items: Array.from({ length: 26 }, (_, i) => ({ ...record, id: `item-${i}`, name: `VPN ${i + 1}` })) } } : original(path, opts));
 render(view());
 expect(await screen.findByRole("button", { name: "VPN 26" })).toBeTruthy();
});

import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put, DELETE: mock.del } }));
import { IPsecWorkspace } from "../src/components/IPsecWorkspace";
import { MemoryRouter } from "react-router-dom";
import type { Site } from "../src/lib/api";
const sites = [{ id: "site-a", name: "Office" }] as Site[];
const record = { id: "connection-a", org_id: "org-a", name: "Office to cloud", site_id: null, gateway_node_id: null, historical_site_id: "site-a", historical_gateway_node_id: "gateway-a", desired_intent: "disabled", desired_revision: 1, application_state: "not_applied", cleanup_state: "not_required", deleted_at: null, finalized_at: null, created_at: "2026-10-08T10:00:00Z", updated_at: "2026-10-08T10:00:00Z" };
const view = () => <MemoryRouter><IPsecWorkspace orgId="org-a" userId="user-a" emailVerified role="owner" sites={sites} /></MemoryRouter>;
async function connectionMenu(name: string) {
 const trigger = await screen.findByRole("button", { name: `Connection actions for ${name}` });
 if (trigger.getAttribute("aria-expanded") !== "true") fireEvent.click(trigger);
 return within(screen.getByRole("menu", { name: `Connection actions for ${name}` }));
}
afterEach(cleanup);
beforeEach(() => { vi.clearAllMocks(); mock.get.mockImplementation(async (path: string) => {
 if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
 if (path.endsWith("/connections")) return { data: { items: [record], next_cursor: null } };
 if (path.endsWith("/nodes")) return { data: [{ id: "gateway-a", name: "Office gateway", site_id: "site-a", status: "active" }] };
 if (path.endsWith("/subnets")) return { data: [{ id: "sub-a", site_id: "site-a", cidr: "10.10.0.0/16", status: "approved" }] };
 if (path.endsWith("/eligibility")) return { data: { eligible: true, reason: "eligible" } };
 if (path.endsWith("/configuration")) return { data: { profile_id: "aws-static-ipv4-v1", configuration_revision: 1, configuration: { mode: "ipv4-static", customer_outside_address: "9.9.9.9", local_prefixes: ["10.10.0.0/16"], remote_prefixes: ["10.20.0.0/16"], tunnels: [] } } };
 return { data: record };
 }); });
it("loads stored disabled configurations and nonsecret readback", async () => {
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Office to cloud" }));
 fireEvent.click(await screen.findByText("Stored configuration"));
 await screen.findByText("9.9.9.9"); expect(screen.getByText("10.20.0.0/16")).toBeTruthy();
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
 const breadcrumb=screen.getByRole("navigation",{name:"IPsec connection breadcrumb"});expect(within(breadcrumb).getByText("Office to cloud").getAttribute("aria-current")).toBe("page");expect(screen.queryByRole("table",{name:"IPsec connections"})).toBeNull();
 fireEvent.click(within(breadcrumb).getByRole("button",{name:"Back to connections"}));expect(screen.getByRole("table",{name:"IPsec connections"})).toBeTruthy();expect(screen.getByRole("button",{name:"Office to cloud"})).toBeTruthy();expect(mock.post).not.toHaveBeenCalled();expect(mock.put).not.toHaveBeenCalled();expect(mock.del).not.toHaveBeenCalled();
});
it("refers disabled organization activation to Features without changing stored connection intent", async () => {
 mock.get.mockImplementation(async (path: string) => path.endsWith("/settings") ? { data: { enabled: false, revision: 4 } } : { data: { items: [], next_cursor: null } });
 render(view());
 const link = await screen.findByRole("link", { name: "Manage in Features" });
 expect(link.getAttribute("href")).toBe("/settings?section=features&feature=ipsec");
 expect(screen.queryByRole("button", { name: "Enable IPsec" })).toBeNull();
 expect(screen.queryByRole("button", { name: "Disable IPsec" })).toBeNull();
 expect(mock.put).not.toHaveBeenCalled();
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
it("uses the server cursor to replace the page and deduplicates records within its response", async () => {
 const original = mock.get.getMockImplementation()!;
 const second = { ...record, id: "second", name: "Second connection" };
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: opts.params.query.after ? { items: [second, second], next_cursor: null } : { items: [record], next_cursor: record.id } } : original(path, opts));
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Next connections" }));
 await screen.findByRole("button", { name: "Second connection" });
 expect(screen.getAllByRole("button", { name: "Second connection" })).toHaveLength(1);
 expect(screen.queryByRole("button", { name: "Office to cloud" })).toBeNull();
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"), expect.objectContaining({ params: { path: { orgId: "org-a" }, query: { limit: 20, after: record.id } } }));
 expect(screen.getByRole("button", { name: "Next connections" })).toHaveProperty("disabled",true);
 fireEvent.click(screen.getByRole("button", { name: "Previous connections" }));
 await screen.findByRole("button", { name: "Office to cloud" });
 expect(screen.queryByRole("button", { name: "Second connection" })).toBeNull();
 expect(mock.get).toHaveBeenLastCalledWith(expect.stringContaining("/connections"), { params: { path: { orgId: "org-a" }, query: { limit: 20 } } });
});
it("deletes only after confirmation using the displayed revision", async () => {
 mock.del.mockResolvedValue({ data: { ...record, desired_intent: "deleted", desired_revision: 2 } });
 render(view()); fireEvent.click((await connectionMenu("Office to cloud")).getByRole("menuitem", { name: "Delete Office to cloud" }));
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
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{next_cursor:null,items:[
 {...record,id:"pending",name:"Pending removal",desired_intent:"deleted",application_state:"not_applied",cleanup_state:"pending",finalized_at:null},
 {...record,id:"retained",name:"Removed tunnel",desired_intent:"deleted",application_state:"not_applied",cleanup_state:"retained_guard",finalized_at:"2026-09-24T10:00:00Z"}
 ]}}:original(path,opts));
 render(view());await screen.findByText("Cleanup pending");await screen.findByText("Removed · guard retained");
 expect((await connectionMenu("Removed tunnel")).queryByRole("menuitem",{name:"Delete Removed tunnel"})).toBeNull();
 expect(screen.getByText("Removed · guard retained").getAttribute("title")).toContain("reserved");
});
it("disables active intent with its exact revision without claiming connected traffic",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{next_cursor:null,items:[{...record,desired_intent:"enabled",desired_revision:7,application_state:"applied",cleanup_state:"not_required"}]}}:original(path,opts));
 mock.put.mockResolvedValue({data:{...record,desired_revision:8,cleanup_state:"pending"}});
 render(view());await screen.findByText("Applied");expect(screen.queryByText("Connected")).toBeNull();
 fireEvent.click((await connectionMenu("Office to cloud")).getByRole("menuitem",{name:"Disable Office to cloud"}));expect(mock.put).not.toHaveBeenCalled();
 fireEvent.click(screen.getByRole("button",{name:"Disable connection"}));
 await waitFor(()=>expect(mock.put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/intent",{params:{path:{orgId:"org-a",connectionId:"connection-a"},header:{"If-Match":'"7"'}},body:{intent:"disabled"}}));
});
it("does not offer enable while cleanup is pending or ownership is read-only",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{next_cursor:null,items:[{...record,cleanup_state:"pending",application_state:"not_applied",site_id:"site-a",gateway_node_id:"gateway-a"}]}}:original(path,opts));
 render(view());await screen.findByText("Cleanup pending");expect((await connectionMenu("Office to cloud")).queryByRole("menuitem",{name:"Enable Office to cloud"})).toBeNull();expect(mock.put).not.toHaveBeenCalled();
});
it("retains a failed intent dialog and requires refresh after conflict",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{next_cursor:null,items:[{...record,desired_intent:"enabled",application_state:"pending",cleanup_state:"not_required"}]}}:original(path,opts));
 mock.put.mockResolvedValue({error:{},response:{status:409}});render(view());
 fireEvent.click((await connectionMenu("Office to cloud")).getByRole("menuitem",{name:"Disable Office to cloud"}));fireEvent.click(screen.getByRole("button",{name:"Disable connection"}));
 await screen.findByText("Could not confirm the change. Close and refresh before retrying.");expect(screen.getByRole("dialog")).toBeTruthy();
});
it("rechecks support before enabling and refuses a gateway that became unsupported",async()=>{
 const original=mock.get.getMockImplementation()!;let supported=true;
 mock.get.mockImplementation(async(path:string,opts:any)=>{
  if(path.endsWith("/connections"))return {data:{next_cursor:null,items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a",cleanup_state:"not_required",application_state:"not_applied"}]}};
  if(path.endsWith("/eligibility"))return {data:{eligible:supported,reason:supported?"eligible":"unsupported"}};
  return original(path,opts);
 });
 render(view());fireEvent.click(await (await connectionMenu("Office to cloud")).findByRole("menuitem",{name:"Enable Office to cloud"}));supported=false;
 fireEvent.click(screen.getByRole("button",{name:"Enable connection"}));
 await screen.findByText("Gateway readiness changed. Close and refresh before enabling.");expect(mock.put).not.toHaveBeenCalled();
});
it("offers no lifecycle writes to a viewer",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{next_cursor:null,items:[{...record,desired_intent:"enabled",application_state:"applied",cleanup_state:"not_required"}]}}:original(path,opts));
 render(<MemoryRouter><IPsecWorkspace orgId="org-a" userId="viewer-a" emailVerified role="member" sites={sites}/></MemoryRouter>);
 await screen.findByText("Applied");const menu=await connectionMenu("Office to cloud");expect(menu.getByRole("menuitem",{name:"Connection details"})).toBeTruthy();expect(menu.queryByRole("menuitem",{name:"Disable Office to cloud"})).toBeNull();expect(menu.queryByRole("menuitem",{name:"Delete Office to cloud"})).toBeNull();expect(screen.queryByRole("button",{name:"New connection"})).toBeNull();
});

it("combines intent filters with network search and clears unmatched filters", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { next_cursor: null, items: [
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
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { next_cursor: null, items: Array.from({ length: 26 }, (_, i) => ({ ...record, id: `item-${i}`, name: `VPN ${i + 1}` })) } } : original(path, opts));
 render(view());
 expect(await screen.findByRole("button", { name: "VPN 26" })).toBeTruthy();
});

it("uses real cursor limits and preserves navigation when page-scoped filters hide every record", async () => {
 const original=mock.get.getMockImplementation()!;
 const records=Array.from({length:55},(_,index)=>({...record,id:`connection-${index}`,name:`VPN ${String(index).padStart(3,"0")}`}));
 mock.get.mockImplementation(async(path:string,opts:any)=>{
  if(!path.endsWith("/connections"))return original(path,opts);
  const {limit,after}=opts.params.query;const offset=after?records.findIndex(item=>item.id===after)+1:0;const items=records.slice(offset,offset+limit);
  return {data:{items,next_cursor:offset+limit<records.length?items.at(-1)!.id:null}};
 });
 render(view());await screen.findByRole("button",{name:"VPN 000"});expect(screen.getAllByRole("row")).toHaveLength(21);
 fireEvent.click(screen.getByRole("button",{name:"Next connections"}));await screen.findByRole("button",{name:"VPN 020"});expect(screen.queryByRole("button",{name:"VPN 000"})).toBeNull();
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:20,after:"connection-19"}}});
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"10"}});await screen.findByRole("button",{name:"VPN 000"});expect(screen.getAllByRole("row")).toHaveLength(11);
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:10}}});
 fireEvent.click(screen.getByRole("button",{name:"Next connections"}));await screen.findByRole("button",{name:"VPN 010"});
 fireEvent.change(screen.getByRole("combobox",{name:"Rows per page"}),{target:{value:"50"}});await screen.findByRole("button",{name:"VPN 000"});expect(screen.getAllByRole("row")).toHaveLength(51);
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:50}}});
 fireEvent.click(screen.getByRole("button",{name:"Next connections"}));await screen.findByRole("button",{name:"VPN 050"});expect(screen.getAllByRole("row")).toHaveLength(6);expect(screen.getByRole("button",{name:"Next connections"})).toHaveProperty("disabled",true);
 expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:50,after:"connection-49"}}});
 fireEvent.click(screen.getByRole("button",{name:"Previous connections"}));await screen.findByRole("button",{name:"VPN 000"});
 fireEvent.change(screen.getByRole("textbox",{name:"Search VPN connections"}),{target:{value:"missing"}});expect(screen.queryByRole("table")).toBeNull();expect(screen.getByText("No connections match your filters.")).toBeTruthy();
 expect(screen.getByRole("button",{name:"Next connections"})).toHaveProperty("disabled",false);fireEvent.click(screen.getByRole("button",{name:"Next connections"}));await screen.findByText("Page 2");
 expect(screen.getByRole("button",{name:"Previous connections"})).toHaveProperty("disabled",false);fireEvent.click(screen.getByRole("button",{name:"Clear filters"}));expect(screen.getByRole("button",{name:"VPN 050"})).toBeTruthy();
 expect(mock.post).not.toHaveBeenCalled();expect(mock.put).not.toHaveBeenCalled();expect(mock.del).not.toHaveBeenCalled();
});

it("can return from an empty later cursor page without treating it as an empty inventory",async()=>{
 const original=mock.get.getMockImplementation()!;mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:opts.params.query.after?{items:[],next_cursor:null}:{items:[record],next_cursor:record.id}}:original(path,opts));
 render(view());fireEvent.click(await screen.findByRole("button",{name:"Next connections"}));await screen.findByText("No connections on this page");expect(screen.queryByText("No IPsec connections configured.")).toBeNull();expect(screen.queryByRole("table")).toBeNull();
 expect(screen.getByRole("button",{name:"Previous connections"})).toHaveProperty("disabled",false);expect(screen.getByRole("button",{name:"Next connections"})).toHaveProperty("disabled",true);fireEvent.click(screen.getByRole("button",{name:"Previous connections"}));await screen.findByRole("button",{name:"Office to cloud"});
});

it("retries a failed next-page read with the same cursor and limit",async()=>{
 const original=mock.get.getMockImplementation()!;let failing=true;mock.get.mockImplementation(async(path:string,opts:any)=>{
  if(!path.endsWith("/connections"))return original(path,opts);
  if(!opts.params.query.after)return {data:{items:[record],next_cursor:record.id}};
  return failing?{error:{}}:{data:{items:[{...record,id:"second",name:"Recovered page"}],next_cursor:null}};
 });
 render(view());fireEvent.click(await screen.findByRole("button",{name:"Next connections"}));await screen.findByText("Could not load IPsec configuration. Try again.");expect(screen.queryByText("No connections on this page")).toBeNull();expect(screen.queryByText("No IPsec connections configured.")).toBeNull();
 failing=false;fireEvent.click(screen.getByRole("button",{name:"Retry connections"}));await screen.findByRole("button",{name:"Recovered page"});expect(screen.getByText("Page 2")).toBeTruthy();
 expect(mock.get.mock.calls.filter(([path,opts])=>path.endsWith("/connections")&&opts.params.query.after===record.id)).toHaveLength(2);expect(mock.get).toHaveBeenLastCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:20,after:record.id}}});
});

it("discards an old organization page response after the workspace changes scope",async()=>{
 const original=mock.get.getMockImplementation()!;let complete:(value:unknown)=>void=()=>{};
 mock.get.mockImplementation((path:string,opts:any)=>path.endsWith("/connections")?opts.params.path.orgId==="org-a"?new Promise(resolve=>{complete=resolve;}):Promise.resolve({data:{items:[{...record,id:"org-b-connection",org_id:"org-b",name:"B connection"}],next_cursor:null}}):original(path,opts));
 const rendered=render(view());await waitFor(()=>expect(mock.get).toHaveBeenCalledWith(expect.stringContaining("/connections"),{params:{path:{orgId:"org-a"},query:{limit:20}}}));
 rendered.rerender(<MemoryRouter><IPsecWorkspace orgId="org-b" userId="user-a" emailVerified role="owner" sites={sites}/></MemoryRouter>);await screen.findByRole("button",{name:"B connection"});
 await act(async()=>{complete({data:{items:[record],next_cursor:record.id}})});expect(screen.queryByRole("button",{name:"Office to cloud"})).toBeNull();expect(screen.getByRole("button",{name:"B connection"})).toBeTruthy();expect(screen.queryByRole("button",{name:"Next connections"})).toBeNull();
});

const invalidPages: Array<[string, unknown]> = [
 ["missing items", { next_cursor: null }],
 ["null items", { items: null, next_cursor: null }],
 ["null connection", { items: [null], next_cursor: null }],
 ["missing revision", { items: [{ ...record, desired_revision: undefined }], next_cursor: null }],
 ["invalid revision", { items: [{ ...record, desired_revision: 0 }], next_cursor: null }],
 ["unknown desired intent", { items: [{ ...record, desired_intent: "connected" }], next_cursor: null }],
 ["unknown application state", { items: [{ ...record, application_state: "healthy" }], next_cursor: null }],
 ["unknown cleanup state", { items: [{ ...record, cleanup_state: "complete" }], next_cursor: null }],
 ["another organization's connection", { items: [{ ...record, org_id: "org-b" }], next_cursor: null }],
 ["invalid observation date", { items: [{ ...record, updated_at: "not-a-date" }], next_cursor: null }],
 ["missing next cursor", { items: [record] }],
 ["malformed next cursor", { items: [record], next_cursor: { id: record.id } }],
];

it.each(invalidPages)("refuses %s without claiming an empty or actionable inventory, then retries the same page", async (_case, invalidPage) => {
 const original = mock.get.getMockImplementation()!;
 let recovered = false;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections")
  ? { data: recovered ? { items: [record], next_cursor: null } : invalidPage }
  : original(path, opts));
 render(view());
 await screen.findByText("The server returned incomplete or non-advancing IPsec inventory. Retry to reload this page.");
 expect(screen.queryByRole("table", { name: "IPsec connections" })).toBeNull();
 expect(screen.queryByText("No IPsec connections configured.")).toBeNull();
 expect(screen.queryByRole("button", { name: "Connection actions for Office to cloud" })).toBeNull();
 expect(screen.queryByRole("button", { name: "Next connections" })).toBeNull();
 recovered = true;
 fireEvent.click(screen.getByRole("button", { name: "Retry connections" }));
 await screen.findByRole("button", { name: "Office to cloud" });
 const pageReads = mock.get.mock.calls.filter(([path]) => path.endsWith("/connections"));
 expect(pageReads).toHaveLength(2);
 for (const [, options] of pageReads) expect(options).toEqual({ params: { path: { orgId: "org-a" }, query: { limit: 20 } } });
 expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled(); expect(mock.del).not.toHaveBeenCalled();
});

it.each(["repeated", "cyclic"] as const)("rejects a %s backend cursor and retries the exact failed keyset page", async (kind) => {
 const original = mock.get.getMockImplementation()!;
 const second = { ...record, id: "connection-b", name: "Second connection" };
 const third = { ...record, id: "connection-c", name: "Third connection" };
 const failedCursor = kind === "repeated" ? record.id : second.id;
 let recovered = false;
 mock.get.mockImplementation(async (path: string, opts: any) => {
  if (!path.endsWith("/connections")) return original(path, opts);
  const cursor = opts.params.query.after;
  if (!cursor) return { data: { items: [record], next_cursor: record.id } };
  if (cursor === failedCursor && recovered) return { data: { items: [{ ...third, name: "Recovered cursor page" }], next_cursor: null } };
  if (cursor === record.id) return { data: { items: [second], next_cursor: kind === "repeated" ? record.id : second.id } };
  return { data: { items: [third], next_cursor: record.id } };
 });
 render(view());
 fireEvent.click(await screen.findByRole("button", { name: "Next connections" }));
 if (kind === "cyclic") {
  await screen.findByRole("button", { name: "Second connection" });
  fireEvent.click(screen.getByRole("button", { name: "Next connections" }));
 }
 await screen.findByText("The server returned incomplete or non-advancing IPsec inventory. Retry to reload this page.");
 expect(screen.queryByRole("table", { name: "IPsec connections" })).toBeNull();
 expect(screen.queryByText("No connections on this page")).toBeNull();
 expect(screen.queryByRole("button", { name: "Next connections" })).toBeNull();
 recovered = true;
 fireEvent.click(screen.getByRole("button", { name: "Retry connections" }));
 await screen.findByRole("button", { name: "Recovered cursor page" });
 expect(screen.getByText(`Page ${kind === "repeated" ? 2 : 3}`)).toBeTruthy();
 expect(screen.getByRole("button", { name: "Previous connections" })).toHaveProperty("disabled", false);
 const retryReads = mock.get.mock.calls.filter(([path, options]) => path.endsWith("/connections") && options.params.query.after === failedCursor);
 expect(retryReads).toHaveLength(2);
 for (const [, options] of retryReads) expect(options).toEqual({ params: { path: { orgId: "org-a" }, query: { limit: 20, after: failedCursor } } });
 expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled(); expect(mock.del).not.toHaveBeenCalled();
});

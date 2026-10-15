import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
const mock = vi.hoisted(() => ({ get: vi.fn(), post: vi.fn(), put: vi.fn(), del: vi.fn() }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get, POST: mock.post, PUT: mock.put, DELETE: mock.del } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: "user-a", email_verified: true } } }) }));
import { IPsecWorkspace, azureSettingsReview, type IPsecCreateProfile } from "../src/components/IPsecWorkspace";
import { awsGeneric } from "./fixtures/awsGeneric";
import { MemoryRouter } from "react-router-dom";
import type { Site } from "../src/lib/api";
const sites = [{ id: "site-a", name: "Office" }] as Site[];
const record = { id: "connection-a", org_id: "org-a", name: "Office to cloud", site_id: null, gateway_node_id: null, historical_site_id: "site-a", historical_gateway_node_id: "gateway-a", desired_intent: "disabled", desired_revision: 1, application_state: "not_applied", cleanup_state: "not_required", deleted_at: null, finalized_at: null, created_at: "2026-10-08T10:00:00Z", updated_at: "2026-10-08T10:00:00Z" };
const view = (initialProfile: IPsecCreateProfile = "aws") => <MemoryRouter><IPsecWorkspace initialProfile={initialProfile} orgId="org-a" userId="user-a" emailVerified role="owner" sites={sites} /></MemoryRouter>;
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
it("opens the shared DNS editor inside connection details with its exact network and gateway", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, options: unknown) => {
  if (path.endsWith("/connections")) return { data: { items: [{ ...record, site_id: "site-a", gateway_node_id: "gateway-a" }], next_cursor: null } };
  if (path.endsWith("/sites")) return { data: [{ id: "other", name: "Another network" }, ...sites] };
  if (path.includes("/fqdn-resolver-contexts/")) return { error: { error: { code: "fqdn_resolver_config_not_found" } } };
  return original(path, options);
 });
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Office to cloud" }));
 const disclosure = (await screen.findByText("DNS records and forwarding")).closest("details")!;
 disclosure.open = true; fireEvent(disclosure, new Event("toggle"));
 fireEvent.click(await screen.findByRole("button", { name: "Configure profiles" }));
 expect((screen.getByLabelText("Site", { selector: "select" }) as HTMLSelectElement).value).toBe("site-a");
 expect((screen.getByLabelText("Gateway", { selector: "select" }) as HTMLSelectElement).value).toBe("gateway-a");
 expect((screen.getByLabelText("Site", { selector: "select" }) as HTMLSelectElement).disabled).toBe(true);
 expect((screen.getByLabelText("Gateway", { selector: "select" }) as HTMLSelectElement).disabled).toBe(true);
 expect((screen.getByLabelText("Profile 1 DNS setup") as HTMLSelectElement).value).toBe("static");
 expect(mock.get.mock.calls.some(([path, options]) => path.includes("fqdn-resolver-contexts") && options.params.path.siteId === "site-a" && options.params.path.gatewayId === "gateway-a")).toBe(true);
 expect(mock.put).not.toHaveBeenCalled();
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
it("blocks another stale deletion attempt until the operator closes and refreshes", async () => {
 mock.del.mockResolvedValue({error:{},response:{status:409}});
 render(view()); fireEvent.click((await connectionMenu("Office to cloud")).getByRole("menuitem",{name:"Delete Office to cloud"}));
 const submit=screen.getByRole("button",{name:"Delete connection"}); fireEvent.click(submit);
 await screen.findByText("Could not confirm deletion. Close and refresh before retrying.");
 expect((submit as HTMLButtonElement).disabled).toBe(true); fireEvent.click(submit); expect(mock.del).toHaveBeenCalledTimes(1);
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
 const retry=screen.getByRole("button",{name:"Disable connection"});expect((retry as HTMLButtonElement).disabled).toBe(true);fireEvent.click(retry);expect(mock.put).toHaveBeenCalledTimes(1);
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

async function prepareBGPForm() {
 fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 fireEvent.change(screen.getByLabelText("Name"), { target: { value: "Office BGP" } });
 fireEvent.change(screen.getByLabelText("Routing"), { target: { value: "ipv4-bgp" } });
 fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
 fireEvent.change(await screen.findByLabelText("Gateway"), { target: { value: "gateway-a" } });
 fireEvent.click(await screen.findByLabelText("10.10.0.0/16"));
 fireEvent.change(screen.getByLabelText("Customer public IP"), { target: { value: "9.9.9.9" } });
 fireEvent.change(screen.getByLabelText("Remote network ranges"), { target: { value: "10.20.0.0/16" } });
 fireEvent.change(screen.getByLabelText("Router ID"), { target: { value: "10.10.0.1" } });
}
function fillBGPTunnels() {
 for (const n of [1, 2]) for (const [field, value] of Object.entries({ "outside IP": n === 1 ? "8.8.8.8" : "1.1.1.1", "inside CIDR": n === 1 ? "169.254.10.0/30" : "169.254.10.4/30", "customer IP": n === 1 ? "169.254.10.1" : "169.254.10.5", "cloud IP": n === 1 ? "169.254.10.2" : "169.254.10.6", PSK: `Synthetic.BGP_${n}` })) fireEvent.change(screen.getByLabelText(`Tunnel ${n} ${field}`), { target: { value } });
}
const bgpReadback = { profile_id: "aws-bgp-ipv4-v1", configuration_revision: 1, configuration: { mode: "ipv4-bgp", customer_outside_address: "9.9.9.9", local_prefixes: ["10.10.0.0/16"], remote_prefixes: ["10.20.0.0/16"], tunnels: [1,2].map(i => ({ outside_address:`8.8.8.${i}`, inside_cidr:`169.254.${i}.0/30`, customer_inside_address:`169.254.${i}.1`, cloud_inside_address:`169.254.${i}.2` })), bgp: { local_asn: 65000, remote_asn: 64512, router_id: "10.10.0.1", maximum_prefixes: 64 } } };
it("reviews and saves BGP disabled even when BGP activation capability is unavailable", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/eligibility") ? { data: { eligible: true, reason: "eligible", bgp: { eligible: false, reason: "unsupported" } } } : original(path, opts));
 mock.post.mockImplementation(async (path: string, opts: any) => path.endsWith("configuration-check") ? { data: { valid: true } } : { data: { ...record, id: opts.body.id } });
 render(view()); await prepareBGPForm();
 expect(await screen.findByText("You can save this BGP configuration disabled. Enabling requires a gateway with fresh BGP support.")).toBeTruthy();
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" })); fillBGPTunnels();
 expect(screen.getByRole("region", { name: "Connection review" }).textContent).toContain("Customer ASN 65000");
 expect(screen.getByRole("region", { name: "Connection review" }).textContent).not.toContain("Synthetic.BGP");
 fireEvent.click(screen.getByRole("button", { name: "Save disabled connection" }));
 await waitFor(() => expect(mock.post.mock.calls.some(([path]) => path.endsWith("/connections"))).toBe(true));
 const payload = mock.post.mock.calls.find(([path]) => path.endsWith("/connections"))![1].body.configuration;
 expect(payload.mode).toBe("ipv4-bgp"); expect(payload.bgp).toEqual(bgpReadback.configuration.bgp);
 expect(payload.tunnels[1].psk).toBe("Synthetic.BGP_2");
});
it("keeps static payload unchanged when switching away from BGP", async () => {
 mock.post.mockImplementation(async (path: string, opts: any) => path.endsWith("configuration-check") ? { data: { valid: true } } : { data: { ...record, id: opts.body.id } });
 render(view()); await prepareBGPForm();
 fireEvent.change(screen.getByLabelText("Routing"), { target: { value: "ipv4-static" } });
 expect(screen.queryByLabelText("Customer ASN")).toBeNull();
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" })); fillBGPTunnels();
 fireEvent.click(screen.getByRole("button", { name: "Save disabled connection" }));
 await waitFor(() => expect(mock.post.mock.calls.some(([path]) => path.endsWith("/connections"))).toBe(true));
 const payload = mock.post.mock.calls.find(([path]) => path.endsWith("/connections"))![1].body.configuration;
 expect(payload.mode).toBe("ipv4-static"); expect(payload).not.toHaveProperty("bgp");
});
it("requires valid distinct private ASNs and bounded per-peer limits before BGP review", async () => {
 render(view()); await prepareBGPForm();
 for (const [label, invalid] of [["Customer ASN", "65535"], ["AWS ASN", "65000"], ["Maximum prefixes per peer", "65"]]) {
  const input = screen.getByLabelText(label); const original = (input as HTMLInputElement).value;
  fireEvent.change(input, { target: { value: invalid } });
  expect((screen.getByRole("button", { name: "Next: tunnels" }) as HTMLButtonElement).disabled).toBe(true);
  fireEvent.change(input, { target: { value: original } });
 }
 expect((screen.getByRole("button", { name: "Next: tunnels" }) as HTMLButtonElement).disabled).toBe(false); expect(mock.post).not.toHaveBeenCalled();
});
it("uses stored BGP mode and fresh BGP readiness for enable and rechecks at the action", async () => {
 const original = mock.get.getMockImplementation()!; let bgpSupported = true;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { items: [{ ...record, cleanup_state: "not_required", site_id: "site-a", gateway_node_id: "gateway-a" }], next_cursor: null } } : path.endsWith("/configuration") ? { data: bgpReadback } : path.endsWith("/eligibility") ? { data: { eligible: true, reason: "eligible", bgp: { eligible: bgpSupported, reason: bgpSupported ? "eligible" : "unsupported" } } } : original(path, opts));
 render(view()); fireEvent.click(await (await connectionMenu("Office to cloud")).findByRole("menuitem", { name: "Enable Office to cloud" }));
 bgpSupported = false; fireEvent.click(screen.getByRole("button", { name: "Enable connection" }));
 await screen.findByText("Gateway readiness changed. Close and refresh before enabling."); expect(mock.put).not.toHaveBeenCalled();
});
it("does not offer BGP enable based on base IPsec support alone", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/connections") ? { data: { items: [{ ...record, cleanup_state: "not_required", site_id: "site-a", gateway_node_id: "gateway-a" }], next_cursor: null } } : path.endsWith("/configuration") ? { data: bgpReadback } : original(path, opts));
 render(view()); await screen.findByRole("button", { name: "Office to cloud" });
 await waitFor(() => expect(mock.get.mock.calls.some(([path]) => path.endsWith("/configuration"))).toBe(true));
 expect((await connectionMenu("Office to cloud")).queryByRole("menuitem", { name: "Enable Office to cloud" })).toBeNull();
});
it("reads back BGP settings without showing credentials", async () => {
 const original = mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/configuration") ? { data: bgpReadback } : original(path, opts));
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "Office to cloud" }));
 await screen.findByText("AWS · IPv4 BGP · revision 1");
 expect(screen.getByText("65000")).toBeTruthy(); expect(screen.getByText("64512")).toBeTruthy();
 expect(screen.getByText("Maximum prefixes per peer")).toBeTruthy(); expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
});
it("saves explicit GCP HA profile using common BGP fields and interface review", async () => {
 mock.post.mockImplementation(async (path:string, opts:any) => path.endsWith("configuration-check") ? {data:{valid:true}} : {data:{...record,id:opts.body.id}});
 render(view("gcp-ha-bgp-ipv4-v1")); await prepareBGPForm();
 fireEvent.change(screen.getByLabelText("Cloud VPN profile"),{target:{value:"gcp-ha-bgp-ipv4-v1"}});
 expect((screen.getByLabelText("Routing") as HTMLSelectElement).disabled).toBe(true);
 expect(screen.getByLabelText("Cloud Router ASN")).toBeTruthy();
 expect(screen.getByText(/Enabling requires fresh Google Cloud HA VPN support/)).toBeTruthy();
 expect(screen.getByText(/A single local gateway/)).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"})); fillBGPTunnels();
 expect(screen.getByText("Tunnel 1 · GCP interface 0")).toBeTruthy();
 expect(screen.getByText("Tunnel 2 · GCP interface 1")).toBeTruthy();
 expect(screen.getByRole("region",{name:"Connection review"}).textContent).not.toContain("Synthetic.BGP");
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
 await waitFor(()=>expect(mock.post.mock.calls.some(([path])=>path.endsWith("/connections"))).toBe(true));
 const configuration=mock.post.mock.calls.find(([path])=>path.endsWith("/connections"))![1].body.configuration;
 expect(configuration.profile_id).toBe("gcp-ha-bgp-ipv4-v1");expect(configuration.mode).toBe("ipv4-bgp");expect(configuration.tunnels).toHaveLength(2);
});
it("saves Classic with one real tunnel and no BGP or invented inside addresses",async()=>{
 mock.post.mockImplementation(async(path:string,opts:any)=>path.endsWith("configuration-check")?{data:{valid:true}}:{data:{...record,id:opts.body.id}});
 render(view("gcp-ha-bgp-ipv4-v1"));await prepareBGPForm();
 fireEvent.change(screen.getByLabelText("Cloud VPN profile"),{target:{value:"gcp-classic-static-ipv4-v1"}});
 expect(screen.getByText(/Classic uses one route-based static tunnel/)).toBeTruthy();expect(screen.queryByLabelText("Cloud Router ASN")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));
 expect(screen.getByRole("region",{name:"Connection review"}).textContent).toContain("Google Cloud Classic VPN");
 expect(screen.queryByLabelText("Tunnel 1 inside CIDR")).toBeNull();expect(screen.queryByLabelText("Tunnel 2 outside IP")).toBeNull();
 fireEvent.change(screen.getByLabelText("Tunnel 1 outside IP"),{target:{value:"8.8.8.8"}});fireEvent.change(screen.getByLabelText("Tunnel 1 PSK"),{target:{value:"Synthetic.Classic1"}});
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
 await waitFor(()=>expect(mock.post.mock.calls.some(([path])=>path.endsWith("/connections"))).toBe(true));
 const input=mock.post.mock.calls.find(([path])=>path.endsWith("/connections"))![1].body;
 expect(input.tunnel_ids).toHaveLength(1);expect(input.configuration.tunnels).toHaveLength(1);expect(input.configuration.profile_id).toBe("gcp-classic-static-ipv4-v1");expect(input.configuration.mode).toBe("ipv4-static");expect(input.configuration).not.toHaveProperty("bgp");
 expect(input.configuration.tunnels[0]).toMatchObject({inside_cidr:"",customer_inside_address:"",cloud_inside_address:""});
});
it("refuses to enable GCP from generic or AWS BGP readiness",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:{...bgpReadback,profile_id:"gcp-ha-bgp-ipv4-v1"}}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",bgp:{eligible:true,reason:"eligible"}}}:original(path,opts));
 render(view());await screen.findByRole("button",{name:"Office to cloud"});
 await waitFor(()=>expect(mock.get.mock.calls.some(([path])=>path.endsWith("/configuration"))).toBe(true));
 expect((await connectionMenu("Office to cloud")).queryByRole("menuitem",{name:"Enable Office to cloud"})).toBeNull();
});
it("reads GCP BGP configuration with Cloud Router labels and no PSK fields",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/configuration")?{data:{...bgpReadback,profile_id:"gcp-ha-bgp-ipv4-v1"}}:original(path,opts));
 render(view());fireEvent.click(await screen.findByRole("button",{name:"Office to cloud"}));
 await screen.findByText("Google Cloud · IPv4 BGP · revision 1");
 expect(screen.getByText("Cloud Router ASN")).toBeTruthy();expect(screen.queryByText("AWS ASN")).toBeNull();
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
});
it("enables GCP HA only with actual GCP and BGP capability and rechecks at action",async()=>{
 const original=mock.get.getMockImplementation()!;let supported=true;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:{...bgpReadback,profile_id:"gcp-ha-bgp-ipv4-v1"}}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",bgp:{eligible:true,reason:"eligible"},gcp_ha:{eligible:supported,reason:supported?"eligible":"unsupported"}}}:original(path,opts));
 render(view());fireEvent.click(await (await connectionMenu("Office to cloud")).findByRole("menuitem",{name:"Enable Office to cloud"}));
 supported=false;fireEvent.click(screen.getByRole("button",{name:"Enable connection"}));
 await screen.findByText("Gateway readiness changed. Close and refresh before enabling.");expect(mock.put).not.toHaveBeenCalled();
});
it("refuses GCP HA enable when GCP readiness exists but BGP readiness is stale",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:{...bgpReadback,profile_id:"gcp-ha-bgp-ipv4-v1"}}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",bgp:{eligible:false,reason:"report_stale"},gcp_ha:{eligible:true,reason:"eligible"}}}:original(path,opts));
 render(view());await screen.findByRole("button",{name:"Office to cloud"});
 await waitFor(()=>expect(mock.get.mock.calls.some(([path])=>path.endsWith("/configuration"))).toBe(true));
 expect((await connectionMenu("Office to cloud")).queryByRole("menuitem",{name:"Enable Office to cloud"})).toBeNull();
});
const classicReadback={...bgpReadback,profile_id:"gcp-classic-static-ipv4-v1",configuration:{...bgpReadback.configuration,mode:"ipv4-static",bgp:undefined,tunnels:[{outside_address:"8.8.8.8",inside_cidr:"",customer_inside_address:"",cloud_inside_address:""}]}};
it("enables Classic with exact one-tunnel capability without BGP, and rechecks before action",async()=>{
 const original=mock.get.getMockImplementation()!;let supported=true;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:classicReadback}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",gcp_classic:{eligible:supported,reason:supported?"eligible":"unsupported"}}}:original(path,opts));
 render(view());fireEvent.click(await (await connectionMenu("Office to cloud")).findByRole("menuitem",{name:"Enable Office to cloud"}));supported=false;
 fireEvent.click(screen.getByRole("button",{name:"Enable connection"}));await screen.findByText("Gateway readiness changed. Close and refresh before enabling.");expect(mock.put).not.toHaveBeenCalled();
});
it("refuses Classic activation from generic IPsec or HA-only readiness",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:classicReadback}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",bgp:{eligible:true,reason:"eligible"},gcp_ha:{eligible:true,reason:"eligible"}}}:original(path,opts));
 render(view());await screen.findByRole("button",{name:"Office to cloud"});await waitFor(()=>expect(mock.get.mock.calls.some(([path])=>path.endsWith("/configuration"))).toBe(true));expect((await connectionMenu("Office to cloud")).queryByRole("menuitem",{name:"Enable Office to cloud"})).toBeNull();
});
it("refuses Classic activation if public stored configuration contains two tunnels",async()=>{
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:{...classicReadback,configuration:{...classicReadback.configuration,tunnels:bgpReadback.configuration.tunnels}}}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",gcp_classic:{eligible:true,reason:"eligible"}}}:original(path,opts));
 render(view());await screen.findByRole("button",{name:"Office to cloud"});await waitFor(()=>expect(mock.get.mock.calls.some(([path])=>path.endsWith("/configuration"))).toBe(true));expect((await connectionMenu("Office to cloud")).queryByRole("menuitem",{name:"Enable Office to cloud"})).toBeNull();
});
it("switches Classic back to HA with two clean tunnel drafts",async()=>{
 render(view("gcp-ha-bgp-ipv4-v1"));await prepareBGPForm();fireEvent.change(screen.getByLabelText("Cloud VPN profile"),{target:{value:"gcp-classic-static-ipv4-v1"}});
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));fireEvent.change(screen.getByLabelText("Tunnel 1 PSK"),{target:{value:"Synthetic.Classic1"}});fireEvent.click(screen.getByRole("button",{name:"Back"}));
 fireEvent.change(screen.getByLabelText("Cloud VPN profile"),{target:{value:"gcp-ha-bgp-ipv4-v1"}});fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));
 expect(screen.getByLabelText("Tunnel 2 PSK")).toBeTruthy();expect(screen.getByLabelText("Tunnel 2 inside CIDR")).toBeTruthy();expect(screen.queryByDisplayValue("Synthetic.Classic1")).toBeNull();expect(mock.post).not.toHaveBeenCalled();
});

it.each(["azure-active-active-bgp-ipv4-v1", "azure-active-standby-bgp-ipv4-v1", "azure-active-active-static-ipv4-v1", "azure-active-standby-static-ipv4-v1"])("saves Azure %s with its independent topology and routing contract", async profile => {
 mock.post.mockImplementation(async (path:string, opts:any) => path.endsWith("configuration-check") ? {data:{valid:true}} : {data:{...record,id:opts.body.id}});
 render(view("azure-active-active-bgp-ipv4-v1")); await prepareBGPForm();
 fireEvent.change(screen.getByLabelText("Cloud VPN profile"), {target:{value:profile}});
 const dynamic = profile.includes("-bgp-"); const count = profile.includes("-standby-") ? 1 : 2;
 expect((screen.getByLabelText("Routing") as HTMLSelectElement).disabled).toBe(true);
 expect(screen.getByText(/Match the custom IKE/)).toBeTruthy();
 if(dynamic) expect((screen.getByLabelText("Azure gateway ASN") as HTMLInputElement).value).toBe("65515");
 else expect(screen.queryByLabelText("Azure gateway ASN")).toBeNull();
 fireEvent.click(screen.getByRole("button", {name:"Next: tunnels"}));
 for(let n=1;n<=count;n++) for(const [field,value] of Object.entries({"outside IP":n===1?"8.8.8.8":"1.1.1.1","inside CIDR":dynamic?"169.254.20.1/32":n===1?"169.254.21.0/30":"169.254.21.4/30","customer IP":dynamic?"169.254.20.1":n===1?"169.254.21.1":"169.254.21.5","cloud IP":n===1?"169.254.21.2":"169.254.21.6",PSK:"Synthetic.Azure_1"})) {
   const runtime=!dynamic&&field!=="outside IP"&&field!=="PSK"?"Tunnex runtime ":"";
   fireEvent.change(screen.getByLabelText(`Tunnel ${n} ${runtime}${field}`), {target:{value}});
 }
 if(count===1) expect(screen.queryByLabelText("Tunnel 2 outside IP")).toBeNull();
 expect(screen.queryByText(/GCP interface/)).toBeNull();
 fireEvent.click(screen.getByRole("button", {name:"Save disabled connection"}));
 await waitFor(()=>expect(mock.post.mock.calls.some(([path])=>path.endsWith("/connections"))).toBe(true));
 const body=mock.post.mock.calls.find(([path])=>path.endsWith("/connections"))![1].body;
 expect(body.tunnel_ids).toHaveLength(count); expect(body.configuration.tunnels).toHaveLength(count);
 expect(body.configuration.azure).toEqual({gateway_sku:"VpnGw1AZ",vpn_type:"RouteBased",ike_version:2,custom_policy:"aes256-sha256-dh14-pfs2048",use_policy_based_traffic_selectors:false,nat_enabled:false});
 expect(body.configuration.profile_id).toBe(profile); expect(body.configuration.mode).toBe(dynamic?"ipv4-bgp":"ipv4-static");
 if(count===1) expect(body.configuration).toMatchObject({transport_version:1,tunnel_count:1});
 if(!dynamic) expect(body.configuration).not.toHaveProperty("bgp");
});
it("refuses Azure enable from AWS or GCP BGP support alone", async () => {
 const original=mock.get.getMockImplementation()!;
 mock.get.mockImplementation(async(path:string,opts:any)=>path.endsWith("/connections")?{data:{items:[{...record,site_id:"site-a",gateway_node_id:"gateway-a"}],next_cursor:null}}:path.endsWith("/configuration")?{data:{...bgpReadback,profile_id:"azure-active-active-bgp-ipv4-v1"}}:path.endsWith("/eligibility")?{data:{eligible:true,reason:"eligible",bgp:{eligible:true},gcp_ha:{eligible:true}}}:original(path,opts));
 render(view()); await screen.findByRole("button", {name:"Office to cloud"});
 await waitFor(()=>expect(mock.get.mock.calls.some(([path])=>path.endsWith("/configuration"))).toBe(true));
 expect((await connectionMenu("Office to cloud")).queryByRole("menuitem", {name:"Enable Office to cloud"})).toBeNull();
});

it("imports bounded Tunnex Azure JSON only after preflight without saving or exposing its secret", async () => {
 mock.post.mockResolvedValue({data:{valid:true}});
 render(view("azure-active-active-bgp-ipv4-v1")); await prepareBGPForm();
 const configuration={...bgpReadback.configuration, profile_id:"azure-active-standby-bgp-ipv4-v1", transport_version:1,tunnel_count:1,
 azure:{gateway_sku:"VpnGw2AZ",vpn_type:"RouteBased",ike_version:2,custom_policy:"aes256-sha256-dh14-pfs2048",use_policy_based_traffic_selectors:false,nat_enabled:false},
 tunnels:[{outside_address:"8.8.8.8",inside_cidr:"169.254.20.1/32",customer_inside_address:"169.254.20.1",cloud_inside_address:"169.254.21.2",psk:"Synthetic.Import.Secret"}]};
 const file=new File([JSON.stringify(configuration)],"azure.json",{type:"application/json"}); Object.defineProperty(file,"text",{value:async()=>JSON.stringify(configuration)});
 fireEvent.change(screen.getByLabelText("Import Tunnex Azure JSON"),{target:{files:[file]}});
 await waitFor(()=>expect((screen.getByLabelText("Cloud VPN profile") as HTMLSelectElement).value).toBe(configuration.profile_id));
 expect((screen.getByLabelText("Azure VPN Gateway SKU") as HTMLSelectElement).value).toBe("VpnGw2AZ");
 expect(mock.post.mock.calls.every(([path])=>path.endsWith("configuration-check"))).toBe(true);
 expect(screen.queryByText("Synthetic.Import.Secret")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));
 expect((screen.getByLabelText("Tunnel 1 PSK") as HTMLInputElement).type).toBe("password");
 expect((screen.getByLabelText("Tunnel 1 PSK") as HTMLInputElement).value).toBe("Synthetic.Import.Secret");
 fireEvent.click(screen.getByRole("button",{name:"Cancel"}));
 fireEvent.click(screen.getByRole("button",{name:"New connection"}));
 expect(screen.queryByDisplayValue("Synthetic.Import.Secret")).toBeNull();
});
it("saves an imported Azure active-active draft only after a fresh check with manually replaced shared keys", async () => {
 mock.post.mockImplementation(async (path:string, opts:any) => path.endsWith("configuration-check") ? {data:{valid:true}} : {data:{...record,id:opts.body.id,name:opts.body.name}});
 const storage = vi.spyOn(Storage.prototype, "setItem");
 try {
  render(view("azure-active-active-bgp-ipv4-v1")); await prepareBGPForm();
  const imported = {profile_id:"azure-active-active-bgp-ipv4-v1",mode:"ipv4-bgp",
   azure:{gateway_sku:"VpnGw3AZ",vpn_type:"RouteBased",ike_version:2,custom_policy:"aes256-sha256-dh14-pfs2048",use_policy_based_traffic_selectors:false,nat_enabled:false},
   bgp:{local_asn:65017,remote_asn:65515,router_id:"10.10.0.17",maximum_prefixes:32},
   customer_outside_address:"9.9.9.9",local_prefixes:["10.10.0.0/16"],remote_prefixes:["10.20.0.0/16","10.21.0.0/24"],
   tunnels:["8.8.8.8","1.1.1.1"].map((outside_address,index)=>({outside_address,inside_cidr:"169.254.20.1/32",customer_inside_address:"169.254.20.1",cloud_inside_address:index===0?"169.254.21.2":"169.254.22.2",psk:"Synthetic.Import_Only"}))};
  const file = new File([JSON.stringify(imported)],"azure.json",{type:"application/json"});
  Object.defineProperty(file,"text",{value:async()=>JSON.stringify(imported)});
  fireEvent.change(screen.getByLabelText("Import Tunnex Azure JSON"),{target:{files:[file]}});
  await waitFor(()=>expect((screen.getByLabelText("Azure VPN Gateway SKU") as HTMLSelectElement).value).toBe("VpnGw3AZ"));
  expect(mock.post.mock.calls.map(([path])=>path)).toEqual(["/api/v1/organizations/{orgId}/ipsec/configuration-check"]);
  fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"}));
  for(const n of [1,2]) {
   const key=screen.getByLabelText(`Tunnel ${n} PSK`) as HTMLInputElement;
   expect(key.type).toBe("password");
   fireEvent.change(key,{target:{value:"Synthetic.Shared_Replacement"}});
  }
  expect(screen.getByRole("region",{name:"Connection review"}).textContent).not.toMatch(/Synthetic\./);
  const readsBeforeSave=mock.get.mock.calls.length;
  fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
  await waitFor(()=>expect(mock.post.mock.calls.filter(([path])=>path.endsWith("/connections"))).toHaveLength(1));
  const expected={...imported,tunnels:imported.tunnels.map(tunnel=>({...tunnel,psk:"Synthetic.Shared_Replacement"}))};
  const writes=mock.post.mock.calls;
  const freshEligibilityIndex=mock.get.mock.calls.findIndex(([path],index)=>index>=readsBeforeSave&&path.endsWith("/eligibility"));
  expect(freshEligibilityIndex).toBeGreaterThanOrEqual(0);
  expect(mock.get.mock.calls[freshEligibilityIndex][1]).toEqual({params:{path:{orgId:"org-a"},query:{site_id:"site-a",gateway_node_id:"gateway-a"}}});
  expect(mock.get.mock.invocationCallOrder[freshEligibilityIndex]).toBeLessThan(mock.post.mock.invocationCallOrder[1]);
  expect(writes.map(([path])=>path)).toEqual(["/api/v1/organizations/{orgId}/ipsec/configuration-check","/api/v1/organizations/{orgId}/ipsec/configuration-check","/api/v1/organizations/{orgId}/ipsec/connections"]);
  expect(writes[0][1].body).toEqual(imported);
  expect(writes[1][1].body).toEqual(expected);
  expect(writes[2][1].body).toMatchObject({name:"Office BGP",site_id:"site-a",gateway_node_id:"gateway-a",configuration:expected});
  expect(writes[2][1].body.tunnel_ids).toHaveLength(2);
  expect(new Set(writes[2][1].body.tunnel_ids).size).toBe(2);
  expect(mock.put).not.toHaveBeenCalled();
  expect(mock.del).not.toHaveBeenCalled();
  await waitFor(()=>expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull());
  expect(document.body.textContent).not.toMatch(/Synthetic\./);
  expect(storage.mock.calls.some(args=>args.some(value=>String(value).includes("Synthetic.")))).toBe(false);
 } finally { storage.mockRestore(); }
});
it.each(["oversized", "foreign-prefix", "unsupported-profile", "bad-json"])("refuses %s Azure JSON without preflight or echoed contents", async kind => {
 render(view("azure-active-active-bgp-ipv4-v1")); await prepareBGPForm();
 const config={...bgpReadback.configuration,profile_id:"azure-active-standby-bgp-ipv4-v1",azure:{},local_prefixes:kind==="foreign-prefix"?["10.99.0.0/16"]:["10.10.0.0/16"]};
 if(kind==="unsupported-profile") config.profile_id="azure-unsupported";
 const text=kind==="bad-json"?"Synthetic.Private.Secret":JSON.stringify(config);
 const file=new File([text],"azure.json"); Object.defineProperty(file,"text",{value:async()=>text}); if(kind==="oversized") Object.defineProperty(file,"size",{value:65537});
 fireEvent.change(screen.getByLabelText("Import Tunnex Azure JSON"),{target:{files:[file]}});
 await screen.findByText(/Azure JSON was not imported/);
 expect(mock.post).not.toHaveBeenCalled(); expect(screen.queryByText("Synthetic.Private.Secret")).toBeNull();
});
it("exports only explicit nonsecret Azure review fields, never arbitrary configuration fields", () => {
 const provider={...bgpReadback,profile_id:"azure-active-active-bgp-ipv4-v1",configuration:{...bgpReadback.configuration,azure:{gateway_sku:"VpnGw1AZ",vpn_type:"RouteBased",ike_version:2,custom_policy:"aes256-sha256-dh14-pfs2048",use_policy_based_traffic_selectors:false,nat_enabled:false,psk:"secret"},psk:"secret",tunnels:[{outside_address:"8.8.8.8",inside_cidr:"169.254.21.0/30",customer_inside_address:"169.254.21.1",cloud_inside_address:"169.254.21.2",psk:"secret"}]}};
 const text=JSON.stringify(azureSettingsReview(provider as any)); expect(text).not.toContain("secret"); expect(text).not.toContain("psk"); expect(text).toContain("VpnGw1AZ");
});
it.each(["psk", "customer-prefix"])("refuses inconsistent Azure active-active %s before preflight", async kind => {
 render(view("azure-active-active-bgp-ipv4-v1")); await prepareBGPForm();
 fireEvent.change(screen.getByLabelText("Cloud VPN profile"),{target:{value:"azure-active-active-bgp-ipv4-v1"}});
 fireEvent.click(screen.getByRole("button",{name:"Next: tunnels"})); fillBGPTunnels();
 if(kind==="customer-prefix") for(const n of [1,2]) fireEvent.change(screen.getByLabelText(`Tunnel ${n} PSK`),{target:{value:"Synthetic.SharedAzure"}});
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
 await screen.findByText(kind==="psk"?/must use the same PSK/:/same customer APIPA address and its \/32/);
 expect(mock.post).not.toHaveBeenCalled();
});

it("resets the creation draft if its provider context changes", async()=>{
 const {rerender}=render(view("gcp-ha-bgp-ipv4-v1"));await prepareBGPForm();
 expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("Office BGP");
 rerender(view("aws"));
 expect((screen.getByLabelText("Name") as HTMLInputElement).value).toBe("");
 expect((screen.getByLabelText("Local network") as HTMLSelectElement).value).toBe("");
 expect(Array.from((screen.getByLabelText("Cloud VPN profile") as HTMLSelectElement).options).map(o=>o.value)).toEqual(["aws"]);
 expect(screen.queryByLabelText("Import Tunnex Azure JSON")).toBeNull();
 expect((screen.getByLabelText("Routing") as HTMLSelectElement).disabled).toBe(false);
});


async function uploadAWS(text = awsGeneric(), read?: () => Promise<string>) {
 const file = new File([text], "synthetic-vpn.txt", { type: "text/plain" });
 Object.defineProperty(file, "text", { value: read ?? (() => Promise.resolve(text)) });
 fireEvent.change(screen.getByLabelText("Import AWS Generic configuration"), { target: { files: [file] } });
}
async function prepareAWSImport(mode: "bgp" | "static" = "bgp", matchingCrypto = false, peer = "Virtual Private Gateway") {
 fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 await uploadAWS(awsGeneric({ mode, matchingCrypto, peer }));
 await screen.findByRole("region", { name: "AWS import review" });
 fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
 fireEvent.change(await screen.findByLabelText("Gateway"), { target: { value: "gateway-a" } });
 fireEvent.click(await screen.findByLabelText("10.10.0.0/16"));
 fireEvent.change(screen.getByLabelText("Remote network ranges"), { target: { value: "10.20.0.0/16" } });
 await waitFor(() => expect(screen.getByRole("button", { name: "Next: tunnels" })).toHaveProperty("disabled", false));
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" }));
}
const awsAcknowledgment = /I have verified that both AWS tunnels allow/;
it.each(["bgp", "static"] as const)("imports AWS Generic %s into a masked disabled draft with explicit ranges", async mode => {
 const setStorage = vi.spyOn(Storage.prototype, "setItem");
 mock.post.mockImplementation(async (path: string, opts: any) => path.endsWith("configuration-check") ? { data: { valid: true } } : { data: { ...record, id: opts.body.id, name: opts.body.name } });
 render(view()); await prepareAWSImport(mode);
 expect(screen.getByLabelText("Tunnel 1 PSK")).toHaveProperty("type", "password");
 expect(screen.getByLabelText("Tunnel 1 PSK")).toHaveProperty("value", "Synthetic.PSK_1");
 expect(screen.getByLabelText("Tunnel 2 cloud IP")).toHaveProperty("value", "169.254.12.1");
 expect(screen.getByRole("region", { name: "AWS import review" }).textContent).toContain("algorithms different");
 expect(screen.getByRole("region", { name: "Connection review" }).textContent).not.toContain("Synthetic");
 expect(screen.getByRole("button", { name: "Create and connect…" })).toHaveProperty("disabled", true);
 expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled(); expect(setStorage).not.toHaveBeenCalled(); setStorage.mockRestore();
 fireEvent.click(screen.getByRole("button", { name: "Save disabled connection" }));
 await waitFor(() => expect(mock.post.mock.calls.filter(([path]) => path.endsWith("/connections"))).toHaveLength(1));
 const configuration = mock.post.mock.calls.find(([path]) => path.endsWith("/connections"))![1].body.configuration;
 expect(configuration.mode).toBe(`ipv4-${mode}`); expect(configuration.local_prefixes).toEqual(["10.10.0.0/16"]); expect(configuration.remote_prefixes).toEqual(["10.20.0.0/16"]);
 if (mode === "bgp") expect(configuration.bgp).toEqual({ local_asn: 65010, remote_asn: 64512, router_id: "9.9.9.9", maximum_prefixes: 64 });
 expect(configuration).not.toHaveProperty("crypto"); expect(configuration).not.toHaveProperty("attachment"); expect(mock.put).not.toHaveBeenCalled();
 await waitFor(() => expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull());
});
it("preserves chosen context, explicit name/router ID and scopes when importing", async () => {
 render(view()); await prepareBGPForm();
 await uploadAWS(); await screen.findByRole("region", { name: "AWS import review" });
 expect(screen.getByLabelText("Name")).toHaveProperty("value", "Office BGP"); expect(screen.getByLabelText("Router ID")).toHaveProperty("value", "10.10.0.1");
 expect(screen.getByLabelText("Local network")).toHaveProperty("value", "site-a"); expect(screen.getByLabelText("Gateway")).toHaveProperty("value", "gateway-a");
 expect(screen.getByLabelText("10.10.0.0/16")).toHaveProperty("checked", true); expect(screen.getByLabelText("Remote network ranges")).toHaveProperty("value", "10.20.0.0/16");
});
it("requires explicit ranges after import, even for a static sample with a default route", async () => {
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "New connection" })); await uploadAWS(awsGeneric({ mode: "static" }));
 await screen.findByRole("region", { name: "AWS import review" });
 expect(screen.getByLabelText("Remote network ranges")).toHaveProperty("value", ""); expect(screen.getByLabelText("Local network")).toHaveProperty("value", "");
 expect(screen.getByRole("button", { name: "Next: tunnels" })).toHaveProperty("disabled", true); expect(mock.post).not.toHaveBeenCalled();
});
it("requires acknowledgment even for matching algorithms and clears it after manual tunnel edits", async () => {
 render(view()); await prepareAWSImport("static", true);
 expect(screen.getByRole("region", { name: "AWS import review" }).textContent).toContain("Actual AWS tunnel options");
 const connect = screen.getByRole("button", { name: "Create and connect…" }); expect(connect).toHaveProperty("disabled", true);
 fireEvent.click(screen.getByLabelText(awsAcknowledgment)); expect(connect).toHaveProperty("disabled", false);
 fireEvent.change(screen.getByLabelText("Tunnel 1 outside IP"), { target: { value: "8.8.4.4" } });
 expect(screen.getByLabelText(awsAcknowledgment)).toHaveProperty("checked", false); expect(connect).toHaveProperty("disabled", true);
});
it("refuses stale import completion after local context changes or cancellation", async () => {
 const deferred: { resolve?: (value: string) => void } = {};
 const result = new Promise<string>(resolve => { deferred.resolve = resolve; });
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 await uploadAWS(awsGeneric(), () => result);
 fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
 await act(async () => deferred.resolve!(awsGeneric()));
 expect(screen.queryByRole("region", { name: "AWS import review" })).toBeNull(); expect(screen.getByLabelText("Customer public IP")).toHaveProperty("value", "");
 let complete!: (value: string) => void;
 await uploadAWS(awsGeneric(), () => new Promise(resolve => { complete = resolve; }));
 fireEvent.click(screen.getByRole("button", { name: "Cancel" })); await act(async () => complete(awsGeneric()));
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull(); expect(mock.post).not.toHaveBeenCalled(); expect(mock.put).not.toHaveBeenCalled();
});
it("keeps prior draft and reports redacted error when a replacement upload fails", async () => {
 render(view()); await prepareAWSImport("static"); fireEvent.click(screen.getByLabelText(awsAcknowledgment));
 fireEvent.click(screen.getByRole("button", { name: "Back" }));
 await uploadAWS(awsGeneric().replace("IKEv2", "secret-certificate"));
 await screen.findByText(/Tunnex requires IKEv2 with pre-shared keys/);
 expect(screen.getByLabelText("Routing")).toHaveProperty("value", "ipv4-static");
 fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" }));
 expect(screen.getByLabelText("Tunnel 1 PSK")).toHaveProperty("value", "Synthetic.PSK_1"); expect(screen.getByLabelText(awsAcknowledgment)).toHaveProperty("checked", false);
 expect(document.body.textContent).not.toContain("secret-certificate"); expect(mock.post).not.toHaveBeenCalled();
});
it.each(["success", "unsupported", "uncertain", "conflict"] as const)("keeps one saved ID through final AWS enable %s", async outcome => {
 const original = mock.get.getMockImplementation()!;
 let created: any; let ready = true;
 mock.get.mockImplementation(async (path: string, opts: any) => {
  if (path.endsWith("/eligibility")) return { data: { eligible: true, reason: "eligible", bgp: { eligible: ready, reason: ready ? "eligible" : "unsupported" } } };
  if (path.endsWith("/configuration")) return { data: bgpReadback };
  if (path.endsWith("/connections") && created) return { data: { items: [created], next_cursor: null } };
  if (path.endsWith("/{connectionId}") && created) return { data: created };
  return original(path, opts);
 });
 mock.post.mockImplementation(async (path: string, opts: any) => {
  if (path.endsWith("configuration-check")) return { data: { valid: true } };
  created = { ...record, id: opts.body.id, name: opts.body.name, site_id: "site-a", gateway_node_id: "gateway-a", desired_revision: 7 };
  return { data: created };
 });
 mock.put.mockImplementation(async () => outcome === "success" ? { data: { ...created, desired_intent: "enabled", desired_revision: 8 } } : { error: {}, response: { status: outcome === "conflict" ? 409 : 503 } });
 render(view()); await prepareAWSImport(); fireEvent.click(screen.getByLabelText(awsAcknowledgment));
 fireEvent.click(screen.getByRole("button", { name: "Create and connect…" }));
 const enable = await screen.findByRole("button", { name: "Enable connection" });
 expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull(); expect(mock.put).not.toHaveBeenCalled();
 if (outcome === "unsupported") ready = false;
 fireEvent.click(enable);
 if (outcome === "unsupported") { await screen.findByText("Gateway readiness changed. Close and refresh before enabling."); expect(mock.put).not.toHaveBeenCalled(); }
 else {
  await waitFor(() => expect(mock.put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/intent", { params: { path: { orgId: "org-a", connectionId: created.id }, header: { "If-Match": '\"7\"' } }, body: { intent: "enabled" } }));
  if (outcome !== "success") { await screen.findByText("Could not confirm the change. Close and refresh before retrying."); expect(enable).toHaveProperty("disabled", true); fireEvent.click(enable); expect(mock.put).toHaveBeenCalledTimes(1); }
 }
 expect(mock.post.mock.calls.filter(([path]) => path.endsWith("/connections"))).toHaveLength(1); expect(screen.queryByText("Connected")).toBeNull();
});
it("recovers a lost create response into the saved connection's final enable review", async () => {
 const original = mock.get.getMockImplementation()!; let created: any;
 mock.get.mockImplementation(async (path: string, opts: any) => path.endsWith("/{connectionId}") && created ? { data: created } : original(path, opts));
 mock.post.mockImplementation(async (path: string, opts: any) => {
  if (path.endsWith("configuration-check")) return { data: { valid: true } };
  created = { ...record, id: opts.body.id, name: opts.body.name, site_id: "site-a", gateway_node_id: "gateway-a" }; throw new Error("synthetic lost response");
 });
 render(view()); await prepareAWSImport("static"); fireEvent.click(screen.getByLabelText(awsAcknowledgment)); fireEvent.click(screen.getByRole("button", { name: "Create and connect…" }));
 await screen.findByRole("button", { name: "Enable connection" });
 expect(mock.post.mock.calls.filter(([path]) => path.endsWith("/connections"))).toHaveLength(1); expect(mock.put).not.toHaveBeenCalled(); expect(screen.queryByLabelText("Tunnel 1 PSK")).toBeNull();
});

it.each(["bgp", "static"] as const)("reviews a Transit Gateway labeled %s file without inventing attachment metadata", async mode => {
 render(view()); await prepareAWSImport(mode, false, "Transit Gateway");
 expect(screen.getByRole("region", { name: "Connection review" }).textContent).toContain(mode === "bgp" ? "Dynamic routing (BGP)" : "Static routes");
 expect(screen.getByLabelText("Tunnel 1 cloud IP")).toHaveProperty("value", "169.254.11.1");
 expect(screen.getByRole("button", { name: "Create and connect…" })).toHaveProperty("disabled", true); expect(mock.post).not.toHaveBeenCalled();
});
it("rejects oversized AWS input before reading it", async () => {
 render(view()); fireEvent.click(await screen.findByRole("button", { name: "New connection" }));
 const file = new File(["x".repeat(65537)], "too-large.txt", { type: "text/plain" }); const read = vi.fn(); Object.defineProperty(file, "text", { value: read });
 fireEvent.change(screen.getByLabelText("Import AWS Generic configuration"), { target: { files: [file] } });
 await screen.findByText("Choose a nonempty AWS Generic text file no larger than 64 KiB.");
 expect(read).not.toHaveBeenCalled(); expect(mock.post).not.toHaveBeenCalled(); expect(screen.queryByRole("region", { name: "AWS import review" })).toBeNull();
});
it("uses the existing configuration validator before saving imported data", async () => {
 mock.post.mockResolvedValue({ data: { valid: false }, error: {} }); render(view()); await prepareAWSImport("static");
 fireEvent.click(screen.getByRole("button", { name: "Save disabled connection" }));
 await screen.findByText("Check the addresses, ranges and credentials before saving.");
 expect(mock.post.mock.calls.filter(([path]) => path.endsWith("/configuration-check"))).toHaveLength(1);
 expect(mock.post.mock.calls.filter(([path]) => path.endsWith("/connections"))).toHaveLength(0); expect(mock.put).not.toHaveBeenCalled();
});

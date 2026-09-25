import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const mock = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: mock }));
import { IPsecWorkspace } from "../src/components/IPsecWorkspace";
const record = { id: "connection-a", name: "Office cloud", desired_intent: "disabled", desired_revision: 4, cleanup_state: "retained_guard" };
const props = { orgId: "org-a", userId: "user-a", emailVerified: true, role: "owner", sites: [] };
const view = (overrides = {}) => <MemoryRouter><IPsecWorkspace {...props} {...overrides} /></MemoryRouter>;
beforeEach(() => {
 Object.values(mock).forEach(m => m.mockReset());
 mock.GET.mockImplementation(async (path: string) => {
  if(path.endsWith("/settings")) return {data:{enabled:false,revision:1}};
  if(path.endsWith("/connections")) return {data:{items:[record]}};
  if(path.endsWith("/status")) return {data:{tunnels:[{id:"tunnel-a",slot:1,status:"unknown",selected:true},{id:"tunnel-b",slot:2,status:"unknown",selected:false}]}};
  return {data:record};
 });
 mock.POST.mockResolvedValue({data:{...record,desired_revision:5}});
});
afterEach(cleanup);
async function open() {
 fireEvent.click(await screen.findByRole("button",{name:"Rotate keys for Office cloud"}));
 await screen.findByLabelText("Tunnel 1 new PSK");
}
it("rotates one write-only key with exact revision and stays disabled", async()=>{
 render(view()); await open();
 const input=screen.getByLabelText("Tunnel 1 new PSK"); expect(input.getAttribute("type")).toBe("password");
 fireEvent.change(input,{target:{value:"Synthetic.PrivateKey1"}});
 fireEvent.click(screen.getByRole("button",{name:"Save new keys"}));
 await waitFor(()=>expect(mock.POST).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/ipsec/connections/{connectionId}/rotate-psks",expect.objectContaining({body:{expected_desired_revision:4,tunnels:[{tunnel_id:"tunnel-a",psk:"Synthetic.PrivateKey1"}]}})));
 await screen.findByText(/Keys saved/); expect(screen.queryByDisplayValue("Synthetic.PrivateKey1")).toBeNull(); expect(mock.PUT).not.toHaveBeenCalled();
});
it("can rotate both keys but never sends an empty partner", async()=>{
 render(view()); await open();
 for(const n of [1,2])fireEvent.change(screen.getByLabelText(`Tunnel ${n} new PSK`),{target:{value:`Synthetic.PrivateKey${n}`}});
 fireEvent.click(screen.getByRole("button",{name:"Save new keys"}));
 await waitFor(()=>expect(mock.POST).toHaveBeenCalled()); expect(mock.POST.mock.calls[0][1].body.tunnels).toHaveLength(2);
});
it.each(["enabled","deleted"])("hides rotation for %s connections",async intent=>{
 const original=mock.GET.getMockImplementation()!; mock.GET.mockImplementation((path:string)=>path.endsWith("/connections")?Promise.resolve({data:{items:[{...record,desired_intent:intent}]}}):original(path));
 render(view()); await screen.findByRole("button",{name:"Office cloud"}); expect(screen.queryByRole("button",{name:/Rotate keys/})).toBeNull();
});
it("hides rotation while cleanup is pending and for members",async()=>{
 const original=mock.GET.getMockImplementation()!; mock.GET.mockImplementation((path:string)=>path.endsWith("/connections")?Promise.resolve({data:{items:[{...record,cleanup_state:"pending"}]}}):original(path));
 const r=render(view()); await screen.findByRole("button",{name:"Office cloud"}); expect(screen.queryByRole("button",{name:/Rotate keys/})).toBeNull();
 mock.GET.mockImplementation(original); r.rerender(view({role:"member"})); await screen.findByRole("button",{name:"Office cloud"}); expect(screen.queryByRole("button",{name:/Rotate keys/})).toBeNull();
});
it.each([{orgId:"org-b"},{userId:"user-b"},{role:"member"},{emailVerified:false}])("clears drafts on authority change %j",async change=>{
 const r=render(view()); await open(); fireEvent.change(screen.getByLabelText("Tunnel 1 new PSK"),{target:{value:"Synthetic.PrivateKey1"}}); r.rerender(view(change)); expect(screen.queryByDisplayValue("Synthetic.PrivateKey1")).toBeNull(); expect(mock.POST).not.toHaveBeenCalled();
});
it("clears keys and prevents retry on uncertain response",async()=>{
 mock.POST.mockRejectedValue(new Error("Synthetic.PrivateKey1")); render(view()); await open(); fireEvent.change(screen.getByLabelText("Tunnel 1 new PSK"),{target:{value:"Synthetic.PrivateKey1"}}); fireEvent.click(screen.getByRole("button",{name:"Save new keys"})); await screen.findByText(/Could not confirm/); expect(screen.queryByDisplayValue("Synthetic.PrivateKey1")).toBeNull(); expect(screen.queryByText("Synthetic.PrivateKey1")).toBeNull(); expect((screen.getByRole("button",{name:"Save new keys"})as HTMLButtonElement).disabled).toBe(true);
});
it("refuses changed connection revision before exposing the draft",async()=>{
 const original=mock.GET.getMockImplementation()!; mock.GET.mockImplementation((path:string)=>path.endsWith("/{connectionId}")?Promise.resolve({data:{...record,desired_revision:5}}):original(path)); render(view()); fireEvent.click(await screen.findByRole("button",{name:/Rotate keys/})); await screen.findByText(/Connection changed/); expect(screen.queryByLabelText("Tunnel 1 new PSK")).toBeNull(); expect(mock.POST).not.toHaveBeenCalled();
});
it("ignores late rotation success after organization changes",async()=>{
 let finish:(v:unknown)=>void=()=>{}; mock.POST.mockImplementation(()=>new Promise(resolve=>{finish=resolve;})); const r=render(view()); await open(); fireEvent.change(screen.getByLabelText("Tunnel 1 new PSK"),{target:{value:"Synthetic.PrivateKey1"}}); fireEvent.click(screen.getByRole("button",{name:"Save new keys"})); await waitFor(()=>expect(mock.POST).toHaveBeenCalled()); r.rerender(view({orgId:"org-b"})); await act(async()=>finish({data:{...record,desired_revision:5}})); expect(screen.queryByText(/Keys saved/)).toBeNull();
});
it("clears cancelled drafts without storing keys",async()=>{
 const storage=vi.spyOn(Storage.prototype,"setItem"); render(view()); await open(); fireEvent.change(screen.getByLabelText("Tunnel 1 new PSK"),{target:{value:"Synthetic.PrivateKey1"}}); fireEvent.click(screen.getByRole("button",{name:"Close"})); expect(screen.queryByDisplayValue("Synthetic.PrivateKey1")).toBeNull(); await open(); expect((screen.getByLabelText("Tunnel 1 new PSK")as HTMLInputElement).value).toBe(""); expect(mock.POST).not.toHaveBeenCalled(); expect(storage).not.toHaveBeenCalled(); storage.mockRestore();
});
it("refuses ambiguous tunnel identities",async()=>{
 const original=mock.GET.getMockImplementation()!; mock.GET.mockImplementation((path:string)=>path.endsWith("/status")?Promise.resolve({data:{tunnels:[{id:"same",slot:1},{id:"same",slot:2}]}}):original(path)); render(view()); fireEvent.click(await screen.findByRole("button",{name:/Rotate keys/})); await screen.findByText(/Could not load tunnel identities/); expect(screen.queryByLabelText("Tunnel 1 new PSK")).toBeNull();
});
it("submits only once while a rotation is in flight",async()=>{
 mock.POST.mockImplementation(()=>new Promise(()=>{})); render(view()); await open(); fireEvent.change(screen.getByLabelText("Tunnel 1 new PSK"),{target:{value:"Synthetic.PrivateKey1"}}); const submit=screen.getByRole("button",{name:"Save new keys"}); fireEvent.click(submit); fireEvent.click(submit); await waitFor(()=>expect(mock.POST).toHaveBeenCalledTimes(1)); expect((screen.getByLabelText("Tunnel 1 new PSK")as HTMLInputElement).value).toBe("");
});
it("does not offer rotation when successor revision cannot be represented safely",async()=>{
 const original=mock.GET.getMockImplementation()!; mock.GET.mockImplementation((path:string)=>path.endsWith("/connections")?Promise.resolve({data:{items:[{...record,desired_revision:Number.MAX_SAFE_INTEGER}]}}):original(path)); render(view()); await screen.findByRole("button",{name:"Office cloud"}); expect(screen.queryByRole("button",{name:/Rotate keys/})).toBeNull();
});

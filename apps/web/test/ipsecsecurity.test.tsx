import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { Site } from "../src/lib/api";
const apiMock = vi.hoisted(() => ({ GET: vi.fn(), POST: vi.fn(), PUT: vi.fn(), DELETE: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: apiMock }));
import { IPsecWorkspace } from "../src/components/IPsecWorkspace";
const sites = [{ id: "site-a", name: "Office" }] as Site[];
const props = { orgId: "org-a", userId: "user-a", emailVerified: true, role: "owner", sites };
const view = (overrides: Partial<typeof props> = {}) => <MemoryRouter><IPsecWorkspace {...props} {...overrides} /></MemoryRouter>;
beforeEach(() => {
  Object.values(apiMock).forEach(mock => mock.mockReset());
  apiMock.GET.mockImplementation(async (path: string) => {
    if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
    if (path.endsWith("/connections")) return { data: { items: [], next_cursor: null } };
    if (path.endsWith("/nodes")) return { data: [{ id: "gateway-a", site_id: "site-a", name: "Office gateway", status: "active" }] };
    if (path.endsWith("/subnets")) return { data: [{ id: "range-a", cidr: "10.10.0.0/16", status: "approved" }] };
    if (path.endsWith("/eligibility")) return { data: { eligible: true, reason: "eligible" } };
    return { error: { error: { message: "Not found" } } };
  });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function openDraft() {
  fireEvent.click(await screen.findByRole("button", { name: /new connection/i }));
  fireEvent.change(await screen.findByLabelText("Name"), { target: { value: "Office cloud" } });
  fireEvent.change(screen.getByLabelText("Local network"), { target: { value: "site-a" } });
  fireEvent.change(await screen.findByLabelText("Gateway"), { target: { value: "gateway-a" } });
  fireEvent.change(screen.getByLabelText("Customer public IP"), { target: { value: "9.9.9.9" } });
  fireEvent.change(screen.getByLabelText("Remote network ranges"), { target: { value: "10.20.0.0/16" } });
  fireEvent.click(await screen.findByRole("checkbox", { name: "10.10.0.0/16" }));
  fireEvent.click(screen.getByRole("button", { name: "Next: tunnels" }));
  const inputs = await screen.findAllByLabelText(/PSK/i);
  expect(inputs).toHaveLength(2);
  inputs.forEach((input, i) => fireEvent.change(input, { target: { value: `Private.Synthetic_PSK${i}` } }));
}
it.each([
  ["organization", { orgId: "org-b" }],
  ["user", { userId: "user-b" }],
  ["verification", { emailVerified: false }],
  ["role", { role: "member" }],
] as const)("withdraws secret draft synchronously on %s change", async (_name, change) => {
  const result = render(view());
  await openDraft();
  result.rerender(view(change));
  expect(screen.queryByDisplayValue("Private.Synthetic_PSK0")).toBeNull();
  expect(screen.queryByDisplayValue("Private.Synthetic_PSK1")).toBeNull();
  expect(apiMock.POST).not.toHaveBeenCalled();
});
it("does not grant IPsec management through site-manager or unverified roles", async () => {
  const result = render(view({ role: "site_manager" }));
  await screen.findByRole("heading", { name: /IPsec/i });
  expect(screen.queryByRole("button", { name: /new connection/i })).toBeNull();
  result.rerender(view({ role: "owner", emailVerified: false }));
  expect(screen.queryByRole("button", { name: /new connection/i })).toBeNull();
});
it("keeps PSKs password-only and out of browser persistent storage", async () => {
  const storage = vi.spyOn(Storage.prototype, "setItem");
  render(view());
  await openDraft();
  for (const input of screen.getAllByLabelText(/PSK/i)) expect(input.getAttribute("type")).toBe("password");
  for (const args of storage.mock.calls) expect(JSON.stringify(args)).not.toContain("Private.Synthetic_PSK");
  expect(screen.queryByText("Private.Synthetic_PSK0")).toBeNull();
});

function fillTunnels() {
 for (const [slot,outside,inside,customer,cloud] of [[1,"8.8.8.8","169.254.10.0/30","169.254.10.2","169.254.10.1"],[2,"1.1.1.1","169.254.10.4/30","169.254.10.5","169.254.10.6"]]) {
  for (const [label,value] of [["outside IP",outside],["inside CIDR",inside],["customer IP",customer],["cloud IP",cloud]]) fireEvent.change(screen.getByLabelText(`Tunnel ${slot} ${label}`),{target:{value}});
 }
}
it("ignores a late create success after organization changes", async () => {
 let complete: (value: unknown) => void = () => {};
 apiMock.POST.mockImplementation((path:string) => path.endsWith("/configuration-check") ? Promise.resolve({data:{valid:true}}) : new Promise(resolve=>{complete=resolve;}));
 const result=render(view()); await openDraft(); fillTunnels();
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
 await waitFor(()=>expect(apiMock.POST.mock.calls.some(([path])=>path.endsWith("/connections"))).toBe(true));
 result.rerender(view({orgId:"org-b"}));
 await act(async()=>{complete({data:{id:"old-created-connection"}});});
 expect(screen.queryByDisplayValue("Private.Synthetic_PSK0")).toBeNull();
 expect(apiMock.GET.mock.calls.some(([,opts])=>opts?.params?.path?.orgId==="org-b" && opts?.params?.path?.connectionId==="old-created-connection")).toBe(false);
 expect(screen.queryByText("Stored configuration")).toBeNull();
});
it("keeps the original IDs and secret payload after uncertain save and refused retry", async () => {
 let creates=0;
 apiMock.POST.mockImplementation(async(path:string)=>{
  if(path.endsWith("/configuration-check")) return {data:{valid:true}};
  creates++; if(creates===1)throw new Error("lost response");
  return {error:{error:{message:"server secret must not render"}},response:{status:403}};
 });
 render(view());await openDraft();fillTunnels();
 fireEvent.click(screen.getByRole("button",{name:"Save disabled connection"}));
 fireEvent.click(await screen.findByRole("button",{name:"Retry save"}));
 await waitFor(()=>expect(creates).toBe(2));
 await screen.findByRole("button",{name:"Retry save"});
 const requests=apiMock.POST.mock.calls.filter(([path])=>path.endsWith("/connections")).map(([,opts])=>opts.body);
 expect(requests).toHaveLength(2);expect(requests[1]).toEqual(requests[0]);
 expect(requests[0].tunnel_ids).toHaveLength(2);expect(new Set([requests[0].id,...requests[0].tunnel_ids]).size).toBe(3);
 expect(screen.getByLabelText("Tunnel 1 PSK").closest("fieldset")?.disabled).toBe(true);
 expect(screen.queryByText("server secret must not render")).toBeNull();
});

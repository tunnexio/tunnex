import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { Node, Site } from "../src/lib/api";
const mock = vi.hoisted(() => ({ get: vi.fn() }));
vi.mock("../src/lib/api", async original => ({ ...await original<object>(), api: { GET: mock.get } }));
import { SitePairReview, SitePairDetails, SitePairConfigurationView } from "../src/components/SitePairReview";
const a: Site = { id: "a", name: "Office", link_transport: "wireguard", created_at: "2026-09-24T00:00:00Z" };
const b: Site = { ...a, id: "b", name: "Cloud" };
const c: Site = { ...a, id: "c", name: "Another office" };
afterEach(cleanup);
beforeEach(() => { mock.get.mockReset(); });
it("requires distinct sites and clears the other selection when it becomes identical", () => {
  render(<MemoryRouter><SitePairReview sites={[a,b,c]} renderDetails={(first,second)=><p>{first.name} to {second.name}</p>} /></MemoryRouter>);
  fireEvent.change(screen.getByLabelText("First network"), {target:{value:"a"}});
  expect(within(screen.getByLabelText("Second network")).queryByRole("option",{name:/^Office$/})).toBeNull();
  fireEvent.change(screen.getByLabelText("Second network"), {target:{value:"b"}});
  expect(screen.getByText("Office to Cloud")).toBeTruthy();
  fireEvent.change(screen.getByLabelText("First network"), {target:{value:"b"}});
  expect(screen.queryByText("Office to Cloud")).toBeNull();
  expect((screen.getByLabelText("Second network") as HTMLSelectElement).value).toBe("");
});
it("keeps unavailable data distinct from absent gateways and ranges", () => {
  render(<MemoryRouter><SitePairConfigurationView first={a} second={b} onRetry={()=>{}} data={{nodes:{ok:false,error:"Unavailable"},firstRanges:{ok:false,error:"Unavailable"},secondRanges:{ok:true,data:[]}}}/></MemoryRouter>);
  expect(screen.queryByText("No gateway assigned.")).toBeNull();
  const office = screen.getByRole("region",{name:"Office configuration"});
  expect(within(office).queryByText("No network ranges advertised.")).toBeNull();
  expect(screen.getByRole("button",{name:"Retry configuration"})).toBeTruthy();
  expect(screen.getByText(/Traffic between these networks has not been verified/)).toBeTruthy();
});
it("reads only selected subnet lists and retries failed configuration", async () => {
  let failing = true;
  mock.get.mockImplementation(async (path:string,opts:{params:{path:{siteId?:string}}}) => path.endsWith("/nodes")
    ? {data:[]}
    : failing ? {error:{}} : {data:[{id:'range',site_id:opts.params.path.siteId,cidr:'10.20.0.0/24',status:'approved'}]});
  render(<MemoryRouter><SitePairDetails orgId="org" first={a} second={b}/></MemoryRouter>);
  await screen.findByRole("button",{name:"Retry configuration"});
  expect(mock.get.mock.calls.filter(([path])=>path.endsWith('/subnets')).map(([,opts])=>opts.params.path.siteId)).toEqual(['a','b']);
  failing=false;
  fireEvent.click(screen.getByRole("button",{name:"Retry configuration"}));
  await screen.findAllByText('10.20.0.0/24');
  expect(screen.queryByRole("button",{name:"Retry configuration"})).toBeNull();
});
it("discards old pair results when selection changes", async () => {
  let resolveA: (value: unknown)=>void = ()=>{};
  mock.get.mockImplementation((path:string,opts:{params:{path:{siteId?:string}}}) => {
    if(path.endsWith('/nodes')) return Promise.resolve({data:[]});
    if(opts.params.path.siteId==='a') return new Promise(resolve=>{resolveA=resolve;});
    return Promise.resolve({data:[]});
  });
  const view=render(<MemoryRouter><SitePairDetails orgId="org" first={a} second={b}/></MemoryRouter>);
  view.rerender(<MemoryRouter><SitePairDetails orgId="org" first={c} second={b}/></MemoryRouter>);
  await screen.findByRole('region',{name:'Another office configuration'});
  await act(async()=>resolveA({data:[{id:'old',site_id:'a',cidr:'10.99.0.0/24',status:'approved'}]}));
  expect(screen.queryByText('10.99.0.0/24')).toBeNull();
  expect(screen.queryByRole('region',{name:'Office configuration'})).toBeNull();
});

function renderGateway(diagnostics: Partial<Node> = {}) {
  const gateway = { id: "gateway", name: "Office gateway", site_id: a.id, status: "active", ...diagnostics } as Node;
  render(<MemoryRouter><SitePairConfigurationView first={a} second={b} onRetry={() => {}} data={{
    nodes: { ok: true, data: [gateway] },
    firstRanges: { ok: true, data: [] },
    secondRanges: { ok: true, data: [] },
  }} /></MemoryRouter>);
  return within(screen.getByRole("region", { name: "Office configuration" }));
}

it("shows the reported site-link diagnosis beside a registered gateway", () => {
  const office = renderGateway({ policy_degraded: true, policy_degraded_kind: "site_link_down" });
  expect(office.getByText("site link down")).toBeTruthy();
  expect(office.getByText(/Registered/)).toBeTruthy();
  expect(screen.getByText(/Traffic between these networks has not been verified/)).toBeTruthy();
});

it("preserves a generic degraded diagnosis for a server kind unknown to this client", () => {
  const office = renderGateway({ policy_degraded: true, policy_degraded_kind: "future_server_kind" as Node["policy_degraded_kind"] });
  expect(office.getByText("degraded")).toBeTruthy();
});

it("does not infer health or connectivity from absent gateway diagnostics", () => {
  const office = renderGateway();
  expect(office.getByText(/Registered/)).toBeTruthy();
  expect(office.queryByText(/healthy|connected|degraded|site link down/i)).toBeNull();
  expect(office.getByText("Last report: Not reported")).toBeTruthy();
});

it("suppresses both headline and subordinate repair diagnostics for revoked gateways", () => {
  const office = renderGateway({ status: "revoked", policy_degraded: true, policy_degraded_kind: "site_link_down", site_link_note_peer: "old-hub", site_link_note_demoted: true });
  expect(office.getByText(/Revoked/)).toBeTruthy();
  expect(office.queryByText(/Registered|site link down|old-hub|demoted|healthy/i)).toBeNull();
});

it("keeps the demoted peer note distinct from the reported headline diagnosis", () => {
  const office = renderGateway({ policy_degraded: true, policy_degraded_kind: "apply_failing", site_link_note_peer: "old-hub", site_link_note_demoted: true });
  const headline = office.getByText("apply failing");
  const note = office.getByText("site link down: old-hub (demoted)");
  expect(headline).not.toBe(note);
  expect(headline.contains(note)).toBe(false);
  expect(note.contains(headline)).toBe(false);
});

it("shows a demoted peer note independently when no headline diagnosis is reported", () => {
  const office = renderGateway({ site_link_note_peer: "old-hub", site_link_note_demoted: true });
  expect(office.getByText("site link down: old-hub (demoted)")).toBeTruthy();
  expect(office.queryByText(/^healthy$|^degraded$/i)).toBeNull();
});

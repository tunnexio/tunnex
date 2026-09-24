import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, within, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { Site } from "../src/lib/api";
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

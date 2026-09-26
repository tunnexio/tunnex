import {afterEach,expect,it} from "vitest";
import {cleanup,fireEvent,render,screen} from "@testing-library/react";
import {MemoryRouter} from "react-router-dom";
import {RoutingExplorer} from "../src/components/RoutingExplorer";
afterEach(cleanup);
function show(){render(<MemoryRouter><RoutingExplorer complete={false} allocations={[{cidr:"10.0.0.0/24",kind:"approved",label:"Office"},{cidr:"10.1.0.0/24",kind:"pending",label:"Office"},{cidr:"10.2.0.0/24",kind:"pool",label:"Device pool"}]} rows={[{range:"10.0.0.0/24",attribution:{kind:"site",siteId:"s1",siteName:"Office"}}]} sites={[{id:"s1",name:"Office"} as never]} fanOut={[{ok:true,siteId:"s1",subnets:[{cidr:"10.1.0.0/24",status:"pending"} as never]}]} forwards={[]} /></MemoryRouter>);}
it("opens the owning site from a routed range",()=>{show();fireEvent.click(screen.getByRole("button",{name:/10.0.0.0/}));expect(screen.getByRole("link",{name:/Open site/}).getAttribute("href")).toBe("/sites?site=s1");expect(screen.getByText("Published to split-tunnel devices")).toBeTruthy();});
it("distinguishes pending and reserved allocations from routes",()=>{show();fireEvent.click(screen.getByRole("button",{name:/10.1.0.0/}));expect(screen.getByText("Withheld until approved")).toBeTruthy();expect(screen.getByRole("link",{name:/Review approvals/})).toBeTruthy();fireEvent.click(screen.getByRole("button",{name:/10.2.0.0/}));expect(screen.getByText(/Reserved allocation; not a published route/)).toBeTruthy();});
it("filters ranges and removes details for hidden selections",()=>{show();fireEvent.click(screen.getByRole("button",{name:/10.0.0.0/}));fireEvent.change(screen.getByRole("combobox",{name:"Filter routing graph"}),{target:{value:"pending"}});expect(screen.queryByRole("button",{name:/10.0.0.0/})).toBeNull();expect(screen.queryByRole("complementary",{name:"Range details"})).toBeNull();expect(screen.getByText(/This view may be incomplete/)).toBeTruthy();});
it("pages a large inventory and searches beyond the visible page",()=>{
 render(<MemoryRouter><RoutingExplorer complete allocations={Array.from({length:25},(_,i)=>({cidr:`10.${i}.0.0/16`,kind:"approved" as const,label:"Office"}))} rows={[]} sites={[]} fanOut={[]} forwards={[]} /></MemoryRouter>);
 expect(screen.getByText("1–12 of 25")).toBeTruthy();
 expect(screen.queryByRole("button",{name:/10\.24\.0\.0/})).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:"Next"}));
 fireEvent.click(screen.getByRole("button",{name:"Next"}));
 expect(screen.getByRole("button",{name:/10\.24\.0\.0/})).toBeTruthy();
 fireEvent.change(screen.getByRole("textbox",{name:"Search routing graph"}),{target:{value:"10.0.0.0"}});
 expect(screen.getByRole("button",{name:/10\.0\.0\.0/})).toBeTruthy();
 expect(screen.queryByRole("button",{name:"Next"})).toBeNull();
});
it("guides an operator from the attention notice to pending review",()=>{
 show();
 fireEvent.click(screen.getByRole("button",{name:/1 range needs approval/}));
 expect(screen.queryByRole("button",{name:/10\.0\.0\.0/})).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:/10\.1\.0\.0/}));
 expect(screen.getByText("Before you approve")).toBeTruthy();
 expect(screen.getByText(/Confirm that this range belongs/)).toBeTruthy();
 expect(screen.getByRole("link",{name:/Review approvals/}).getAttribute("href")).toBe("/sites?site=s1&section=approvals");
});
it("keeps verbose guidance behind the range details disclosure",()=>{
 show();
 fireEvent.click(screen.getByRole("button",{name:/10\.1\.0\.0/}));
 expect(screen.getByRole("figure",{name:"Illustrated route, not live traffic"})).toBeTruthy();
 const disclosure=screen.getByText("Details & next steps").closest("details");
 expect(disclosure?.open).toBe(false);
 fireEvent.click(screen.getByRole("button",{name:"Approval needed"}));
 expect(screen.getByText("This range is withheld until an administrator approves it.")).toBeTruthy();
 fireEvent.click(screen.getByText("Details & next steps"));
 expect(disclosure?.open).toBe(true);
});

it("shows one diagram tied to the selected range, with no generic duplicate",()=>{
 show();
 expect(screen.queryByRole("figure")).toBeNull();
 fireEvent.click(screen.getByRole("button",{name:/10\.0\.0\.0/}));
 expect(screen.getAllByRole("figure")).toHaveLength(1);
 expect(screen.getByRole("button",{name:"Office 10.0.0.0/24"})).toBeTruthy();
 fireEvent.click(screen.getByRole("button",{name:"Close range details"}));
 expect(screen.queryByRole("figure")).toBeNull();
});

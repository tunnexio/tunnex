import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const mock=vi.hoisted(()=>({get:vi.fn(),org:{id:"org-a",name:"Acme"},role:"owner",failed:false,nodes:[{id:"gateway-a",name:"Office gateway",enrolled_kind:"gateway",status:"active",site_id:"site-a"}]}));
vi.mock("../src/lib/api",async()=>({...await vi.importActual("../src/lib/api"),api:{GET:mock.get}}));
vi.mock("../src/lib/useOrg",()=>({useOrg:()=>({org:mock.org,loading:false,failed:false})}));
const auth={status:"authed",user:{id:"u1",email_verified:true,must_change_password:false}};
vi.mock("../src/lib/auth",()=>({useAuth:()=>({state:auth})}));
vi.mock("../src/components/Gateways",()=>({Gateways:()=> <p>Existing enrollment form</p>}));
import Setup from "../src/pages/Setup";
afterEach(cleanup);
beforeEach(()=>{
  mock.org={id:"org-a",name:"Acme"};mock.role="owner";mock.failed=false;
  mock.nodes=[{id:"gateway-a",name:"Office gateway",enrolled_kind:"gateway",status:"active",site_id:"site-a"}];
  mock.get.mockImplementation(async(path:string)=>{
    if(path.endsWith("/nodes")) return mock.failed ? {error:{error:{message:"Gateway inventory unavailable"}}}:{data:mock.nodes};
    if(path.endsWith("/members")) return {data:[{user_id:"u1",role:mock.role}]};
    if(path.endsWith("/routed-ranges")) return {data:{ranges:[]}};
    if(path.endsWith("/license")) return {data:{tier:"community"}};
    if(path.endsWith("/meta")) return {data:{public_base_url:"https://vpn.acme.example"}};
    return {data:[]};
  });
});
function show(purpose="vpn",step=1){return render(<MemoryRouter initialEntries={[`/setup?purpose=${purpose}&step=${step}`]}><Setup/></MemoryRouter>);}
function goToStep(step: number) {fireEvent.click(screen.getByRole("button",{name:new RegExp(`^Step ${step}:`)}));}
describe("dashboard setup guide",()=>{
  it("reuses an installed gateway, links the existing network editor and does not claim a verified connection",async()=>{
    show();await screen.findByText(/already registered/);
    expect(screen.getByRole("link",{name:"Office gateway →"}).getAttribute("href")).toBe("/gateways/gateway-a?from=setup&purpose=vpn&setupStep=1");
    goToStep(2);
    expect(screen.getByRole("link",{name:"Set up a private network →"}).getAttribute("href")).toBe("/network/setup?from=setup&purpose=vpn&setupStep=2");
    expect(screen.queryByRole("button",{name:"Register a gateway"})).toBeNull();
    goToStep(4);
    expect(await screen.findByRole("link",{name:"Download Client"})).toBeTruthy();
    expect(screen.queryByText("Private access verified")).toBeNull();
  });
  it("offers existing enrollment for no gateway, excludes revoked gateways",async()=>{
    mock.nodes[0].status="revoked";show();
    fireEvent.click(await screen.findByRole("button",{name:"Register a gateway"}));
    expect(screen.getByText("Existing enrollment form")).toBeTruthy();
    expect(screen.queryByRole("link",{name:"Set up a private network →"})).toBeNull();
  });
  it("failed inventory is not an empty setup and can retry",async()=>{
    mock.failed=true;show();await screen.findByText("Gateway inventory unavailable");
    expect(screen.queryByRole("button",{name:"Register a gateway"})).toBeNull();
    mock.failed=false;fireEvent.click(screen.getByRole("button",{name:"Retry setup"}));
    await screen.findByText(/already registered/);
  });
  it("refuses setup controls without network management permission",async()=>{
    mock.role="member";show();await screen.findByText("Ask your administrator to finish setup");
    expect(screen.queryByRole("button",{name:"Add another gateway"})).toBeNull();
  });
  it("offers all tasks without changing a product mode",async()=>{
    show("");await screen.findByText("What do you want to connect?");
    fireEvent.click(screen.getByRole("link",{name:/Kubernetes access/}));
    goToStep(2);
    await screen.findByRole("link",{name:"Open Kubernetes setup →"});
    expect(screen.queryByRole("link",{name:"Set up a private network →"})).toBeNull();
    fireEvent.click(screen.getByRole("button",{name:"Choose another task"}));
    fireEvent.click(screen.getByRole("link",{name:/Site-to-site VPN/}));
    goToStep(2);
    expect(screen.queryByRole("link",{name:"Invite users →"})).toBeNull();
    expect(screen.getByRole("link",{name:"Open connection setup →"}).getAttribute("href")).toBe("/site-to-site?from=setup&purpose=networks&setupStep=2");
  });
  it("does not describe a failed private-network read as no networks",async()=>{
    const normal=mock.get.getMockImplementation()!;
    mock.get.mockImplementation((path:string)=>path.endsWith("/routed-ranges")?Promise.resolve({error:{error:{message:"Network read failed"}}}):normal(path));
    show("vpn",2);await screen.findByText("Network read failed");
    expect(screen.queryByText(/Add the private IP ranges employees need/)).toBeNull();
    expect(screen.getByRole("button",{name:"Retry private networks"})).toBeTruthy();
  });
  it("withdraws gateway and range data on an organization switch",async()=>{
    const result=show();await screen.findByText(/already registered/);
    mock.org={id:"org-b",name:"Beta"}; mock.get.mockImplementation(()=>new Promise(()=>{}));
    result.rerender(<MemoryRouter><Setup/></MemoryRouter>);
    await waitFor(()=>expect(screen.queryByText("Office gateway →")).toBeNull());
    expect(screen.queryByRole("button",{name:"Add another gateway"})).toBeNull();
  });
});


describe("customer setup handoff", () => {
  it("offers the native client and authoritative server address without forcing a config export", async () => {
    show("vpn",4);
    expect((await screen.findByRole("link", {name: "Download Client"})).getAttribute("href")).toBe("https://tunnex.io/download");
    expect(await screen.findByText("https://vpn.acme.example")).toBeTruthy();
    expect(screen.getByRole("button", {name: "Copy server address"})).toBeTruthy();
  });
  it("does not treat an enrolled gateway with no heartbeat as online", async () => {
    show();
    await screen.findByText("Awaiting first connection");
    expect(screen.getByRole("heading", {name: "Connect a gateway"})).toBeTruthy();
    expect(screen.queryByText("Private access verified")).toBeNull();
  });
  it("links an offline gateway to diagnostics and preserves the setup task", async () => {
    Object.assign(mock.nodes[0], {last_seen_at:"2020-01-01T00:00:00Z"});
    show();
    const link=await screen.findByRole("link", {name: "Check gateway health"});
    expect(link.getAttribute("href")).toContain("tab=health");
    expect(link.getAttribute("href")).toContain("from=setup");
  });
  it("distinguishes pending device approval from an observed handshake", async () => {
    const normal=mock.get.getMockImplementation()!;
    mock.get.mockImplementation((path:string)=>path.endsWith("/devices")?Promise.resolve({data:[{id:"d1",kind:"human",status:"pending",last_handshake_at:new Date().toISOString(),public_key:"wg"}]}):normal(path));
    show("vpn",4);
    expect(await screen.findByText(/1 device awaiting approval/)).toBeTruthy();
    expect(screen.queryByText(/Handshake observed on/)).toBeNull();
  });
});


describe("one step at a time", () => {
  it("shows only the current stage and preserves Back/Continue navigation", async () => {
    show(); await screen.findByText(/already registered/);
    expect(screen.queryByRole("heading", {name:"Choose your private networks"})).toBeNull();
    expect(screen.queryByRole("link", {name:"Download Client"})).toBeNull();
    fireEvent.click(screen.getByRole("button", {name:"Continue"}));
    expect(await screen.findByRole("heading", {name:"Choose your private networks"})).toBeTruthy();
    expect(screen.queryByRole("heading", {name:"Connect a gateway"})).toBeNull();
    fireEvent.click(screen.getByRole("button", {name:"Back"}));
    await screen.findByRole("heading", {name:"Connect a gateway"});
  });
  it("holds wizard navigation while the enrollment form is open", async () => {
    mock.nodes=[]; show();
    fireEvent.click(await screen.findByRole("button",{name:"Register a gateway"}));
    expect((screen.getByRole("button",{name:"Continue"}) as HTMLButtonElement).disabled).toBe(true);
    expect((screen.getByRole("button",{name:"Step 2: Network"}) as HTMLButtonElement).disabled).toBe(true);
  });
  it("opens a bookmarked step and rejects an invalid step", async () => {
    const result=show("vpn",3);
    await screen.findByRole("heading",{name:"Review who can access it"});
    expect(screen.getByRole("link",{name:"Invite users →"}).getAttribute("href")).toContain("setupStep=3");
    result.unmount(); show("vpn",99);
    await screen.findByRole("heading",{name:"Connect a gateway"});
  });
});

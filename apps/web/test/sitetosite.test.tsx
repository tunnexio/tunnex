import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, fireEvent, act, within } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { MemoryRouter } from "react-router-dom";
import { ConnectionChooser } from "../src/components/ConnectionChooser";
const mock = vi.hoisted(() => ({ org: { id: "a" } as { id: string } | null, failed: false, loading: false, verified: true, userId: "user", get: vi.fn() }));
const authStates = vi.hoisted(() => new Map<string, { status: "authed"; user: { id: string; email_verified: boolean } }>());
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mock.org, loading: mock.loading, failed: mock.failed }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => {
  const key = `${mock.userId}:${mock.verified}`;
  let state = authStates.get(key);
  if (!state) { state = { status: "authed", user: { id: mock.userId, email_verified: mock.verified } }; authStates.set(key, state); }
  return { state };
} }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get } }));
import SiteToSite from "../src/pages/SiteToSite";
// SSI-13: the page is the Cloud VPN tab by default; the pair review these tests cover lives at ?method=wireguard.
const app = () => <MemoryRouter initialEntries={["/site-to-site?method=wireguard"]}><SiteToSite /></MemoryRouter>;
afterEach(cleanup);
beforeEach(() => { authStates.clear(); mock.org = { id: "a" }; mock.loading = false; mock.failed = false; mock.verified = true; mock.userId = "user"; mock.get.mockReset(); });
it("does not turn a failed site read into an empty inventory, and retries", async () => {
  let fail = true;
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: [] } : fail ? { error: { error: { message: "Unavailable" } } } : { data: [] });
  render(app());
  await screen.findByRole("alert");
  expect(screen.queryByText("No networks configured yet.")).toBeNull();
  fail = false;
  fireEvent.click(screen.getByRole("button", { name: "Retry networks" }));
  await screen.findByText("No networks configured yet.");
});
it("withdraws old-organization rows immediately and ignores late responses", async () => {
  let finish: (value: unknown) => void = () => {};
  mock.get.mockImplementation((path: string, opts: { params: { path: { orgId: string } } }) => {
    if (path.endsWith("/members")) return Promise.resolve({ data: [] });
    if (opts.params.path.orgId === "a") return new Promise(resolve => { finish = resolve; });
    return Promise.resolve({ data: [{ id: "b-site", name: "B network" }, { id: "b-other", name: "Partner network" }] });
  });
  const view = render(app());
  mock.org = { id: "b" }; view.rerender(app());
  await screen.findAllByRole("option", { name: "B network" });
  finish({ data: [{ id: "a-site", name: "A network" }, { id: "a-other", name: "Partner network" }] });
  await waitFor(() => expect(screen.queryByText("A network")).toBeNull());
  expect(screen.getAllByRole("option", { name: "B network" })).toHaveLength(2);
});
it("hides setup when membership cannot be established", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { error: {} } : { data: [] });
  render(app());
  await screen.findByText("No networks configured yet.");
  expect(screen.queryByRole("button", { name: "Add a network" })).toBeNull();
});
it("lets a verified owner reuse existing network setup", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: [{ user_id: "user", role: "owner" }] } : { data: [] });
  render(app());
  const link = await screen.findByRole("button", { name: "Add a network" });
  fireEvent.click(link);
  expect(screen.getByRole("dialog", { name: "Add a network" })).toBeTruthy();
  expect(screen.getByText("What is on the other side?")).toBeTruthy();
});
it("removes already rendered site data while the next organization loads", async () => {
  mock.get.mockImplementation((path: string, opts: { params: { path: { orgId: string } } }) => {
    if (path.endsWith("/members")) return Promise.resolve({ data: [] });
    return opts.params.path.orgId === "a"
      ? Promise.resolve({ data: [{ id: "a-site", name: "A network" }, { id: "a-other", name: "Partner network" }] })
      : new Promise(() => {});
  });
  const view = render(app());
  await screen.findAllByRole("option", { name: "A network" });
  mock.org = { id: "b" }; view.rerender(app());
  expect(screen.queryByText("A network")).toBeNull();
  expect(screen.getByRole("status").textContent).toBe("Loading networks…");
});

it("recovers membership failure without presenting it as denied permission", async () => {
  let unavailable = true;
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members")
    ? unavailable ? { error: {} } : { data: [{ user_id: "user", role: "owner" }] }
    : { data: [{ id: "site", name: "Office network" }] });
  render(app());
  await screen.findByText("Could not check your setup permissions.");
  expect(screen.queryByText(/Contact your administrator/)).toBeNull();
  unavailable = false;
  fireEvent.click(screen.getByRole("button", { name: "Retry permissions" }));
  await screen.findByRole("button", { name: "Add a network" });
});
it("offers page reload for organization discovery failure rather than network retry", async () => {
  mock.org = null; mock.failed = true;
  render(app());
  await screen.findByRole("button", { name: "Reload page" });
  expect(screen.queryByRole("button", { name: "Retry networks" })).toBeNull();
  expect(mock.get).not.toHaveBeenCalled();
});
it("withdraws setup immediately when email verification is lost", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: [{ user_id: "user", role: "owner" }] } : { data: [] });
  const view = render(app());
  await screen.findByRole("button", { name: "Add a network" });
  mock.verified = false; view.rerender(app());
  expect(screen.queryByRole("button", { name: "Add a network" })).toBeNull();
  await screen.findByText("No networks configured yet.");
  expect(screen.queryByRole("button", { name: "Add a network" })).toBeNull();
});
it("resets the selected pair on user switch and ignores the previous user's pending configuration", async () => {
  let finishPrevious: (value: unknown) => void = () => {};
  let finishPreviousHubs: (value: unknown) => void = () => {};
  mock.get.mockImplementation((path: string, opts: { params: { path: { siteId?: string } } }) => {
    if (path.endsWith("/members")) return Promise.resolve({ data: [{ user_id: "user", role: "owner" }] });
    if (path.endsWith("/sites")) return Promise.resolve({ data: [{ id: "office", name: "Office" }, { id: "cloud", name: "Cloud" }] });
    if (path.endsWith("/nodes")) return Promise.resolve({ data: [] });
    if (path.endsWith("/hub-set")) return mock.userId === "user"
      ? new Promise(resolve => { finishPreviousHubs = resolve; })
      : Promise.resolve({ data: { generation: 0, members: [] } });
    if (mock.userId === "user" && opts.params.path.siteId === "office") {
      return new Promise(resolve => { finishPrevious = resolve; });
    }
    return Promise.resolve({ data: [] });
  });
  const view = render(app());
  await screen.findByLabelText("First network");
  fireEvent.change(screen.getByLabelText("First network"), { target: { value: "office" } });
  fireEvent.change(screen.getByLabelText("Second network"), { target: { value: "cloud" } });
  expect(screen.getByRole("status").textContent).toBe("Loading network configuration…");

  mock.userId = "another-user";
  view.rerender(app());
  expect(screen.queryByRole("button", { name: "Add a network" })).toBeNull();
  expect(screen.queryByLabelText("First network")).toBeNull();
  await screen.findByLabelText("First network");
  expect((screen.getByLabelText("First network") as HTMLSelectElement).value).toBe("");
  expect((screen.getByLabelText("Second network") as HTMLSelectElement).value).toBe("");
  expect(screen.queryByRole("button", { name: "Add a network" })).toBeNull();

  fireEvent.change(screen.getByLabelText("First network"), { target: { value: "office" } });
  fireEvent.change(screen.getByLabelText("Second network"), { target: { value: "cloud" } });
  await screen.findByRole("region", { name: "Office configuration" });
  await act(async () => finishPrevious({ data: [{ id: "old", site_id: "office", cidr: "10.99.0.0/24", status: "approved" }] }));
  await act(async () => finishPreviousHubs({ data: { generation: 1, members: [{ node_id: "old-user-hub", role: "primary" }] } }));
  expect(screen.queryByText("old-user-hub")).toBeNull();
  expect(screen.getByText("No transit hub set reported.")).toBeTruthy();
  expect(screen.queryByText("10.99.0.0/24")).toBeNull();
  expect(screen.getAllByText("No network ranges advertised.")).toHaveLength(2);
});
it("SSI-13: the page is the Cloud VPN tab; the pair review at ?method=wireguard never loads IPsec", async () => {
 mock.get.mockImplementation(async (path: string) => {
  if (path.endsWith("/members")) return { data: [{ user_id: "user", role: "owner" }] };
  if (path.endsWith("/settings")) return { data: { enabled: false, revision: 0 } };
  if (path.endsWith("/connections")) return { data: { items: [], next_cursor: null } };
  return { data: [] };
 });
 const view = render(app()); await screen.findByText("No networks configured yet.");
 expect(mock.get.mock.calls.some(([path]) => path.includes("/ipsec/"))).toBe(false);
 expect(screen.queryByRole("radio")).toBeNull(); // no method switch any more
 view.unmount();
 render(<MemoryRouter initialEntries={["/site-to-site"]}><SiteToSite /></MemoryRouter>);
 await screen.findByRole("link", { name: "Manage in Features" });
 expect(screen.getByRole("link", { name: "Cloud VPN" }).getAttribute("aria-current")).toBe("page");
 expect(screen.getByRole("button", { name: "Add a network" })).toBeTruthy();
});
it("withdraws IPsec on the first commit of same-organization loading", async () => {
 mock.get.mockImplementation(async(path:string)=>path.endsWith("/members")?{data:[{user_id:"user",role:"owner"}]}:path.endsWith("/settings")?{data:{enabled:true,revision:1}}:path.endsWith("/connections")?{data:{items:[],next_cursor:null}}:{data:[]});
 let leaked=false;
 function Probe(){useLayoutEffect(()=>{if(mock.loading) leaked=!!screen.queryByRole("button",{name:"Add a network"});});return app();}
 const result=render(<Probe/>);await screen.findByText("No networks configured yet.");
 await screen.findByRole("button",{name:"Add a network"});
 mock.loading=true;result.rerender(<Probe/>);expect(leaked).toBe(false);
 expect(screen.queryByRole("button",{name:"Add a network"})).toBeNull();
});

it("shows no links for one network without duplicating network inventory", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members")
    ? { data: [{ user_id: "user", role: "owner" }] }
    : { data: [{ id: "office", name: "Home Wi-Fi lab" }] });
  render(app());
  expect(await screen.findByRole("heading", { name: "No WireGuard links" })).toBeTruthy();
  expect(screen.queryByRole("table")).toBeNull();
  expect(screen.queryByText("Home Wi-Fi lab")).toBeNull();
  expect(screen.getByRole("link", { name: "Go to Networks" }).getAttribute("href")).toBe("/sites");
  expect(screen.queryByRole("radio")).toBeNull();
  expect(screen.queryByLabelText("First network")).toBeNull();
  expect(screen.queryByRole("button", { name: "New connection" })).toBeNull();
});

it("routes AWS through provider selection and does not reopen a cancelled draft on tab return", async () => {
  mock.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user", role: "owner" }] };
    if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
    if (path.endsWith("/connections")) return { data: { items: [], next_cursor: null } };
    return { data: [] };
  });
  render(app());
  fireEvent.click(await screen.findByRole("button", { name: "Add a network" }));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button", { name: /A cloud VPN gateway/ }));
  const providerDialog = screen.getByRole("dialog", { name: "Choose your cloud VPN" });
  for (const [name, provider] of [
    [/AWS Site-to-Site/, "aws"], [/Azure/, "azure"],
    [/Google Cloud/, "gcp"], [/On-premises/, "self_managed"],
  ] as const) {
    const choice = within(providerDialog).getByRole("button", { name });
    const logo = choice.querySelector(`[data-provider-mark="${provider}"]`);
    expect(logo?.getAttribute("aria-hidden")).toBe("true");
    expect(logo?.getAttribute("focusable")).toBe("false");
    if (provider !== "self_managed") expect(logo?.querySelector("image")?.getAttribute("href")).toMatch(/^data:image\/(?:svg\+xml|png);base64,/);
  }
  expect((screen.getByRole("button", { name: /Azure/ }) as HTMLButtonElement).disabled).toBe(false);
  for (const name of [/On-premises/]) {
    expect((screen.getByRole("button", { name }) as HTMLButtonElement).disabled).toBe(true);
  }
  fireEvent.click(screen.getByRole("button", { name: /AWS Site-to-Site/ }));
  await screen.findByRole("dialog", { name: "New IPsec connection" });
  fireEvent.click(screen.getByRole("button", { name: "Cancel" }));
  await screen.findByText("No IPsec connections configured.");
  expect(screen.queryByRole("dialog")).toBeNull();
});
it("SSI-13 D3: Add a network asks one question; a Tunnex gateway goes straight to network setup", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: [{ user_id: "user", role: "owner" }] } : { data: [] });
  const added = vi.fn();
  render(<MemoryRouter><ConnectionChooser orgId="org" sites={[]} onClose={() => {}} onAWS={() => {}} onNetworkAdded={added} /></MemoryRouter>);
  const first = within(screen.getByRole("dialog", { name: "Add a network" }));
  expect(first.getByText("What is on the other side?")).toBeTruthy();
  expect(first.getByRole("button", { name: /A cloud VPN gateway/ })).toBeTruthy();
  fireEvent.click(first.getByRole("button", { name: /A machine where I can run a Tunnex gateway/ }));
  const adding = within(screen.getByRole("dialog", { name: "Add a network" }));
  expect(await adding.findByRole("navigation", { name: "Network setup steps" })).toBeTruthy();
  expect(adding.queryByRole("button", { name: "Review network pair" })).toBeNull();
});
it("SSI-13 D3: the cloud VPN choice shows the existing provider step, marks included", () => {
  render(<MemoryRouter><ConnectionChooser orgId="org" sites={[]} onClose={() => {}} onAWS={() => {}} onAzure={() => {}} /></MemoryRouter>);
  fireEvent.click(screen.getByRole("button", { name: /A cloud VPN gateway/ }));
  const providers = within(screen.getByRole("dialog", { name: "Choose your cloud VPN" }));
  for (const provider of ["aws", "gcp", "azure"]) expect(document.querySelector(`[data-provider-mark="${provider}"]`)).toBeTruthy();
  expect(providers.getByRole("button", { name: "Back" })).toBeTruthy();
});

it("opens the Cloud VPN workspace by default and from the old ?method=ipsec URL", async () => {
  mock.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user", role: "owner" }] };
    if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
    if (path.endsWith("/connections")) return { data: { items: [], next_cursor: null } };
    return { data: [] };
  });
  const view = render(<MemoryRouter initialEntries={["/site-to-site?method=ipsec"]}><SiteToSite /></MemoryRouter>);
  expect(await screen.findByRole("heading", { name: "IPsec VPN connections" })).toBeTruthy();
  view.unmount();
  render(<MemoryRouter initialEntries={["/site-to-site"]}><SiteToSite /></MemoryRouter>);
  expect(await screen.findByRole("heading", { name: "IPsec VPN connections" })).toBeTruthy();
});

it("opens Google Cloud HA profile through the existing provider chooser", async () => {
  mock.get.mockImplementation(async (path:string) => {
    if(path.endsWith("/members"))return {data:[{user_id:"user",role:"owner"}]};
    if(path.endsWith("/settings"))return {data:{enabled:true,revision:1}};
    if(path.endsWith("/connections"))return {data:{items:[],next_cursor:null}};
    return {data:[]};
  });
  render(app());fireEvent.click(await screen.findByRole("button",{name:"Add a network"}));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button",{name:/A cloud VPN gateway/}));
   fireEvent.click(screen.getByRole("button",{name:/Google Cloud HA VPN/}));
  await screen.findByRole("dialog",{name:"New IPsec connection"});
  expect((screen.getByLabelText("Cloud VPN profile") as HTMLSelectElement).value).toBe("gcp-ha-bgp-ipv4-v1");
  expect((screen.getByLabelText("Routing") as HTMLSelectElement).value).toBe("ipv4-bgp");
  expect(screen.getByLabelText("Cloud Router ASN")).toBeTruthy();
});

it.each([
 {card:/AWS Site-to-Site/,options:["aws"],azure:false},
 {card:/Google Cloud HA VPN/,options:["gcp-ha-bgp-ipv4-v1","gcp-classic-static-ipv4-v1"],azure:false},
 {card:/Azure/,options:["azure-active-active-bgp-ipv4-v1","azure-active-active-static-ipv4-v1","azure-active-standby-bgp-ipv4-v1","azure-active-standby-static-ipv4-v1"],azure:true},
])("keeps the selected provider context in the IPsec draft: $options",async({card,options,azure})=>{
 mock.get.mockImplementation(async(path:string)=>path.endsWith("/members")?{data:[{user_id:"user",role:"owner"}]}:path.endsWith("/settings")?{data:{enabled:true,revision:1}}:path.endsWith("/connections")?{data:{items:[],next_cursor:null}}:{data:[]});
 render(app());fireEvent.click(await screen.findByRole("button",{name:"Add a network"}));
  fireEvent.click(within(screen.getByRole("dialog")).getByRole("button",{name:/A cloud VPN gateway/}));
 fireEvent.click(screen.getByRole("button",{name:card}));await screen.findByRole("dialog",{name:"New IPsec connection"});
 expect(Array.from((screen.getByLabelText("Cloud VPN profile") as HTMLSelectElement).options).map(option=>option.value)).toEqual(options);
 expect(Boolean(screen.queryByLabelText("Import Tunnex Azure JSON"))).toBe(azure);
});

it("SSI-13: arriving with ?create= opens the provider's form once the page has loaded", async () => {
  mock.get.mockImplementation(async (path: string) => {
    if (path.endsWith("/members")) return { data: [{ user_id: "user", role: "owner" }] };
    if (path.endsWith("/settings")) return { data: { enabled: true, revision: 1 } };
    if (path.endsWith("/connections")) return { data: { items: [], next_cursor: null } };
    return { data: [] };
  });
  render(<MemoryRouter initialEntries={["/site-to-site?create=gcp"]}><SiteToSite /></MemoryRouter>);
  await screen.findByRole("dialog", { name: "New IPsec connection" });
  expect((screen.getByLabelText("Cloud VPN profile") as HTMLSelectElement).value).toBe("gcp-ha-bgp-ipv4-v1");
});

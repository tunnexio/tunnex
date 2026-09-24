import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { useLayoutEffect } from "react";
import { MemoryRouter } from "react-router-dom";
const mock = vi.hoisted(() => ({ org: { id: "a" } as { id: string } | null, failed: false, loading: false, verified: true, userId: "user", get: vi.fn() }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mock.org, loading: mock.loading, failed: mock.failed }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: mock.userId, email_verified: mock.verified } } }) }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get } }));
import SiteToSite from "../src/pages/SiteToSite";
const app = () => <MemoryRouter><SiteToSite /></MemoryRouter>;
afterEach(cleanup);
beforeEach(() => { mock.org = { id: "a" }; mock.loading = false; mock.failed = false; mock.verified = true; mock.userId = "user"; mock.get.mockReset(); });
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
  expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();
});
it("lets a verified owner reuse existing network setup", async () => {
  mock.get.mockImplementation(async (path: string) => path.endsWith("/members") ? { data: [{ user_id: "user", role: "owner" }] } : { data: [] });
  render(app());
  const link = await screen.findByRole("link", { name: "Add a network" });
  expect(link.getAttribute("href")).toBe("/network/setup");
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
  await screen.findByRole("link", { name: "Add a network" });
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
  await screen.findByRole("link", { name: "Add a network" });
  mock.verified = false; view.rerender(app());
  expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();
  await screen.findByText("No networks configured yet.");
  expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();
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
  expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();
  expect(screen.queryByLabelText("First network")).toBeNull();
  await screen.findByLabelText("First network");
  expect((screen.getByLabelText("First network") as HTMLSelectElement).value).toBe("");
  expect((screen.getByLabelText("Second network") as HTMLSelectElement).value).toBe("");
  expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();

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
it("loads IPsec only after choosing its method and leaves WireGuard as default", async () => {
 mock.get.mockImplementation(async (path: string) => {
  if (path.endsWith("/members")) return { data: [{ user_id: "user", role: "owner" }] };
  if (path.endsWith("/settings")) return { data: { enabled: false, revision: 0 } };
  if (path.endsWith("/connections")) return { data: { items: [] } };
  return { data: [] };
 });
 render(app()); await screen.findByText("No networks configured yet.");
 expect(mock.get.mock.calls.some(([path]) => path.includes("/ipsec/"))).toBe(false);
 fireEvent.click(screen.getByRole("button", { name: "IPsec" }));
 await screen.findByRole("button", { name: "Enable IPsec" });
 expect(screen.queryByRole("link", { name: "Add a network" })).toBeNull();
 fireEvent.click(screen.getByRole("button", { name: "WireGuard" }));
 expect(screen.queryByRole("button", { name: "Enable IPsec" })).toBeNull();
 expect(screen.getByText("No networks configured yet.")).toBeTruthy();
});
it("withdraws IPsec on the first commit of same-organization loading", async () => {
 mock.get.mockImplementation(async(path:string)=>path.endsWith("/members")?{data:[{user_id:"user",role:"owner"}]}:path.endsWith("/settings")?{data:{enabled:true,revision:1}}:path.endsWith("/connections")?{data:{items:[]}}:{data:[]});
 let leaked=false;
 function Probe(){useLayoutEffect(()=>{if(mock.loading) leaked=!!screen.queryByRole("button",{name:"New connection"});});return app();}
 const result=render(<Probe/>);await screen.findByText("No networks configured yet.");
 fireEvent.click(screen.getByRole("button",{name:"IPsec"}));await screen.findByRole("button",{name:"New connection"});
 mock.loading=true;result.rerender(<Probe/>);expect(leaked).toBe(false);
 expect(screen.queryByRole("button",{name:"New connection"})).toBeNull();
});

import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor, fireEvent, act } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const mock = vi.hoisted(() => ({ org: { id: "a" } as { id: string } | null, failed: false, verified: true, userId: "user", get: vi.fn() }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mock.org, loading: false, failed: mock.failed }) }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: { id: mock.userId, email_verified: mock.verified } } }) }));
vi.mock("../src/lib/api", async (original) => ({ ...await original<object>(), api: { GET: mock.get } }));
import SiteToSite from "../src/pages/SiteToSite";
const app = () => <MemoryRouter><SiteToSite /></MemoryRouter>;
afterEach(cleanup);
beforeEach(() => { mock.org = { id: "a" }; mock.failed = false; mock.verified = true; mock.userId = "user"; mock.get.mockReset(); });
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
    return Promise.resolve({ data: [{ id: "b-site", name: "B network" }] });
  });
  const view = render(app());
  mock.org = { id: "b" }; view.rerender(app());
  await screen.findByText("B network");
  finish({ data: [{ id: "a-site", name: "A network" }] });
  await waitFor(() => expect(screen.queryByText("A network")).toBeNull());
  expect(screen.getByText("B network")).toBeTruthy();
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
      ? Promise.resolve({ data: [{ id: "a-site", name: "A network" }] })
      : new Promise(() => {});
  });
  const view = render(app());
  await screen.findByText("A network");
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
  await screen.findByText("Office network");
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
  mock.get.mockImplementation((path: string, opts: { params: { path: { siteId?: string } } }) => {
    if (path.endsWith("/members")) return Promise.resolve({ data: [{ user_id: "user", role: "owner" }] });
    if (path.endsWith("/sites")) return Promise.resolve({ data: [{ id: "office", name: "Office" }, { id: "cloud", name: "Cloud" }] });
    if (path.endsWith("/nodes")) return Promise.resolve({ data: [] });
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
  expect(screen.queryByText("10.99.0.0/24")).toBeNull();
  expect(screen.getAllByText("No network ranges advertised.")).toHaveLength(2);
});

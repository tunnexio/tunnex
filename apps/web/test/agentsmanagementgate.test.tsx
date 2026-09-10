import { createElement } from "react";
import {
  act,
  cleanup,
  fireEvent,
  render,
  screen,
} from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { AgentsManagementGate } from "../src/pages/AgentsManagementGate";
const mocked = vi.hoisted(() => ({
  GET: vi.fn(),
  org: { id: "org-a" },
  user: "user-a",
}));
vi.mock("../src/lib/api", () => ({ api: mocked }));
vi.mock("../src/lib/useOrg", () => ({ useOrg: () => ({ org: mocked.org }) }));
vi.mock("../src/lib/auth", () => ({
  useAuth: () => ({ state: { status: "authed", user: { id: mocked.user } } }),
}));
const child = vi.fn((org: string) =>
  createElement("div", null, `private workspace ${org}`),
);
const view = () => createElement(AgentsManagementGate, { children: child });
beforeEach(() => {
  vi.resetAllMocks();
  mocked.org = { id: "org-a" };
  mocked.user = "user-a";
  child.mockImplementation((org) =>
    createElement("div", null, `private workspace ${org}`),
  );
});
afterEach(cleanup);
describe("Agent management permission gate", () => {
  it("handles network rejection and retries without exposing children", async () => {
    mocked.GET.mockRejectedValueOnce(
      new Error("offline"),
    ).mockResolvedValueOnce({ data: [{ user_id: "user-a", role: "admin" }] });
    render(view());
    await screen.findByRole("alert");
    expect(child).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Retry permissions" }));
    await screen.findByText("private workspace org-a");
    expect(mocked.GET).toHaveBeenCalledTimes(2);
  });
  it("allows a retry after an API error response", async () => {
    mocked.GET.mockResolvedValueOnce({
      error: { error: { code: "unavailable" } },
    }).mockResolvedValueOnce({ data: [{ user_id: "user-a", role: "member" }] });
    render(view());
    await screen.findByRole("button", { name: "Retry permissions" });
    fireEvent.click(screen.getByRole("button", { name: "Retry permissions" }));
    await screen.findByText(/You do not have permission/);
    expect(child).not.toHaveBeenCalled();
  });
  it("does not reuse old organization permission even for one render", async () => {
    mocked.GET.mockResolvedValueOnce({
      data: [{ user_id: "user-a", role: "owner" }],
    }).mockReturnValueOnce(new Promise(() => {}));
    const page = render(view());
    await screen.findByText("private workspace org-a");
    child.mockClear();
    mocked.org = { id: "org-b" };
    page.rerender(view());
    expect(child).not.toHaveBeenCalled();
    expect(screen.queryByText(/private workspace/)).toBeNull();
    expect(
      screen.getByText(/Checking AI Agents management permissions/),
    ).toBeTruthy();
  });
  it("ignores the old organization response after switching", async () => {
    let resolve!: (value: unknown) => void;
    mocked.GET.mockReturnValueOnce(
      new Promise((done) => {
        resolve = done;
      }),
    ).mockResolvedValueOnce({ data: [{ user_id: "user-a", role: "member" }] });
    const page = render(view());
    mocked.org = { id: "org-b" };
    page.rerender(view());
    await screen.findByText(/You do not have permission/);
    await act(async () => {
      resolve({ data: [{ user_id: "user-a", role: "owner" }] });
    });
    expect(child).not.toHaveBeenCalled();
  });
  it("does not reuse a previous user's permission", async () => {
    mocked.GET.mockResolvedValueOnce({
      data: [{ user_id: "user-a", role: "owner" }],
    }).mockResolvedValueOnce({ data: [{ user_id: "user-b", role: "member" }] });
    const page = render(view());
    await screen.findByText("private workspace org-a");
    child.mockClear();
    mocked.user = "user-b";
    page.rerender(view());
    await screen.findByText(/You do not have permission/);
    expect(child).not.toHaveBeenCalled();
  });
});

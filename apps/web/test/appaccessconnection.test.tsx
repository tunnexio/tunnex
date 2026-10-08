import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import AppAccessConnection from "../src/components/AppAccessConnection";
import { api } from "../src/lib/api";

const fixture = vi.hoisted(() => ({ status: "supported", stale: false, result: "succeeded", requests: [] as unknown[] }));
const check = { id: "check-1", org_id: "org-1", app_id: "app-1", gateway_id: "gateway-1", generation: "gen-1", revision: 7, digest: "a".repeat(64), purpose: "origin_check", status: "queued", created_at: "2026-10-03T00:00:00Z", deadline: "2026-10-03T00:00:10Z", completed_at: null, dns_status: "pending", connect_status: "pending", tls_status: "pending", error_code: "" };
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: {
    GET: vi.fn(async (path: string) => path.endsWith("/status") ? { data: { org_id: "org-1", gateway_id: "gateway-1", capability_version: 1, reported_at: "2026-10-03T00:00:00Z", status: fixture.status } } : { data: { ...check, status: fixture.result, dns_status: "passed", connect_status: "passed", tls_status: fixture.result === "failed" ? "failed" : "passed", error_code: fixture.result === "failed" ? "tls_failed" : "" } }),
    POST: vi.fn(async (_path: string, options: unknown) => { fixture.requests.push(options); return fixture.stale ? { error: { error: { code: "version_conflict" } } } : { data: check }; }),
  } };
});
afterEach(cleanup);
beforeEach(() => { Object.assign(fixture, { status: "supported", stale: false, result: "succeeded", requests: [] }); vi.clearAllMocks(); });
const props = { orgId: "org-1", appId: "app-1", gatewayId: "gateway-1", version: 7, canCheck: true, dirty: false };

it("requires a fresh supported connector and saved input before requesting a check", async () => {
  fixture.status = "unsupported";
  const view = render(<AppAccessConnection {...props} />);
  await screen.findByText(/does not support the required/);
  expect(screen.getByRole("button", { name: "Check saved connection" })).toHaveProperty("disabled", true);
  fixture.status = "supported";
  fireEvent.click(screen.getByRole("button", { name: "Refresh gateway status" }));
  await screen.findByText(/supports Applications connection checks/);
  view.rerender(<AppAccessConnection {...props} dirty />);
  expect(screen.getByRole("button", { name: "Check saved connection" })).toHaveProperty("disabled", true);
  expect(api.POST).not.toHaveBeenCalled();
});
it("uses the exact saved version, polls its request and labels success as origin connectivity", async () => {
  render(<AppAccessConnection {...props} />);
  await screen.findByText(/supports Applications connection checks/);
  fireEvent.click(screen.getByRole("button", { name: "Check saved connection" }));
  await screen.findByText("Connection check is pending.");
  expect(fixture.requests[0]).toEqual({ params: { path: { orgId: "org-1", appId: "app-1" } }, body: { expected_version: 7 } });
  expect(await screen.findByText("Origin connection succeeded.", {}, { timeout: 3000 })).toBeTruthy();
  expect(screen.getByText(/Connection checks do not change the active publication/)).toBeTruthy();
});
it("retains a stale check refusal without pretending an origin result exists", async () => {
  fixture.stale = true;
  render(<AppAccessConnection {...props} />);
  await screen.findByText(/supports Applications connection checks/);
  fireEvent.click(screen.getByRole("button", { name: "Check saved connection" }));
  expect(await screen.findByRole("alert")).toHaveProperty("textContent", expect.stringContaining("saved application changed"));
  expect(screen.queryByText("Origin connection succeeded.")).toBeNull();
});
it("shows redacted TLS failure after gateway check completion", async () => {
  fixture.result = "failed";
  render(<AppAccessConnection {...props} />);
  await screen.findByText(/supports Applications connection checks/);
  fireEvent.click(screen.getByRole("button", { name: "Check saved connection" }));
  expect(await screen.findByText(/Origin TLS verification failed/, {}, { timeout: 3000 })).toBeTruthy();
  const results = within(screen.getByLabelText("Origin check results"));
  const tls = results.getByText("TLS", { selector: "dt" });
  expect(tls.nextElementSibling).toHaveProperty("tagName", "DD");
  expect(tls.nextElementSibling).toHaveProperty("textContent", "failed");
});
it("lets retained configuration inspect capability after entitlement loss without initiating checks", async () => {
  render(<AppAccessConnection {...props} canCheck={false} />);
  await screen.findByText(/supports Applications connection checks/);
  expect(screen.queryByRole("button", { name: "Check saved connection" })).toBeNull();
  await waitFor(() => expect(api.POST).not.toHaveBeenCalled());
});

it("keeps the saved revision distinct from the mutable application version", async () => {
  const onCheck = vi.fn();
  render(<AppAccessConnection {...props} version={8} revision={7} onCheck={onCheck} />);
  await screen.findByText(/supports Applications connection checks/);
  fireEvent.click(screen.getByRole("button", { name: "Check saved connection" }));
  await screen.findByText("Origin connection succeeded.", {}, { timeout: 3000 });
  expect(fixture.requests[0]).toEqual({ params: { path: { orgId: "org-1", appId: "app-1" } }, body: { expected_version: 8 } });
  expect(screen.queryByText(/does not cover your current/)).toBeNull();
  expect(onCheck).toHaveBeenLastCalledWith(expect.objectContaining({ revision: 7, status: "succeeded" }));
});

it("shows failed capability loading as an error rather than a continuing loading state", async () => {
  vi.mocked(api.GET).mockResolvedValueOnce({ error: { error: { code: "unavailable", message: "Gateway status unavailable." } } } as never);
  render(<AppAccessConnection {...props} />);
  await screen.findByRole("alert");
  expect(screen.queryByText("Loading gateway capability…")).toBeNull();
  expect(screen.queryByText("Origin connection succeeded.")).toBeNull();
  expect(screen.getByRole("button", { name: "Check saved connection" })).toHaveProperty("disabled", true);
});

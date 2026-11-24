import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
const api = vi.hoisted(() => ({ POST: vi.fn() }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api }));
import { AppAccessSelfGrant } from "../src/components/AppAccessSelfGrant";
afterEach(() => { cleanup(); vi.resetAllMocks(); });

it("offers a grant manager without access a time-limited self-grant through the ordinary endpoint (AA-4)", async () => {
  let granted = false;
  api.POST.mockImplementation(async (path: string) => path.endsWith("/effective-access") ? { data: { grant_match: granted } } : (granted = true, { data: { id: "grant-1" } }));
  render(<AppAccessSelfGrant orgId="org-1" appId="app-1" userId="user-1" appName="Payroll" />);
  fireEvent.click(await screen.findByRole("button", { name: "Grant myself access" }));
  await waitFor(() => expect(screen.queryByRole("button", { name: "Grant myself access" })).toBeNull());
  const call = api.POST.mock.calls.find(c => c[0] === "/api/v1/organizations/{orgId}/app-access/grants")!;
  const body = (call[1] as { body: { subject_kind: string; subject_id: string; app_id: string; starts_at: string; expires_at: string } }).body;
  expect(body).toMatchObject({ app_id: "app-1", subject_kind: "user", subject_id: "user-1", enabled: true });
  expect(Date.parse(body.expires_at) - Date.parse(body.starts_at)).toBe(3600000);
});
it("stays hidden when the manager already has access", async () => {
  api.POST.mockResolvedValue({ data: { grant_match: true } });
  render(<AppAccessSelfGrant orgId="org-1" appId="app-1" userId="user-1" appName="Payroll" />);
  await waitFor(() => expect(api.POST).toHaveBeenCalled());
  expect(screen.queryByRole("button", { name: "Grant myself access" })).toBeNull();
});

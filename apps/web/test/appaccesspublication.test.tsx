import { afterEach, beforeEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { components } from "@tunnex/shared";
import AppAccessPublication from "../src/components/AppAccessPublication";
import { api } from "../src/lib/api";

type Publication = components["schemas"]["AppAccessPublicationState"];
type Impact = components["schemas"]["AppAccessPublicationImpact"];
type Operation = components["schemas"]["AppAccessPublicationOperation"];
const f = vi.hoisted(() => ({ view: {} as Publication, operation: {} as Operation, outcome: "queued", reads: 0, byKey: false, impact: undefined as Impact | undefined, impactFail: false }));
const id = "11111111-1111-4111-8111-111111111111";
const checkId = "22222222-2222-4222-8222-222222222222";
const digest = "b".repeat(64);
const application: components["schemas"]["AppAccessApplication"] = {
  require_mfa: false, mfa_freshness_seconds: 900, id, org_id: "org-1", version: 7, draft_revision: 6, state: "draft", publication_state: "unpublished", connector_status: "supported", created_at: "2026-10-03T00:00:00Z", updated_at: "2026-10-03T00:00:00Z",
  draft: { allowed_destination_cidrs: [], origin_ca_digest: "", revision: 6, digest, name: "New payroll", description: "", icon: "app", public_hostname: "new.apps.example.com", origin_url: "https://origin.example.com", gateway_id: "gateway-1", idle_timeout_seconds: 1800, absolute_timeout_seconds: 28800, created_at: "2026-10-03T00:00:00Z" },
};
const check: components["schemas"]["AppAccessCheck"] = { id: checkId, org_id: "org-1", app_id: id, gateway_id: "gateway-1", generation: id, revision: 6, digest, purpose: "origin_check", status: "succeeded", created_at: "2026-10-03T00:00:00Z", deadline: "2026-10-03T00:00:10Z", completed_at: "2026-10-03T00:00:01Z", dns_status: "passed", connect_status: "passed", tls_status: "passed", error_code: "" };
const callbacks = { onChanged: vi.fn(), onArchived: vi.fn(), onRollback: vi.fn() };
const props = { orgId: "org-1", userId: "user-1", application, check, dirty: false, canManage: true, canPublish: true, ...callbacks };
vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return { ...actual, api: {
    GET: vi.fn(async (path: string) => {
      if (path.endsWith("/publication/impact")) return f.impactFail ? { error: { error: { code: "unavailable", message: "Impact unavailable." } } } : { data: structuredClone(f.impact) };
      if (path.endsWith("/publication")) return { data: structuredClone(f.view) };
      if (path.includes("/by-key/")) { f.reads++; return f.byKey ? { data: structuredClone(f.operation) } : { error: { error: { code: "not_found" } }, response: { status: 404 } }; }
      return { data: structuredClone(f.operation) };
    }),
    POST: vi.fn(async (path: string) => {
      if (path.endsWith("/publication-operations")) {
        if (f.outcome === "lost") throw new Error("response lost");
        if (f.outcome === "refused") return { error: { error: { code: "origin_check_required", message: "A fresh connection check is required." } }, response: { status: 409 } };
        f.byKey = true; f.view = { ...f.view, application_version: 8, pending_operation: f.operation };
        return { data: structuredClone(f.operation), response: { status: 202 } };
      }
      if (path.endsWith("/cancel")) { f.operation = { ...f.operation, status: "cancelled", version: 2 }; f.view = { ...f.view, application_version: 9, pending_operation: undefined, last_operation: f.operation }; return { data: structuredClone(f.operation) }; }
      if (path.endsWith("/disable")) { f.view = { ...f.view, active: { ...active(), state: "disabled", withdrawal_confirmed: true } }; return { data: structuredClone(f.view) }; }
      if (path.endsWith("/rollback-draft")) return { data: { ...application, version: 8, draft_revision: 7 } };
      throw new Error(`Unexpected POST ${path}`);
    }),
    DELETE: vi.fn(async () => ({ response: { status: 204 } })),
  } };
});
function active(): components["schemas"]["AppAccessActivePublication"] { return { revision: 4, digest: "a".repeat(64), hostname: "old.apps.example.com", gateway_id: "gateway-1", generation: id, authority_version: 12, state: "active", withdrawal_confirmed: false }; }
function show(extra: Partial<typeof props> = {}) { return render(<MemoryRouter><AppAccessPublication {...props} {...extra} /></MemoryRouter>); }
async function publish() { fireEvent.click(await screen.findByRole("button", { name: "Publish application" })); fireEvent.click(screen.getByRole("button", { name: "Confirm publication" })); }
async function ready() { await waitFor(() => expect(screen.getByRole("button", { name: "Publish application" })).toHaveProperty("disabled", false)); }
const storedKey = `tunnex.appPublication:user-1:org-1:${id}`;
afterEach(() => { cleanup(); vi.useRealTimers(); });
beforeEach(() => {
  window.sessionStorage.clear(); vi.clearAllMocks(); check.completed_at = new Date().toISOString();
  Object.assign(f, { view: { application_version: 7, browser_capability: "supported", rollback_revisions: [] }, outcome: "queued", reads: 0, byKey: false, impact: undefined, impactFail: false,
    operation: { id: "33333333-3333-4333-8333-333333333333", version: 1, app_id: id, status: "queued", revision: 6, digest, hostname: application.draft.public_hostname, gateway_id: "gateway-1", generation: id, authority_version: 13, reviewed_application_version: 7, expected_application_version: 8, expected_active_authority_version: 12, origin_check_id: checkId, readiness_request_id: id, created_at: "2026-10-03T00:00:00Z", deadline: "2026-10-03T00:01:00Z", public_dns_status: "pending", public_tls_status: "pending", connector_dns_status: "pending", connector_connect_status: "pending", connector_tls_status: "pending", error_code: "" },
  });
});

it("requires distinct browser capability, the exact checked revision and saved changes", async () => {
  f.view.browser_capability = "unsupported";
  const page = show(); await screen.findByText(/Upgrade the gateway/);
  expect(screen.getByRole("button", { name: "Publish application" })).toHaveProperty("disabled", true);
  f.view.browser_capability = "supported"; fireEvent.click(screen.getByRole("button", { name: "Refresh publication status" })); await ready();
  page.rerender(<MemoryRouter><AppAccessPublication {...props} check={{ ...check, revision: 7 }} /></MemoryRouter>);
  expect(screen.getByRole("button", { name: "Publish application" })).toHaveProperty("disabled", true);
  page.rerender(<MemoryRouter><AppAccessPublication {...props} dirty /></MemoryRouter>);
  expect(screen.getByRole("button", { name: "Publish application" })).toHaveProperty("disabled", true);
  expect(api.POST).not.toHaveBeenCalled();
});
it("publishes only the confirmed review and keeps the old active revision visible while queued", async () => {
  f.view.active = active(); f.view.active_label = "Old payroll";
  show(); await ready(); fireEvent.click(screen.getByRole("button", { name: "Publish application" }));
  expect(api.POST).not.toHaveBeenCalled(); expect(window.sessionStorage.getItem(storedKey)).toBeNull();
  fireEvent.click(screen.getByRole("button", { name: "Confirm publication" }));
  await screen.findByText(/Publication requested/);
  expect(api.POST).toHaveBeenCalledWith(expect.stringContaining("/publication-operations"), { params: { path: { orgId: "org-1", appId: id } }, body: { expected_version: 7, revision: 6, digest, check_id: checkId, idempotency_key: expect.stringMatching(/^[0-9a-f-]{36}$/) } });
  expect(screen.getByText("Active revision 4")).toBeTruthy(); expect(screen.getByText("Old payroll")).toBeTruthy();
  expect(screen.queryByText("Active revision 6")).toBeNull(); expect(callbacks.onChanged).toHaveBeenCalledTimes(1);
});
it("retains unknown outcomes across remount and retries the original key and review", async () => {
  f.outcome = "lost"; const page = show(); await ready(); await publish();
  const original = vi.mocked(api.POST).mock.calls[0][1];
  await screen.findByText(/previous publication request is retained/); page.unmount();
  show({ application: { ...application, version: 10, draft: { ...application.draft, revision: 9 } } });
  await screen.findByRole("button", { name: "Retry the same publication request" });
  expect(api.POST).toHaveBeenCalledTimes(1);
  fireEvent.click(screen.getByRole("button", { name: "Retry the same publication request" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
  expect(vi.mocked(api.POST).mock.calls[1][1]).toEqual(original); expect(f.reads).toBeGreaterThan(0);
});
it("a definitive first preflight refusal allows a fresh checked attempt", async () => {
  f.outcome = "refused"; show(); await ready(); await publish();
  await screen.findByText("A fresh connection check is required.");
  expect(window.sessionStorage.getItem(storedKey)).toBeNull(); expect(screen.queryByText(/previous publication request is retained/)).toBeNull();
  f.outcome = "queued"; await ready(); await publish();
  await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
  const first = vi.mocked(api.POST).mock.calls[0][1] as { body: { idempotency_key: string } };
  const second = vi.mocked(api.POST).mock.calls[1][1] as { body: { idempotency_key: string } };
  expect(second.body.idempotency_key).not.toBe(first.body.idempotency_key);
});
it("a later refusal cannot discard a previously uncertain request", async () => {
  f.outcome = "lost"; show(); await ready(); await publish();
  await screen.findByRole("button", { name: "Retry the same publication request" });
  f.outcome = "refused"; fireEvent.click(screen.getByRole("button", { name: "Retry the same publication request" }));
  await waitFor(() => expect(api.POST).toHaveBeenCalledTimes(2));
  expect(window.sessionStorage.getItem(storedKey)).not.toBeNull(); expect(screen.getByText(/previous publication request is retained/)).toBeTruthy();
});
it("reads a retained terminal operation without resubmitting it", async () => {
  const input = { expected_version: 7, revision: 6, digest, check_id: checkId, idempotency_key: id };
  window.sessionStorage.setItem(storedKey, JSON.stringify(input)); f.byKey = true; f.operation.status = "failed"; f.operation.error_code = "public_tls_failed";
  show(); await screen.findByText(/public application certificate could not be verified/);
  await waitFor(() => expect(window.sessionStorage.getItem(storedKey)).toBeNull()); expect(api.POST).not.toHaveBeenCalled();
});
it("permits safe disable after license loss and captures both current authority guards", async () => {
  f.view.active = active(); show({ canPublish: false });
  fireEvent.click(await screen.findByRole("button", { name: "Disable application" }));
  expect(api.POST).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole("button", { name: "Confirm disable" }));
  await screen.findByText(/Routing and stream withdrawal confirmed/);
  expect(api.POST).toHaveBeenCalledWith(expect.stringContaining("/publication/disable"), { params: { path: { orgId: "org-1", appId: id } }, body: { expected_application_version: 7, expected_authority_version: 12 } });
  expect(screen.getByRole("button", { name: "Archive application" })).toBeTruthy();
});
it("unconfirmed withdrawal can be retried but cannot be archived", async () => {
  f.view.active = { ...active(), state: "disabled", withdrawal_confirmed: false }; show();
  fireEvent.click(await screen.findByRole("button", { name: "Retry withdrawal confirmation" }));
  expect(screen.queryByRole("button", { name: "Archive application" })).toBeNull(); fireEvent.click(screen.getByRole("button", { name: "Confirm disable" }));
  await screen.findByRole("button", { name: "Archive application" });
});
it("archives only after explicit confirmation of the current application version", async () => {
  f.view.active = { ...active(), state: "disabled", withdrawal_confirmed: true }; show();
  fireEvent.click(await screen.findByRole("button", { name: "Archive application" }));
  expect(api.DELETE).not.toHaveBeenCalled(); fireEvent.click(screen.getByRole("button", { name: "Confirm archive" }));
  await waitFor(() => expect(callbacks.onArchived).toHaveBeenCalledTimes(1));
  expect(api.DELETE).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/app-access/applications/{appId}", { params: { path: { orgId: "org-1", appId: id }, query: { expected_version: 7 } } });
});
it("restores history as a new draft while preserving the current publication", async () => {
  f.view.active = active(); f.view.rollback_revisions = [{ revision: 2, digest: "a".repeat(64), name: "Previous payroll", hostname: "prior.apps.example.com", gateway_id: "gateway-1", activated_at: "2026-10-02T00:00:00Z" }]; show();
  fireEvent.change(await screen.findByLabelText("Previously published revision"), { target: { value: "2" } });
  fireEvent.click(screen.getByRole("button", { name: "Create rollback draft" })); fireEvent.click(screen.getByRole("button", { name: "Confirm rollback draft" }));
  await waitFor(() => expect(callbacks.onRollback).toHaveBeenCalledTimes(1)); expect(screen.getByText("Active revision 4")).toBeTruthy();
  expect(api.POST).toHaveBeenCalledWith(expect.stringContaining("/rollback-draft"), { params: { path: { orgId: "org-1", appId: id } }, body: { expected_version: 7, revision: 2 } });
  expect(api.POST).toHaveBeenCalledTimes(1);
});

it("a poll response arriving after cancellation cannot resurrect the pending revision", async () => {
  const input = { expected_version: 7, revision: 6, digest, check_id: checkId, idempotency_key: id };
  window.sessionStorage.setItem(storedKey, JSON.stringify(input)); f.byKey = true; f.view.pending_operation = f.operation;
  const normalGet = vi.mocked(api.GET).getMockImplementation()!;
  let resolvePoll!: (result: { data: Operation }) => void; let started = false;
  vi.mocked(api.GET).mockImplementation((async (path: string, options: unknown) => {
    if (path.endsWith("/publication-operations/{operationId}")) { started = true; return new Promise<{ data: Operation }>(resolve => { resolvePoll = resolve; }); }
    return (normalGet as (path: string, options: unknown) => Promise<unknown>)(path, options);
  }) as typeof api.GET);
  show(); await screen.findByRole("button", { name: "Cancel pending publication" });
  await waitFor(() => expect(started).toBe(true), { timeout: 2500 });
  fireEvent.click(screen.getByRole("button", { name: "Cancel pending publication" })); fireEvent.click(screen.getByRole("button", { name: "Confirm cancellation" }));
  await screen.findByText(/Publication cancelled/);
  resolvePoll({ data: { ...f.operation, status: "activated" } });
  await new Promise(resolve => window.setTimeout(resolve, 0));
  expect(screen.queryByText("Publication confirmed.")).toBeNull(); expect(window.sessionStorage.getItem(storedKey)).toBeNull();
  expect(callbacks.onChanged).toHaveBeenCalledTimes(1);
  vi.mocked(api.GET).mockImplementation(normalGet);
});

it("an expired origin check requires a fresh check rather than a new publication request", async () => {
  show({ check: { ...check, completed_at: new Date(Date.now() - 5 * 60_000 - 1).toISOString() } });
  await screen.findByText(/gateway supports browser/);
  expect(screen.getByRole("button", { name: "Publish application" })).toHaveProperty("disabled", true);
  expect(screen.getByRole("link", { name: "Check the saved connection" })).toHaveProperty("href", expect.stringContaining("step=connection"));
  expect(api.POST).not.toHaveBeenCalled();
});

it("a by-key response for a different review cannot confirm or discard the retained request", async () => {
  window.sessionStorage.setItem(storedKey, JSON.stringify({ expected_version: 7, revision: 6, digest, check_id: checkId, idempotency_key: id }));
  f.byKey = true; f.operation = { ...f.operation, status: "activated", reviewed_application_version: 5, revision: 4 };
  show(); await screen.findByText(/request key belongs to a different review/);
  expect(window.sessionStorage.getItem(storedKey)).not.toBeNull(); expect(screen.queryByText("Publication confirmed.")).toBeNull();
  expect(api.POST).not.toHaveBeenCalled();
});
it("malformed browser recovery identifiers cannot wedge a fresh publication", async () => {
  window.sessionStorage.setItem(storedKey, JSON.stringify({ expected_version: 7, revision: 6, digest, check_id: "a".repeat(36), idempotency_key: "b".repeat(36) }));
  show(); await ready(); expect(screen.queryByText(/previous publication request is retained/)).toBeNull();
  expect(f.reads).toBe(0);
});


function currentImpact(): Impact { return { evaluated_at: new Date().toISOString(), application_version: 7, authority_version: 12, matching_user_count: 1000, matching_user_count_is_lower_bound: true, live_app_session_count: 4, live_app_session_count_is_lower_bound: true, session_impact_available: true }; }
it("impact counts expose lower bounds, exact audit scope and become stale after publication changes", async () => {
  f.view.active = active(); f.impact = currentImpact(); show();
  fireEvent.click(await screen.findByRole("button", { name: "Evaluate current impact" }));
  await screen.findByText("At least 1000 users match current access grants.");
  expect(screen.getByText("At least 4 unexpired app session records.")).toBeTruthy();
  expect(screen.getByRole("link", { name: "Application configuration audits" }).getAttribute("href")).toBe(`/audit?target_type=app_access&target_id=${id}`);
  f.view.application_version = 8;
  fireEvent.click(screen.getByRole("button", { name: "Refresh publication status" }));
  await screen.findByText("The application changed after the impact preview. Evaluate it again.");
  expect(screen.queryByText("At least 4 unexpired app session records.")).toBeNull();
});
it("an unavailable impact never blocks confirmed withdrawal or invents a session count", async () => {
  f.view.active = active(); f.impactFail = true; show();
  fireEvent.click(await screen.findByRole("button", { name: "Evaluate current impact" }));
  await screen.findByText("Impact unavailable.");
  const disable = screen.getByRole("button", { name: "Disable application" });
  expect(disable).toHaveProperty("disabled", false); fireEvent.click(disable);
  expect(api.POST).not.toHaveBeenCalled();
  fireEvent.click(screen.getByRole("button", { name: "Confirm disable" }));
  await screen.findByText("Disabled. Routing and stream withdrawal confirmed.");
  expect(screen.queryByText(/unexpired app session records\./)).toBeNull();
});
it("missing session impact is reported independently from the matching user count", async () => {
  f.view.active = active(); f.impact = { ...currentImpact(), session_impact_available: false, live_app_session_count: 0 }; show();
  fireEvent.click(await screen.findByRole("button", { name: "Evaluate current impact" }));
  await screen.findByText("Unexpired app session records are unavailable.");
  expect(screen.getByText("At least 1000 users match current access grants.")).toBeTruthy();
  expect(screen.queryByText(/0 unexpired/)).toBeNull();
});

it("reports an expired first publication without claiming an earlier serving revision", async () => {
  f.operation.status = "expired"; f.view.last_operation = f.operation;
  show(); await screen.findByText("Publication expired.");
  expect(screen.getByText(/No active publication/)).toBeTruthy();
  expect(screen.queryByText("The previous active revision stays available.")).toBeNull();
  f.view.active = active();
  fireEvent.click(screen.getByRole("button", { name: "Refresh publication status" }));
  await screen.findByText("The previous active revision stays available.");
});

it("keeps current publication and request readiness separately labelled", async () => {
  f.view.active = active();
  f.operation.status = "failed"; f.view.last_operation = f.operation;
  show();
  await screen.findByRole("heading", { name: "Current publication" });
  expect(screen.getByText("Published")).toBeTruthy();
  expect(screen.getByRole("heading", { name: "Latest publication request" })).toBeTruthy();
  expect(screen.getByRole("list", { name: "Publication readiness results" })).toBeTruthy();
  expect(screen.getByText("The previous active revision stays available.")).toBeTruthy();
});

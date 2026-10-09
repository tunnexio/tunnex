import { act, cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { WorkspaceFeatureControl } from "../src/components/WorkspaceFeatureControl";

const mock = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn(), policy: vi.fn(), impact: vi.fn(), save: vi.fn(), user: { id: "actor-a", email_verified: true } }));
vi.mock("../src/lib/api", async () => ({ ...await vi.importActual("../src/lib/api"), api: { GET: mock.GET, PUT: mock.PUT } }));
vi.mock("../src/lib/auth", () => ({ useAuth: () => ({ state: { status: "authed", user: mock.user } }) }));
vi.mock("../src/lib/beam", async () => ({ ...await vi.importActual("../src/lib/beam"), beamApi: { policy: mock.policy, policyImpact: mock.impact, savePolicy: mock.save } }));
const policy = { enabled: true, version: 7, domain_ready: true, can_manage_policy: true, open_for_all_users: false, require_mfa: true, max_duration_seconds: 5400, max_shares: 4, publisher_group_ids: ["publishers"], reviewer_user_ids: ["reviewer"], reviewer_group_ids: ["reviewers"] };
const server = { enabled: false, can_manage: true, recording_retention_days: 17, mfa_freshness_seconds: 600, recording_max_session_bytes: 1048576, recording_max_org_bytes: 33554432 };
type Feature = "server-access" | "local-sharing" | "alert-delivery" | "sandboxes";
function page(feature: Feature, canEdit = true, orgId = "org-a") { return <MemoryRouter><WorkspaceFeatureControl feature={feature} orgId={orgId} roles={["admin"]} canEdit={canEdit} serverAdmin={false} /></MemoryRouter>; }
beforeEach(() => {
  vi.resetAllMocks(); mock.user = { id: "actor-a", email_verified: true };
  mock.GET.mockImplementation(async (path: string) => ({ data: path.endsWith("/server-access") ? server : { enabled: true } }));
  mock.PUT.mockResolvedValue({ data: { status: "updated" } });
  mock.policy.mockResolvedValue({ ok: true, data: policy });
  mock.impact.mockResolvedValue({ ok: true, data: { policy_version: 7, active_share_count: 4, affected_share_count: 3, affected_reviewer_session_count: 6, requires_confirmation: true } });
  mock.save.mockResolvedValue({ ok: true, data: { ...policy, enabled: false, version: 8 } });
});
afterEach(cleanup);

describe("central workspace feature contracts", () => {
  it("changes Server Access with the saved security limits and waits for authoritative readback", async () => {
    let finish!: (value: unknown) => void;
    mock.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    render(page("server-access"));
    const toggle = await screen.findByRole("switch", { name: "Server Access" });
    fireEvent.click(toggle); fireEvent.click(toggle);
    expect(toggle.getAttribute("aria-checked")).toBe("false");
    expect(toggle).toHaveProperty("disabled", true);
    expect(mock.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/server-access", { params: { path: { orgId: "org-a" } }, body: { enabled: true, recording_retention_days: 17, mfa_freshness_seconds: 600, recording_max_session_bytes: 1048576, recording_max_org_bytes: 33554432 } });
    mock.GET.mockResolvedValue({ data: { ...server, enabled: true } });
    await act(async () => finish({ data: { status: "updated" } }));
    await waitFor(() => expect(screen.getByRole("switch", { name: "Server Access" }).getAttribute("aria-checked")).toBe("true"));
    expect(mock.GET).toHaveBeenCalledTimes(2);
  });

  it("does not infer Server Access enablement from an acknowledgement when the following read fails", async () => {
    render(page("server-access"));
    const toggle = await screen.findByRole("switch", { name: "Server Access" });
    mock.GET.mockRejectedValue(new Error("readback lost"));
    fireEvent.click(toggle);
    await screen.findByRole("button", { name: "Reload Server Access setting" });
    expect(screen.queryByRole("switch", { name: "Server Access" })).toBeNull();
    expect(screen.getByText("Unavailable")).toBeTruthy();
    expect(mock.PUT).toHaveBeenCalledTimes(1);
  });

  it("checks Local Sharing impact before withdrawal and retains every saved policy field", async () => {
    render(page("local-sharing"));
    fireEvent.click(await screen.findByRole("switch", { name: "Local Sharing" }));
    const review = await screen.findByRole("dialog", { name: "Review Local Sharing activation" });
    expect(mock.impact).toHaveBeenCalledExactlyOnceWith("org-a", { ...policy, enabled: false });
    expect(mock.save).not.toHaveBeenCalled();
    const confirm = within(review).getByRole("button", { name: "Confirm Local Sharing change" });
    expect(confirm).toHaveProperty("disabled", true);
    fireEvent.click(within(review).getByRole("checkbox", { name: "End active shares affected by this policy change" }));
    fireEvent.click(confirm);
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(mock.save).toHaveBeenCalledExactlyOnceWith("org-a", { ...policy, enabled: false }, true);
    expect(screen.getByRole("switch", { name: "Local Sharing" }).getAttribute("aria-checked")).toBe("false");
  });

  it("cannot review a sharing activation against another saved policy version", async () => {
    mock.impact.mockResolvedValue({ ok: true, data: { policy_version: 8, active_share_count: 0, affected_share_count: 0, affected_reviewer_session_count: 0, requires_confirmation: false } });
    render(page("local-sharing"));
    fireEvent.click(await screen.findByRole("switch", { name: "Local Sharing" }));
    await screen.findByText(/Sharing policy or its impact changed/);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("switch", { name: "Local Sharing" })).toBeNull();
    expect(screen.getByRole("button", { name: "Reload Local Sharing setting" })).toBeTruthy();
    expect(mock.save).not.toHaveBeenCalled();
  });

  it("blocks sharing enablement without qualified serving authority but still permits withdrawal", async () => {
    mock.policy.mockResolvedValue({ ok: true, data: { ...policy, enabled: false, domain_ready: false } });
    const view = render(page("local-sharing"));
    const toggle = await screen.findByRole("switch", { name: "Local Sharing" });
    expect(toggle).toHaveProperty("disabled", true); fireEvent.click(toggle);
    expect(mock.impact).not.toHaveBeenCalled();
    view.unmount();
    mock.policy.mockResolvedValue({ ok: true, data: { ...policy, domain_ready: false } });
    render(page("local-sharing"));
    fireEvent.click(await screen.findByRole("switch", { name: "Local Sharing" }));
    await screen.findByRole("dialog", { name: "Review Local Sharing activation" });
    expect(mock.impact).toHaveBeenCalledTimes(1);
  });

  it("withdraws a pending sharing review immediately when the actor changes", async () => {
    let finish!: (value: unknown) => void;
    mock.impact.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const view = render(page("local-sharing"));
    fireEvent.click(await screen.findByRole("switch", { name: "Local Sharing" }));
    mock.user = { id: "actor-b", email_verified: true };
    view.rerender(page("local-sharing", false));
    await screen.findByRole("switch", { name: "Local Sharing" });
    await act(async () => finish({ ok: true, data: { policy_version: 7, active_share_count: 0, affected_share_count: 0, affected_reviewer_session_count: 0, requires_confirmation: false } }));
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.getByRole("switch", { name: "Local Sharing" })).toHaveProperty("disabled", true);
    expect(mock.save).not.toHaveBeenCalled();
  });

  it("pauses alert delivery with the exact organization setting and preserves failed-write uncertainty", async () => {
    mock.PUT.mockRejectedValue(new Error("response lost"));
    render(page("alert-delivery"));
    const toggle = await screen.findByRole("switch", { name: "Alert delivery" });
    fireEvent.click(toggle);
    await screen.findByText("Could not confirm the change. Reload the saved setting before trying again.");
    expect(mock.PUT).toHaveBeenCalledExactlyOnceWith("/api/v1/organizations/{orgId}/alerting-settings", { params: { path: { orgId: "org-a" } }, body: { enabled: false } });
    expect(toggle.getAttribute("aria-checked")).toBe("true");
    expect(toggle).toHaveProperty("disabled", true); fireEvent.click(toggle);
    expect(mock.PUT).toHaveBeenCalledTimes(1);
  });

  it("keeps shelved Sandbox availability unavailable without requesting setup or changing activation", () => {
    render(page("sandboxes"));
    expect(screen.getByText("Unavailable in this product.")).toBeTruthy();
    expect(screen.queryByRole("switch")).toBeNull();
    expect(mock.GET).not.toHaveBeenCalled();
    expect(mock.PUT).not.toHaveBeenCalled();
  });
});

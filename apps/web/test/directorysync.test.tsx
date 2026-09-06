import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { IdpSyncSection } from "../src/pages/Settings";
import { api } from "../src/lib/api";
afterEach(cleanup);
const health = { provider: "okta", enabled: true, provisioning_allowed: true, client_id: "client", okta_org_url: "https://acme.okta.com", sso_connection_id: "22222222-2222-4222-8222-222222222222", sync_health: "ok", last_sync_ok: true };
function fakeClient() {
 return {
 GET: vi.fn(async (path: string) => path.endsWith("sso-connections") ? { data: { items: [{ id: health.sso_connection_id, name: "Workforce", issuer_url: health.okta_org_url, provider: "okta", enabled: true }] } } : path.endsWith("/health") ? { data: health } : { data: [] }),
 PUT: vi.fn(async (_path: string, _req: any): Promise<any> => ({ data: health })),
 POST: vi.fn(), DELETE: vi.fn(),
 };
}
async function open(client: ReturnType<typeof fakeClient>) {
 render(<IdpSyncSection orgId="org" provider="okta" role="owner" isEnterprise canEdit directoryAPI={client as unknown as typeof api} />);
 fireEvent.click(await screen.findByRole("button", { name: "Manage" }));
 await screen.findByText("Directory sync: Enabled");
}
it("preserves enabled state during signing-key rotation", async () => {
 const client = fakeClient(); await open(client);
 fireEvent.click(screen.getByRole("button", { name: "Replace credential" }));
 fireEvent.change(screen.getByRole("textbox", { name: "Private JWK" }), { target: { value: "sample-private-key" } });
 fireEvent.click(screen.getByRole("button", { name: "Save credential" }));
 await waitFor(() => expect(client.PUT).toHaveBeenCalledOnce());
 expect(client.PUT.mock.calls[0][1].body).toMatchObject({ enabled: true, client_id: "client", sso_connection_id: health.sso_connection_id });
});
it("serializes pause and rotation through the health refresh", async () => {
 const client = fakeClient(); let release!: (v: any) => void;
 client.PUT.mockImplementation(() => new Promise((resolve) => { release = resolve; }));
 await open(client); fireEvent.click(screen.getByRole("button", { name: "Replace credential" }));
 fireEvent.change(screen.getByRole("textbox", { name: "Private JWK" }), { target: { value: "sample-private-key" } });
 fireEvent.click(screen.getByRole("button", { name: "Pause directory sync" }));
 const save = screen.getByRole("button", { name: "Save credential" }) as HTMLButtonElement;
 expect(save.disabled).toBe(true);
 fireEvent.submit(save.closest("form")!);
 expect(client.PUT).toHaveBeenCalledOnce();
 let refreshed!: (v: any) => void;
 const prior = client.GET.getMockImplementation()!;
 client.GET.mockImplementation((path) => path.endsWith("/health") ? new Promise((resolve) => { refreshed = resolve; }) : prior(path));
 release({ data: { ...health, enabled: false } });
 await waitFor(() => expect(refreshed).toBeTypeOf("function"));
 expect(save.disabled).toBe(true);
 refreshed({ data: { ...health, enabled: false } });
 await screen.findByRole("button", { name: "Resume directory sync" });
 await waitFor(() => expect(save.disabled).toBe(false));
});

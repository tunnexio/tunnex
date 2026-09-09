import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { act, cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { RelayFallbackSettings } from "../src/components/RelayFallbackSettings";

const mocks = vi.hoisted(() => ({ GET: vi.fn(), PUT: vi.fn() }));
vi.mock("../src/lib/api", () => ({ api: mocks }));
const profile = { enabled: false, relay_url: "turns:relay.example:5349?transport=tcp", secret_configured: true, revision: 7 };
beforeEach(() => {
  vi.resetAllMocks();
  mocks.GET.mockResolvedValue({ data: profile });
  mocks.PUT.mockResolvedValue({ data: { ...profile, revision: 8 } });
});
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
async function mount(canEdit = true) {
  render(<RelayFallbackSettings key="org-a" orgId="org-a" canEdit={canEdit} />);
  await screen.findByRole("button", { name: "Save relay" });
}
describe("relay fallback configuration", () => {
  it("shows setup and saved state without claiming live readiness", async () => {
    await mount();
    expect(screen.getByText(/This is configuration status, not a connectivity test/)).toBeTruthy();
    expect(screen.getByText(/Saving does not test reachability/)).toBeTruthy();
    expect(screen.getByText(/does not stop coturn/)).toBeTruthy();
    expect((screen.getByLabelText("Relay shared secret") as HTMLInputElement).value).toBe("");
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
  });
  it("read-only callers cannot mutate", async () => {
    await mount(false);
    for (const control of screen.getAllByRole("button")) expect((control as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Save relay" }));
    expect(mocks.PUT).not.toHaveBeenCalled();
  });
  it("preserves a stored secret when left blank and sends the saved revision", async () => {
    await mount();
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "Save relay" }));
    await screen.findByText("Relay configuration saved.");
    expect(mocks.PUT).toHaveBeenCalledWith(expect.any(String), {
      params: { path: { orgId: "org-a" } },
      body: { enabled: true, relay_url: profile.relay_url, shared_secret: undefined, clear_secret: false, expected_revision: 7 },
    });
  });
  it("clears the submitted secret from the form after saving", async () => {
    await mount();
    fireEvent.change(screen.getByLabelText("Relay shared secret"), { target: { value: "test-only-secret-material-not-a-real-credential" } });
    fireEvent.click(screen.getByRole("button", { name: "Save relay" }));
    await screen.findByText("Relay configuration saved.");
    expect((screen.getByLabelText("Relay shared secret") as HTMLInputElement).value).toBe("");
  });
  it("cancelling removal performs no request", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    await mount();
    fireEvent.click(screen.getByRole("button", { name: "Remove configuration" }));
    expect(mocks.PUT).not.toHaveBeenCalled();
  });
  it("confirmed removal disables fallback and explicitly clears the stored secret", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    await mount();
    fireEvent.click(screen.getByRole("button", { name: "Remove configuration" }));
    await screen.findByText("Relay configuration saved.");
    expect(mocks.PUT.mock.calls[0][1].body).toEqual({ enabled: false, relay_url: "", shared_secret: undefined, clear_secret: true, expected_revision: 7 });
  });
  for (const failure of ["conflict", "network"]) {
    it(`${failure} requires reload before another save, never echoes raw errors`, async () => {
      await mount();
      if (failure === "conflict") mocks.PUT.mockResolvedValueOnce({ error: { message: "private-backend-detail" } });
      else mocks.PUT.mockRejectedValueOnce(new Error("private-backend-detail"));
      fireEvent.click(screen.getByRole("button", { name: "Save relay" }));
      await screen.findByRole("alert");
      expect(screen.queryByRole("button", { name: "Save relay" })).toBeNull();
      expect(screen.queryByText(/private-backend-detail/)).toBeNull();
      mocks.GET.mockResolvedValueOnce({ data: { ...profile, revision: 12 } });
      fireEvent.click(screen.getByRole("button", { name: "Reload" }));
      fireEvent.click(await screen.findByRole("button", { name: "Save relay" }));
      await screen.findByText("Relay configuration saved.");
      expect(mocks.PUT.mock.calls[1][1].body.expected_revision).toBe(12);
    });
  }
  it("load failure exposes retry without an editable configuration", async () => {
    mocks.GET.mockRejectedValueOnce(new Error("private-backend-detail"));
    render(<RelayFallbackSettings orgId="org-a" canEdit />);
    await screen.findByRole("alert");
    expect(screen.queryByRole("button", { name: "Save relay" })).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Reload" }));
    await screen.findByRole("button", { name: "Save relay" });
  });
  it("a delayed response from an unmounted org cannot replace the next org", async () => {
    let finish!: (result: unknown) => void;
    mocks.GET.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const view = render(<RelayFallbackSettings key="org-a" orgId="org-a" canEdit />);
    view.rerender(<RelayFallbackSettings key="org-b" orgId="org-b" canEdit />);
    await screen.findByRole("button", { name: "Save relay" });
    await act(async () => finish({ data: { ...profile, relay_url: "turns:old-org.example:5349?transport=tcp" } }));
    expect((screen.getByLabelText("TLS relay URL") as HTMLInputElement).value).toBe(profile.relay_url);
    fireEvent.click(screen.getByRole("button", { name: "Save relay" }));
    await waitFor(() => expect(mocks.PUT).toHaveBeenCalled());
    expect(mocks.PUT.mock.calls[0][1].params.path.orgId).toBe("org-b");
  });
  it("a pending save disables edits and its late result stays with the original org", async () => {
    let finish!: (result: unknown) => void;
    mocks.PUT.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
    const view = render(<RelayFallbackSettings key="org-a" orgId="org-a" canEdit />);
    fireEvent.click(await screen.findByRole("button", { name: "Save relay" }));
    expect((screen.getByLabelText("TLS relay URL") as HTMLInputElement).disabled).toBe(true);
    expect((screen.getByRole("button", { name: "Saving…" }) as HTMLButtonElement).disabled).toBe(true);
    fireEvent.click(screen.getByRole("button", { name: "Saving…" }));
    expect(mocks.PUT).toHaveBeenCalledTimes(1);
    view.rerender(<RelayFallbackSettings key="org-b" orgId="org-b" canEdit />);
    await screen.findByRole("button", { name: "Save relay" });
    await act(async () => finish({ data: { ...profile, enabled: true, revision: 99 } }));
    expect((screen.getByRole("checkbox") as HTMLInputElement).checked).toBe(false);
    expect(screen.queryByText("Relay configuration saved.")).toBeNull();
    expect(mocks.PUT.mock.calls[0][1].params.path.orgId).toBe("org-a");
  });
});

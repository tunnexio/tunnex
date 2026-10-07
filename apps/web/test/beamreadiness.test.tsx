import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { BeamDomainReadinessSettings } from "../src/components/BeamDomainReadinessSettings";
import { beamApi, type BeamReadiness, type BeamDomainSettings } from "../src/lib/beam";
vi.mock("../src/lib/beam", async () => { const actual = await vi.importActual<typeof import("../src/lib/beam")>("../src/lib/beam"); return { ...actual, beamApi: { ...actual.beamApi, readiness: vi.fn(), checkReadiness: vi.fn(), domainSettings: vi.fn(), saveDomainSettings: vi.fn() } }; });
const view: BeamReadiness = { base_domain: "beam.example.net", proxy_url: "https://connector.example.net:8443", portal_url: "https://console.example.com", settings_version: 1, configuration_version: "a".repeat(64), operator_asserted: true, checked_at: null, expires_at: null, passed: false, checks: [] };
const settings: BeamDomainSettings = { version: 1, source: "environment", operator_enabled: true, base_domain: "beam.example.net", proxy_url: "https://connector.example.net:8443", portal_url: "https://console.example.com", affected_active_shares: 0, authority_ready: false };
beforeEach(() => { vi.clearAllMocks(); vi.mocked(beamApi.domainSettings).mockResolvedValue({ ok: true, data: settings }); vi.mocked(beamApi.readiness).mockResolvedValue({ ok: true, data: view }); });
afterEach(cleanup);
describe("Beam operator measured serving checks", () => {
  it("does not convert operator assertion into measured readiness", async () => { render(<BeamDomainReadinessSettings canEdit />); await screen.findByText("Not checked"); expect(screen.getByText(/Serving is allowed by the operator.*Authority at last read: unavailable/)).toBeTruthy(); expect(screen.queryByText("Measured checks passed")).toBeNull(); expect(beamApi.checkReadiness).not.toHaveBeenCalled(); });
  it("shows failed reads and never substitutes a healthy default", async () => { vi.mocked(beamApi.readiness).mockResolvedValue({ ok: false, error: "Operator access denied" }); render(<BeamDomainReadinessSettings canEdit />); await screen.findByText("Operator access denied"); expect(screen.queryByText("Not checked")).toBeNull(); expect(screen.queryByRole("button", { name: "Check DNS and TLS" })).toBeNull(); });
  it("runs only the saved configuration version and shows individual repairs", async () => { vi.mocked(beamApi.checkReadiness).mockResolvedValue({ ok: true, data: { ...view, checked_at: new Date().toISOString(), expires_at: "2099-10-07T12:00:00Z", checks: [{ name: "wildcard_tls", passed: false, detail: "Renew the wildcard certificate." }] } }); render(<BeamDomainReadinessSettings canEdit />); fireEvent.click(await screen.findByRole("button", { name: "Check DNS and TLS" })); await screen.findByText("Setup needs repair"); expect(screen.getByText("Serving HTTPS certificate: Needs repair")).toBeTruthy(); expect(beamApi.checkReadiness).toHaveBeenCalledWith(view.configuration_version); });
  it("requires reload after a configuration conflict before another check", async () => { vi.mocked(beamApi.checkReadiness).mockResolvedValue({ ok: false, code: "beam_readiness_version_conflict", error: "Configuration changed" }); render(<BeamDomainReadinessSettings canEdit />); fireEvent.click(await screen.findByRole("button", { name: "Check DNS and TLS" })); await screen.findByText(/Configuration changed.*Reload serving configuration/); expect((screen.getByRole("button", { name: "Check DNS and TLS" }) as HTMLButtonElement).disabled).toBe(true); });
  it("marks previously passed but expired evidence unavailable", async () => { vi.mocked(beamApi.readiness).mockResolvedValue({ ok: true, data: { ...view, passed: true, checked_at: "2000-01-01T00:00:00Z", expires_at: "2000-01-01T00:05:00Z", checks: [{ name: "wildcard_dns", passed: true, detail: "Wildcard resolved." }] } }); render(<BeamDomainReadinessSettings canEdit />); await screen.findByText("Check expired"); expect(screen.queryByText("Measured checks passed")).toBeNull(); expect(screen.getByText("Wildcard DNS: Previously passed; expired")).toBeTruthy(); });
  it("requires verified operator editing permission to execute probes", async () => { render(<BeamDomainReadinessSettings canEdit={false} />); const button = await screen.findByRole("button", { name: "Check DNS and TLS" }); expect((button as HTMLButtonElement).disabled).toBe(true); fireEvent.click(button); expect(beamApi.checkReadiness).not.toHaveBeenCalled(); });
  it("refuses to check unsaved caller edits as arbitrary probe targets", async () => {
    render(<BeamDomainReadinessSettings canEdit />);
    fireEvent.change(await screen.findByRole("textbox", { name: "Beam connector endpoint" }), { target: { value: "https://different.example.net" } });
    expect((screen.getByRole("button", { name: "Check DNS and TLS" }) as HTMLButtonElement).disabled).toBe(true);
    expect(beamApi.checkReadiness).not.toHaveBeenCalled();
    expect(screen.queryByRole("textbox", { name: /Control-plane portal/ })).toBeNull();
  });
  it("requires an impact review and explicit active-share confirmation before saving versioned settings", async () => {
    vi.mocked(beamApi.domainSettings).mockResolvedValue({ ok: true, data: { ...settings, affected_active_shares: 2 } });
    vi.mocked(beamApi.saveDomainSettings).mockResolvedValue({ ok: true, data: { ...settings, version: 2, base_domain: "new-beam.example.net" } });
    render(<BeamDomainReadinessSettings canEdit />);
    fireEvent.change(await screen.findByRole("textbox", { name: "Beam serving domain" }), { target: { value: "new-beam.example.net" } });
    fireEvent.click(screen.getByRole("button", { name: "Review serving changes" }));
    await screen.findByRole("dialog", { name: "Review Beam serving change" });
    expect(beamApi.saveDomainSettings).not.toHaveBeenCalled();
    const submit = screen.getByRole("button", { name: "Save serving configuration" }) as HTMLButtonElement;
    expect(submit.disabled).toBe(true);
    fireEvent.click(screen.getByRole("checkbox", { name: "End all active shares affected by this configuration change" }));
    fireEvent.click(submit);
    await screen.findByText(/Serving configuration saved/);
    expect(beamApi.saveDomainSettings).toHaveBeenCalledWith({ expected_version: 1, operator_enabled: true, base_domain: "new-beam.example.net", proxy_url: settings.proxy_url, confirm_end_active_shares: true });
  });
  it("preserves serving edits after a conflict and requires saved-state reload", async () => {
    vi.mocked(beamApi.saveDomainSettings).mockResolvedValue({ ok: false, error: "Configuration changed" });
    render(<BeamDomainReadinessSettings canEdit />);
    fireEvent.change(await screen.findByRole("textbox", { name: "Beam serving domain" }), { target: { value: "new-beam.example.net" } });
    fireEvent.click(screen.getByRole("button", { name: "Review serving changes" }));
    fireEvent.click(await screen.findByRole("button", { name: "Save serving configuration" }));
    await screen.findByText(/Configuration changed.*Your edits are still shown/);
    expect((screen.getByRole("textbox", { name: "Beam serving domain" }) as HTMLInputElement).value).toBe("new-beam.example.net");
    expect((screen.getByRole("button", { name: "Review serving changes" }) as HTMLButtonElement).disabled).toBe(true);
  });
  it("refuses mismatched settings and readiness versions from overlapping operator changes", async () => {
    vi.mocked(beamApi.domainSettings).mockResolvedValue({ ok: true, data: { ...settings, version: 2 } });
    render(<BeamDomainReadinessSettings canEdit />);
    await screen.findByText(/Serving settings changed while loading/);
    expect((screen.getByRole("button", { name: "Check DNS and TLS" }) as HTMLButtonElement).disabled).toBe(true);
    expect(beamApi.checkReadiness).not.toHaveBeenCalled();
  });
});

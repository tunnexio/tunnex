import { describe, expect, it } from "vitest";
import { beamDiagnosticExport, type BeamDiagnostics, beamCanOpen, beamLaunchURL, beamStatus, type BeamShare } from "../src/lib/beam";
const share = { state: "active", connectivity: "online", can_open: true, expires_at: "2099-01-01T00:00:00Z" } as BeamShare;
describe("Beam reviewer boundary", () => {
  it("never labels an expired active projection live", () => { const expired = { ...share, expires_at: "2000-01-01T00:00:00Z" }; expect(beamStatus(expired)).toBe("Expired"); expect(beamCanOpen(expired)).toBe(false); });
  it.each(["http://p-1.beam.example.net/", "https://p-1.beam.example.net:8443/", "https://u:p@p-1.beam.example.net/", "https://foreign.example.net/"])("refuses unsafe launch URL %s", raw => { expect(beamLaunchURL(raw, "p-1.beam.example.net")).toBeNull(); });
  it("allows only the exact HTTPS share host", () => { expect(beamLaunchURL("https://p-1.beam.example.net/_beam/redeem?code=x", "p-1.beam.example.net")).toBe("https://p-1.beam.example.net/_beam/redeem?code=x"); });
});

 describe("Beam diagnostic redaction", () => {
  it("exports only safe fields even when a future response contains credential or topology fields", () => {
    const value = { share_id: "share", hostname: "p-1.beam.example.net", state: "active", connectivity: "online", version: 2, authority_version: 3, generation: "11111111-1111-4111-8111-111111111111", expires_at: "2099-01-01T00:00:00Z", domain_ready: true, status: "ready", reason: "ready", target: { address: "127.0.0.1", port: 3000, ca_pem: "PRIVATE-CA" }, connector_token: "PRIVATE-TOKEN", reviewer_email: "private@example.com", cookie: "PRIVATE-COOKIE" } as BeamDiagnostics;
    const json = JSON.stringify(beamDiagnosticExport(value));
    expect(json).toContain('"authority_version":3');
    expect(json).not.toMatch(/PRIVATE|127\.0\.0\.1|private@example|target|connector_token|cookie|reviewer_email/);
  });
});

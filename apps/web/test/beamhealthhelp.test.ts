import { describe, expect, it } from "vitest";
import { beamHealthNextStep } from "../src/components/BeamDiagnostics";
describe("Beam health actions", () => {
  it("gives origin repair instructions without asking for a new link", () => {
    expect(beamHealthNextStep({ reason: "ready", connectivity: "origin_unavailable" })).toContain("Start your local app on the port you published");
  });
  it("prioritizes ended authority over a disconnected connector", () => {
    expect(beamHealthNextStep({ reason: "share_ended", connectivity: "offline" })).toContain("An ended link cannot be restarted");
  });
  it("distinguishes installation setup from publisher connectivity", () => {
    expect(beamHealthNextStep({ reason: "domain_unavailable", connectivity: "offline" })).toContain("installation operator");
    expect(beamHealthNextStep({ reason: "connector_offline", connectivity: "offline" })).toContain("publishing terminal or desktop client");
  });
});

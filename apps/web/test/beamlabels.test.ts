import { describe, expect, it } from "vitest";
import { beamActionLabel, beamConnectivityLabel, beamOutcomeLabel, beamStateLabel, beamWords } from "../src/lib/beam";

// LS-UX-1: Local Sharing events and diagnostics show words, never raw codes.
describe("Local Sharing labels", () => {
  it("names known codes and keeps unknown ones readable", () => {
    expect(beamActionLabel("beam.access.denied")).toBe("Reviewer access refused");
    expect(beamActionLabel("beam.future.thing")).toBe("Future thing");
    expect(beamStateLabel("revoked")).toBe("Ended by a policy or server change");
    expect(beamConnectivityLabel("origin_unavailable")).toBe("Local app unavailable");
    expect(beamOutcomeLabel("denied")).toBe("Refused");
    expect(beamWords("grant_removed")).toBe("Grant removed");
    expect(beamWords("")).toBe("");
  });
});

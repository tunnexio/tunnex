import { describe, expect, it } from "vitest";
import { ceilingSentence } from "../src/components/CeilingUpgrade";

// ⛔ AT-CEILING AND OVER-CEILING ARE DIFFERENT SENTENCES, AND THE WRONG ONE CAUSES A DESTRUCTIVE MISTAKE.
describe("the standing ceiling notice", () => {
  it("at the ceiling, offers retiring as a real route AND names what it costs", () => {
    const s = ceilingSentence(1, 1, "community");
    expect(s).toContain("no room for another");
    expect(s).toContain("retire a gateway");
    // ⛔ THE CLAUSE THAT STOPS THIS READING AS HOUSEKEEPING. Revoking cascades to every device homed to
    // that gateway, so the remedy this notice recommends can disconnect fifty people. "Revoke a gateway
    // you no longer use" was TRUE and named none of that.
    expect(s).toContain("permanent");
    // ⛔ AND IT STATES THE PRECONDITION, NOT AN OUTAGE. Since S12.12 the revoke is REFUSED while devices
    // are homed there, so an operator who reads "disconnects everyone" is being warned about something
    // that can no longer happen — and is NOT being told about the work that will.
    expect(s).toContain("cannot be retired while devices are homed to it");
    expect(s).toContain("move them to another gateway first");
    // ⚠ THE RE-ISSUE IS THE PART THAT SURPRISES, and the ceiling is the last moment it can be planned for.
    expect(s).toContain("re-issues their configurations");
    // Neither superseded phrasing may survive anywhere in the string.
    expect(s).not.toContain("you no longer use");
    expect(s).not.toContain("disconnects every device");
  });

  // ⭐ THE ONE THAT MATTERS TODAY. At 6 against 1, revoking a gateway frees NOTHING — five would still be
  // over. Telling that operator "no room left" invites them to revoke one and retry, which fails, and now
  // they have destroyed a working gateway for nothing.
  it("past the ceiling, says how far over and does NOT offer revoking", () => {
    const s = ceilingSentence(6, 1, "community");
    expect(s).toContain("6 are enrolled");
    expect(s).toContain("5 past the limit");
    expect(s).toContain("Revoking one will not free a slot");
    expect(s).not.toContain("retire a gateway");
  });

  // ⚠ BOTH SENTENCES PROMISE THE SAME THING FIRST, because the operator's real question is "is my fleet
  // about to stop", and the answer is no.
  it("always says nothing running is affected", () => {
    expect(ceilingSentence(6, 1, "community")).toContain(
      "Nothing running is affected",
    );
  });

  it("pluralises the ceiling", () => {
    expect(ceilingSentence(2, 2, "trial")).toContain("allows 2 gateways");
    expect(ceilingSentence(1, 1, "community")).toContain("allows 1 gateway");
  });
});

import { describe, it, expect } from "vitest";
import { siteLinkExposure } from "../src/lib/sitelinkview";

// SSI-4 (finding F2): the wizard says what a new range links before it is applied.
describe("siteLinkExposure", () => {
  const others = [
    { name: "eu-lan", ranges: ["10.30.0.0/24"] },
    { name: "ap-lan", ranges: ["10.40.1.0/24", "10.40.0.0/24"] },
  ];

  it("says nothing when there is no second side", () => {
    expect(siteLinkExposure({ mode: "off", newRange: "10.50.1.0/24", others: [] })).toBeNull();
    // A network whose ranges are all pending is routed nowhere, so it is not a second side either.
    expect(siteLinkExposure({ mode: "off", newRange: "10.50.1.0/24", others: [{ name: "draft", ranges: [] }] })).toBeNull();
  });

  it("with enforcement off, names what opens and requires an acknowledgement", () => {
    const e = siteLinkExposure({ mode: "off", newRange: " 10.50.1.0/24 ", others });
    expect(e?.kind).toBe("open");
    expect(e?.heading).toBe("This opens 10.50.1.0/24 to 2 other networks");
    expect(e?.body).toContain("on every port");
    expect(e?.acknowledgement).toBe("I understand this link is open in both directions");
    // Stable order whatever the API returned.
    expect(e?.networks.map((n) => n.name)).toEqual(["ap-lan", "eu-lan"]);
    expect(e?.networks[0].ranges).toEqual(["10.40.0.0/24", "10.40.1.0/24"]);
  });

  it("with enforcement on, says nothing crosses without a rule and asks for nothing", () => {
    const e = siteLinkExposure({ mode: "enforcing", newRange: "10.50.1.0/24", others: [others[0]] });
    expect(e?.kind).toBe("rules");
    expect(e?.heading).toBe("This links 10.50.1.0/24 to 1 other network");
    expect(e?.acknowledgement).toBeNull();
  });

  it("never guesses the safe mode when it could not be read", () => {
    const e = siteLinkExposure({ mode: "unknown", newRange: "10.50.1.0/24", others });
    expect(e?.kind).toBe("unknown");
    expect(e?.body).toContain("could not be read");
    expect(e?.acknowledgement).not.toBeNull();
  });
});

import { describe, expect, it } from "vitest";
import {
  revokeConsequence,
  transferConsequence,
} from "../src/lib/gatewaysview";

// ⛔ THE COPY THAT WAS TRUE UNTIL THE COMMIT THAT SHIPPED TRANSFER.
//
// Revoking a gateway cascaded to every device homed on it, so "they stop connecting immediately" was
// accurate and this test asserted it. The revoke now REFUSES while any device is homed there, which makes
// the old sentence a warning about something that cannot happen — and, worse, silence about the thing that
// will: the operator has work to do first. The assertions moved in the same commit as the behaviour, which
// is the whole discipline: copy describing a flow the product does not have is the defect docs/laws.md
// records twice this cycle.
describe("the revoke confirm", () => {
  it("with devices homed there, INSTRUCTS rather than warns \u2014 the revoke will be refused", () => {
    const s = revokeConsequence({ "gw-1": 3 }, "gw-1");
    expect(s).toContain("3 devices are homed here");
    expect(s).toContain("cannot be retired yet");
    expect(s).toContain("move them to another gateway first");
    // The permanence is still stated: it is why the order matters.
    expect(s).toContain("never active again");
    // ⛔ AND THE SUPERSEDED CLAIM IS GONE. A confirm that still promised an immediate disconnection would
    // be describing the pre-transfer product to an operator using the post-transfer one.
    expect(s).not.toContain("stop connecting");
  });

  it("pluralises down to one device without reading as a template", () => {
    const s = revokeConsequence({ "gw-1": 1 }, "gw-1");
    expect(s).toContain("1 device is homed here");
    expect(s).toContain("move it to another gateway first");
  });

  // ⚠ SILENT ON THE HARMLESS CASE. A caution that fires when nothing is at stake is a caution nobody reads
  // when something is \u2014 but the PERMANENCE is a fact about the gateway and holds at zero devices.
  it("with nothing homed there, states only the permanence", () => {
    const s = revokeConsequence({ "gw-1": 0 }, "gw-1");
    expect(s).toContain("never active again");
    expect(s).not.toContain("homed here");
  });

  // ⛔ AN UNREADABLE COUNT IS NOT ZERO. A silent all-clear manufactured by a failed fetch is the worst
  // possible output for the one sentence whose job is to stop a destructive click \u2014 and here it would
  // also promise a revoke the server may refuse.
  it("when the count could not be read, says so and does NOT report zero", () => {
    const s = revokeConsequence(null, "gw-1");
    expect(s).toContain("could not be counted");
    expect(s).toContain("refused");
    expect(s).toContain("never active again");
  });
});

describe("the transfer confirm", () => {
  // ⛔ THE RE-IMPORT LEADS, because moving the row is the easy half. Every issued config bakes its
  // gateway's endpoint and public key, so a moved device holds a config naming a gateway that will not
  // serve it \u2014 the failure this sentence exists to pre-empt.
  it("names the re-import before the click", () => {
    const s = transferConsequence(4, false);
    expect(s).toContain("4 devices will move");
    expect(s).toContain("re-import");
    // Same-site moves must NOT claim a policy change; a warning that fires either way is not a warning.
    expect(s).not.toContain("DIFFERENT SITE");
  });

  // ⛔ D5. Site-scoped policy is evaluated against the device's GATEWAY'S SITE, so a cross-site move
  // changes which rules apply. That is a grant or a revocation arriving as a side effect of maintenance,
  // and a move that does not say so is a silent access change wearing a maintenance label.
  it("says a cross-site move changes which rules apply", () => {
    const s = transferConsequence(4, true);
    expect(s).toContain("DIFFERENT SITE");
    expect(s).toContain("rules that apply");
    expect(s).toContain("widen or narrow");
  });

  it("pluralises down to one device", () => {
    const s = transferConsequence(1, true);
    expect(s).toContain("1 device will move");
    expect(s).toContain("its owner");
    expect(s).toContain("this device");
  });
});

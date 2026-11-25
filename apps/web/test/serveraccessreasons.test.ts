import { describe, expect, it } from "vitest";
import { serverAccessReason, serverAccessReasonCodes, serverAccessReasonText, sessionReasonText } from "../src/lib/serverAccessReasons";

describe("Server Access reasons (SA-UX-2 item 8)", () => {
  it("has a human sentence with no raw code for every known code", () => {
    // The Go test TestEveryServerAccessCodeHasWebText keeps this list in step with the API and gateway.
    expect(serverAccessReasonCodes.length).toBeGreaterThan(80);
    for (const code of serverAccessReasonCodes) {
      for (const text of [sessionReasonText(code), serverAccessReasonText(code)]) {
        expect(text, code).not.toContain(code);
        expect(text, code).not.toMatch(/[a-z]_[a-z]/);
        expect(text.endsWith("."), code).toBe(true);
      }
    }
    expect(sessionReasonText("server_access_disabled")).toMatch(/turned off for this installation/);
  });
  it("gives the reachability next step for ssh_unreachable", () => {
    expect(serverAccessReason("ssh_unreachable").next).toMatch(/Allow TCP from the gateway/);
  });
  it("explains every target setup refusal with a next step (SA-UX-3)", () => {
    const setup = serverAccessReasonCodes.filter(code => code.startsWith("setup_") && !["setup_failed", "setup_expired", "setup_capacity", "setup_in_progress", "setup_not_ready"].includes(code));
    expect(setup.length).toBe(23);
    for (const code of setup) expect(serverAccessReason(code).next, code).toBeTruthy();
    // A leftover unit has no managed configuration, so the helper's remove command would refuse; never suggest it.
    expect(serverAccessReasonText("setup_existing_setup")).not.toMatch(/tunnex-browser-ssh remove/);
    expect(serverAccessReasonText("setup_identity_differs")).toMatch(/SSH port/);
    expect(serverAccessReasonText("setup_failed")).toMatch(/journalctl -t tunnex-browser-ssh/);
  });
  it("never humanizes an unknown code and is empty for none", () => {
    expect(sessionReasonText("some_new_reason")).toBe("Server Access could not complete this action.");
    expect(serverAccessReasonText("some_new_reason")).not.toMatch(/some new reason/i);
    expect(sessionReasonText("")).toBe("");
  });
});

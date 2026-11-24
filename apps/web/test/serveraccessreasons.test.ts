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
  it("never humanizes an unknown code and is empty for none", () => {
    expect(sessionReasonText("some_new_reason")).toBe("Server Access could not complete this action.");
    expect(serverAccessReasonText("some_new_reason")).not.toMatch(/some new reason/i);
    expect(sessionReasonText("")).toBe("");
  });
});

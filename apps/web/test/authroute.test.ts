import { describe, it, expect } from "vitest";
import { loginDestination, resolveMfaGateRoute } from "../src/lib/authroute";

// Pins the MFA-enrollment gate's client routing in BOTH directions (S7.5.5 D8 + the WF-3 UI-walk
// finding). The original code had only the confinement direction; a user whose gate had cleared while
// on /enroll-mfa was stranded there with no exit. The WF-3 case below is the release journey — it
// fails loudly if the release branch is ever removed, so the trap cannot silently return.
describe("resolveMfaGateRoute — MFA-enrollment gate routing (confine + release)", () => {
  it("gated user OFF the ceremony → confined to /enroll-mfa", () => {
    expect(resolveMfaGateRoute(true, "/dashboard")).toBe("/enroll-mfa");
    expect(resolveMfaGateRoute(true, "/settings")).toBe("/enroll-mfa");
    expect(resolveMfaGateRoute(true, "/users")).toBe("/enroll-mfa");
  });

  it("gated user ON the ceremony → stays put (no redirect loop)", () => {
    expect(resolveMfaGateRoute(true, "/enroll-mfa")).toBeNull();
  });

  it("WF-3: NON-gated user stranded on the ceremony → RELEASED to the app", () => {
    // The exact trap: enrollment confirmed (or a stale flag) → gate false, still on /enroll-mfa.
    // Must route out, not dead-end.
    expect(resolveMfaGateRoute(false, "/enroll-mfa")).toBe("/dashboard");
  });

  it("non-gated user already in the app → render through (no redirect)", () => {
    expect(resolveMfaGateRoute(false, "/dashboard")).toBeNull();
    expect(resolveMfaGateRoute(false, "/settings")).toBeNull();
  });
});

describe("login destination", () => {
  it("preserves the CLI consent query through authentication", () => {
    const path = "/cli-auth?redirect_uri=http%3A%2F%2F127.0.0.1%3A54321%2Fcallback&state=opaque";
    expect(loginDestination(path)).toBe(path);
  });
  it.each([null, "https://evil.example", "//evil.example", "/\\evil.example", "/\nevil", "/login", "/login?next=/login", "/login/"])("rejects unsafe or recursive destination %s", next => {
    expect(loginDestination(next)).toBe("/dashboard");
  });
});

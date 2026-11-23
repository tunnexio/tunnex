import { describe, expect, it } from "vitest";
import { accessTestLink, blockerAdvice, parseAccessTest } from "../src/lib/accesstest";

describe("Test access links", () => {
  it("round-trips who and what to test", () => {
    const request = { kind: "device" as const, id: "0f1e2d3c-aaaa-bbbb-cccc-000000000001", destination: "100.65.0.3", protocol: "tcp" as const, port: 80 };
    const link = accessTestLink(request);
    expect(link.startsWith("/access?")).toBe(true);
    expect(parseAccessTest(link.slice(link.indexOf("?")))).toEqual(request);
  });
  it("ignores a malformed subject and drops invalid parts instead of half-applying them", () => {
    expect(parseAccessTest("?test=user:1")).toBeNull();
    expect(parseAccessTest("?test=device:")).toBeNull();
    expect(parseAccessTest("?test=device:abc&proto=icmp&port=70000")).toEqual({ kind: "device", id: "abc" });
  });
});

describe("blocker advice", () => {
  it("says what the blocker means and where it is fixed", () => {
    expect(blockerAdvice("no_matching_grant")?.action?.to).toBe("/access");
    expect(blockerAdvice("posture_blocked")?.action?.to).toBe("/devices/posture");
    expect(blockerAdvice("device_dns_not_observed")?.action).toBeUndefined();
  });
  it("gives no advice for a code it does not know", () => {
    expect(blockerAdvice("something_new")).toBeNull();
  });
});

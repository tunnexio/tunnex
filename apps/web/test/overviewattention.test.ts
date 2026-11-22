import { describe, expect, it } from "vitest";
import { attentionItems } from "../src/lib/overviewview";

const clear = { pendingApprovals: 0, unhealthyGateways: 0, unownedGateways: 0, blockedDevices: 0, zeroTrust: "enforcing" as const, rules: 2 };

describe("Overview — what is waiting for the operator", () => {
  it("is empty and fully read when every check came back clean", () => {
    expect(attentionItems(clear)).toEqual({ items: [], unread: 0 });
  });

  it("never calls an unread check clean", () => {
    const result = attentionItems({ ...clear, unhealthyGateways: null, unownedGateways: null });
    expect(result.items).toEqual([]);
    expect(result.unread).toBe(2);
  });

  it("orders failures before reviews and links each to where it is fixed", () => {
    const { items } = attentionItems({ pendingApprovals: 2, unhealthyGateways: 1, unownedGateways: 3, blockedDevices: 1, zeroTrust: "not enforced", rules: 4 });
    expect(items.map(item => [item.key, item.tone, item.to])).toEqual([
      ["gateways", "danger", "/gateways"],
      ["blocked", "danger", "/devices"],
      ["approvals", "warn", "/devices/approvals"],
      ["zero-trust", "warn", "/access"],
      ["owners", "warn", "/gateways"],
    ]);
    expect(items[0]!.text).toBe("1 gateway reports a health problem");
    expect(items[2]!.text).toBe("2 devices are waiting for approval");
    expect(items[3]!.text).toBe("4 access rules are written but not enforced");
  });

  it("does not nag about enforcement when there are no rules to enforce", () => {
    expect(attentionItems({ ...clear, zeroTrust: "not enforced", rules: 0 }).items).toEqual([]);
  });
});

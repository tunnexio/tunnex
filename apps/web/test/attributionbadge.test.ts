import { describe, expect, it } from "vitest";
import { attributionBadge, gatewayHealthRow } from "../src/lib/healthview";

// ⛔ ATTRIBUTION AND HEALTH ARE TWO QUESTIONS, AND THE TEST'S JOB IS TO KEEP THEM APART.
//
// Policy health asks *is this gateway enforcing what the control plane believes it is enforcing*.
// Attribution asks *can we say who authorised it into the org*. A gateway can be perfectly healthy and
// unattributable at once — so a single badge would force a choice between reporting an enforcement problem
// and reporting an accountability one.
describe("the attribution badge — S15.2 / D25(C)", () => {
  it("⛔ an unattributable gateway is FLAGGED, not refused — and says what it means", () => {
    const b = attributionBadge({ unattributable: true });
    expect(b).not.toBeNull();
    expect(b!.label).toMatch(/unattributable/i);
    // ⚠ TONE IS THE RULING. An unattributable tunnel is a LOGGING failure, not an access-control one —
    // the policy engine still enforces every rule. Painting it danger would claim a security failure that
    // has not occurred.
    expect(b!.tone).toBe("warn");
    expect(b!.detail).toMatch(/keeps running/i);
    expect(b!.detail).toMatch(/audit trail, not in access control/i);
  });

  it("an attributable gateway carries NO badge — without this the flag could be a constant", () => {
    expect(attributionBadge({ unattributable: false })).toBeNull();
  });

  it("⛔ HEALTHY AND UNATTRIBUTABLE AT THE SAME TIME — the case a merged badge could not report", () => {
    const node = {
      status: "active" as const,
      policy_degraded: false,
      policy_degraded_kind: undefined,
      unattributable: true,
    };
    // The health verdict is untouched by attribution...
    expect(gatewayHealthRow(node).tone).toBe("ok");
    // ...and the attribution badge is present anyway. Both facts, independently reportable.
    expect(attributionBadge(node)).not.toBeNull();
  });

  it("⛔ a REVOKED gateway still reports attribution — revocation does not answer the question", () => {
    // Revoking a gateway says nothing about who authorised it into the org, and the audit trail is
    // MORE interesting for a revoked node, not less.
    const node = {
      status: "revoked" as const,
      policy_degraded: false,
      policy_degraded_kind: undefined,
      unattributable: true,
    };
    expect(gatewayHealthRow(node).label).toBe("revoked");
    expect(attributionBadge(node)).not.toBeNull();
  });
});

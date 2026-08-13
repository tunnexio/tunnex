import { describe, expect, it } from "vitest";
import {
  REVOKED_CAUSE_NOTE,
  canResend,
  canRevoke,
  invitationState,
  inviteErrorCopy,
  inviteGate,
  inviterLabel,
  orderInvitations,
  outstandingCount,
  stateLabel,
  type Invitation,
} from "../src/lib/invitationview";

const NOW = new Date("2026-08-03T12:00:00Z");
const iso = (d: string) => new Date(d).toISOString();

function inv(over: Partial<Invitation> = {}): Invitation {
  return {
    id: "i1",
    email: "a@acme.io",
    role: "member",
    expires_at: iso("2026-08-10T12:00:00Z"),
    created_at: iso("2026-08-01T12:00:00Z"),
    ...over,
  };
}

// ⛔ FOUR STATES, THREE STORED. The table holds accepted_at and revoked_at and nothing else;
// `expired` is DERIVED from expires_at against the clock, which is why the server does not store
// it — a stored status is correct at write time and wrong a day later.
describe("invitationState", () => {
  it("derives expired from the clock, not from a column", () => {
    expect(
      invitationState(inv({ expires_at: iso("2026-08-01T00:00:00Z") }), NOW),
    ).toBe("expired");
    expect(invitationState(inv(), NOW)).toBe("pending");
  });

  it("⛔ treats an accepted-and-past-expiry row as ACCEPTED, not expired", () => {
    // Redemption already happened, so the clock is no longer interesting. Getting this backwards
    // would offer Resend/Revoke on a row that is already a member — controls the server ignores.
    const row = inv({
      accepted_at: iso("2026-07-20T00:00:00Z"),
      expires_at: iso("2026-07-25T00:00:00Z"),
    });
    expect(invitationState(row, NOW)).toBe("accepted");
  });

  it("⛔ treats a revoked-and-past-expiry row as REVOKED, not expired", () => {
    const row = inv({
      revoked_at: iso("2026-07-20T00:00:00Z"),
      expires_at: iso("2026-07-25T00:00:00Z"),
    });
    expect(invitationState(row, NOW)).toBe("revoked");
  });

  it("expires ON the boundary, not after it", () => {
    expect(invitationState(inv({ expires_at: NOW.toISOString() }), NOW)).toBe(
      "expired",
    );
  });
});

// ⛔ CONTROLS ONLY WHERE THE SERVER WOULD ACT. RevokeInvitationByOrgEmail updates
// `WHERE … accepted_at IS NULL AND revoked_at IS NULL`, so on a terminal row it matches zero rows,
// changes nothing, and returns success — a button that lies is worse than no button.
describe("canResend / canRevoke", () => {
  it("offers nothing on a terminal row", () => {
    for (const s of ["accepted", "revoked"] as const) {
      expect(canResend(s)).toBe(false);
      expect(canRevoke(s)).toBe(false);
    }
  });

  it("⛔ offers RESEND on an expired row — it is the only recovery path", () => {
    // Resend mints a NEW token and invalidates the old one. There is no "extend", so withholding
    // it here would strand the row with no way forward but a fresh invite.
    expect(canResend("expired")).toBe(true);
    expect(canRevoke("expired")).toBe(true);
  });

  it("offers both on a pending row", () => {
    expect(canResend("pending")).toBe(true);
    expect(canRevoke("pending")).toBe(true);
  });
});

describe("inviteGate", () => {
  it("hides the panel from anyone without member:invite", () => {
    expect(inviteGate("member")).toEqual({ kind: "hidden" });
    expect(inviteGate(null)).toEqual({ kind: "hidden" });
    expect(inviteGate(undefined)).toEqual({ kind: "hidden" });
  });

  it("is ready for the roles that hold it", () => {
    expect(inviteGate("admin")).toEqual({ kind: "ready" });
    expect(inviteGate("owner")).toEqual({ kind: "ready" });
  });
});

// ⛔ THE COUNT THE PANEL MAY NAME. Only outstanding rows — pending plus expired. An accepted
// invitation is a member now and is already counted on the roster.
describe("outstandingCount", () => {
  it("counts pending and expired, never accepted or revoked", () => {
    const rows = [
      inv({ id: "p" }),
      inv({ id: "e", expires_at: iso("2026-08-01T00:00:00Z") }),
      inv({ id: "a", accepted_at: iso("2026-07-01T00:00:00Z") }),
      inv({ id: "r", revoked_at: iso("2026-07-01T00:00:00Z") }),
    ];
    expect(outstandingCount(rows, NOW)).toBe(2);
  });

  it("is zero on an empty list rather than throwing", () => {
    expect(outstandingCount([], NOW)).toBe(0);
  });
});

// The server returns newest-first, which buries the rows that need action under historical ones.
describe("orderInvitations", () => {
  it("floats actionable states above terminal ones", () => {
    const rows = [
      inv({
        id: "acc",
        accepted_at: iso("2026-08-02T00:00:00Z"),
        created_at: iso("2026-08-02T00:00:00Z"),
      }),
      inv({
        id: "rev",
        revoked_at: iso("2026-08-02T00:00:00Z"),
        created_at: iso("2026-08-02T00:00:00Z"),
      }),
      inv({
        id: "exp",
        expires_at: iso("2026-08-01T00:00:00Z"),
        created_at: iso("2026-07-01T00:00:00Z"),
      }),
      inv({ id: "pend", created_at: iso("2026-07-01T00:00:00Z") }),
    ];
    expect(orderInvitations(rows, NOW).map((r) => r.id)).toEqual([
      "pend",
      "exp",
      "rev",
      "acc",
    ]);
  });

  it("keeps newest-first within a group", () => {
    const rows = [
      inv({ id: "old", created_at: iso("2026-07-01T00:00:00Z") }),
      inv({ id: "new", created_at: iso("2026-08-02T00:00:00Z") }),
    ];
    expect(orderInvitations(rows, NOW).map((r) => r.id)).toEqual([
      "new",
      "old",
    ]);
  });

  it("does not mutate the caller's array", () => {
    const rows = [
      inv({ id: "a" }),
      inv({ id: "b", created_at: iso("2026-08-02T00:00:00Z") }),
    ];
    orderInvitations(rows, NOW);
    expect(rows.map((r) => r.id)).toEqual(["a", "b"]);
  });
});

// ⛔ THE INVITER CAN BE GONE — invited_by_user_id is ON DELETE SET NULL, and the query LEFT JOINs
// so the row survives. An inner join would DROP it, hiding an outstanding invitation precisely
// because its sender left, which is the failure this whole endpoint exists to end.
describe("inviterLabel", () => {
  it("names the deleted account rather than rendering blank", () => {
    expect(inviterLabel(inv({ invited_by_email: null }))).toMatch(/deleted/i);
    expect(inviterLabel(inv({ invited_by_email: "" }))).toMatch(/deleted/i);
    expect(inviterLabel(inv({ invited_by_email: "   " }))).toMatch(/deleted/i);
  });

  it("uses the address when there is one", () => {
    expect(inviterLabel(inv({ invited_by_email: "o@acme.io" }))).toBe(
      "o@acme.io",
    );
  });
});

describe("REVOKED_CAUSE_NOTE", () => {
  it("⛔ names the OTHER cause without claiming which one happened", () => {
    // SupersedePendingInvites revokes on a domain-capture JIT join, and the table records no
    // cause — so asserting "this was superseded" would be a second source of truth.
    expect(REVOKED_CAUSE_NOTE).toMatch(/either/i);
    expect(REVOKED_CAUSE_NOTE).toMatch(/superseded/i);
    expect(REVOKED_CAUSE_NOTE).toMatch(/domain/i);
  });
});

describe("stateLabel", () => {
  it("labels every state", () => {
    expect(
      (["pending", "expired", "accepted", "revoked"] as const).map(stateLabel),
    ).toEqual(["PENDING", "EXPIRED", "ACCEPTED", "REVOKED"]);
  });
});

// Codes READ OFF invites.Service, not guessed — the first draft invented two the service cannot
// emit, which is untestable against the server by definition.
describe("inviteErrorCopy", () => {
  it("points a duplicate-invite conflict at the list that now exists", () => {
    // invites.go:109 has always said "resend or revoke it" — advice about two verbs that had no
    // surface, on a row nobody could see.
    expect(inviteErrorCopy("invite_pending")).toMatch(/resend or revoke/i);
  });

  it("covers the service's other codes", () => {
    expect(inviteErrorCopy("invite_not_pending")).toMatch(
      /no pending invitation/i,
    );
    expect(inviteErrorCopy("invalid_role")).toMatch(/role/i);
    expect(inviteErrorCopy("account_deactivated")).toMatch(/deactivated/i);
  });

  it("does not invent a diagnosis", () => {
    expect(inviteErrorCopy("brand_new")).toBe(
      "Could not complete the request.",
    );
    expect(inviteErrorCopy(null)).toBe("Could not complete the request.");
  });
});

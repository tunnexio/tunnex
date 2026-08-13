import { describe, expect, it, afterEach, vi, beforeEach } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import { MachineCredentials } from "../src/components/MachineCredentials";
import * as apiMod from "../src/lib/api";

// ⛔ THE THREE EMPTY STATES ARE THE POINT OF THIS SCREEN, AND THE THIRD IS WHY IT IS HARD.
//
// none · all owned · THE LIST FAILED TO LOAD. An unreachable query rendering as an empty list is
// "migration complete" written by an error path — and this is a MIGRATION screen, so that is precisely the
// reassurance that must be earned rather than defaulted to.
//
// The component previously used a raw `api.GET`, which is review-refused on a list whose emptiness is
// user-meaningful: a non-2xx and a network REJECTION are different paths, and reading only `data` renders a
// reassuring "none" for both.

const ORG = "11111111-1111-1111-1111-111111111111";

function cred(over: Partial<Record<string, unknown>> = {}) {
  return {
    id: String(over.id ?? "c1"),
    name: String(over.name ?? "gitops"),
    fingerprint: "fp-abc",
    created_at: new Date(Date.now() - 86_400_000).toISOString(),
    last_used_at: over.last_used_at ?? null,
    owner_user_id: over.owner_user_id ?? null,
    // ⛔ POPULATED BY THE SERVER (D22 ruled). It was documented-and-always-null before, which is what
    // let the first consumer read it and render "unknown" on every owned row. The handler now resolves
    // it by LEFT JOIN on `users`, so it survives the owner leaving the org — `in`, not `??`, because a
    // nullable field cannot be overridden to null by a coalescing default.
    owner_email:
      "owner_email" in over
        ? over.owner_email
        : over.owner_user_id
          ? "owner@demo.tunnex.local"
          : null,
  };
}

/** GET returns per-path fixtures; anything unlisted rejects, which is itself the failure case. */
function stubGet(byPath: Record<string, unknown>) {
  vi.spyOn(apiMod.api, "GET").mockImplementation((async (path: string) => {
    if (path in byPath) {
      const v = byPath[path];
      if (v === "REJECT") return Promise.reject(new Error("network down"));
      return { data: v };
    }
    return { data: [] };
  }) as never);
}

beforeEach(() => vi.restoreAllMocks());
afterEach(() => {
  cleanup();
  vi.restoreAllMocks();
});

const LIST = "/api/v1/organizations/{orgId}/machine-credentials";
const MEMBERS = "/api/v1/organizations/{orgId}/members";

describe("⛔ the three empty states are distinguishable", () => {
  it("NONE — no credentials exist, and it says there is nothing to assign", async () => {
    stubGet({ [LIST]: [], [MEMBERS]: [] });
    render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(screen.getByText(/no machine credentials exist/i)).toBeTruthy(),
    );
    expect(document.querySelector('[data-state="load-failed"]')).toBeNull();
  });

  it("⛔ FAILED TO LOAD is NOT 'none' — the state this screen exists to keep apart", async () => {
    stubGet({ [LIST]: "REJECT", [MEMBERS]: [] });
    render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(
        document.querySelector('[data-state="load-failed"]'),
      ).not.toBeNull(),
    );
    // The failure must NOT be readable as absence, and must say so in words.
    expect(screen.queryByText(/no machine credentials exist/i)).toBeNull();
    expect(screen.getByText(/not the same as having none/i)).toBeTruthy();

    // ⚠ SHIPPING COPY: the message is concatenated from two sources with different punctuation
    // conventions — the client's own fallbacks are written as sentences ("Could not reach the API."),
    // while apiErrorMessage returns the SERVER's message, whose punctuation is not ours to assume.
    // Appending "." unconditionally shipped "Could not reach the API..".
    const failed = document.querySelector('[data-state="load-failed"]')!;
    expect(failed.textContent).not.toMatch(/\.\./);
  });

  it("ALL OWNED — earned, and rendered ABOVE the rows", async () => {
    stubGet({
      [LIST]: [cred({ id: "c1", owner_user_id: "u1" })],
      [MEMBERS]: [],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(
        container.querySelector('[data-state="all-owned"]'),
      ).not.toBeNull(),
    );
    // ⚠ ORDER IS THE ASSERTION. A qualifier under a list is read after the list is already believed.
    const banner = container.querySelector('[data-state="all-owned"]')!;
    // ⚠ The panel is a DataTable now, not a <ul>. The claim is unchanged — the refusal banner sits ABOVE
    // the rows — only the element carrying "the rows" is different.
    const list = container.querySelector("table")!;
    expect(
      banner.compareDocumentPosition(list) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();

    // ⛔ IT IS A CLAIM ABOUT OWNERSHIP, NOT ABOUT HEALTH. It knows one predicate — nothing is refused
    // for want of an owner. It cannot know the fleet is well: a credential may be revoked, dead at the
    // far end, or owned by someone who has left. The first version said "the migration is complete for
    // this organization", which reads as "everything is fine" AND is false on its own terms — step 4,
    // the NOT NULL contract, has not run.
    expect(banner.textContent).toMatch(/none is being refused/i);
    for (const overclaim of [
      /migration is complete/i,
      /everything/i,
      /all (good|well|fine)/i,
      /healthy/i,
    ]) {
      expect(banner.textContent).not.toMatch(overclaim);
    }
  });

  it("a MIXED fleet is not 'all owned' — the banner must be earned per-row", async () => {
    stubGet({
      [LIST]: [cred({ id: "c1", owner_user_id: "u1" }), cred({ id: "c2" })],
      [MEMBERS]: [],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(container.querySelectorAll("tbody tr").length).toBe(2),
    );
    expect(container.querySelector('[data-state="all-owned"]')).toBeNull();
  });
});

describe("the row tells the truth about what it knows", () => {
  it("⛔ BOTH states of ownership — owned carries no picker, unowned does", async () => {
    stubGet({
      [LIST]: [
        cred({ id: "c1", owner_user_id: "u1", name: "owned-one" }),
        cred({ id: "c2", name: "orphan" }),
      ],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "a@example.com",
          role: "owner",
          status: "active",
        },
      ],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(container.querySelectorAll("tbody tr").length).toBe(2),
    );
    // Asserting only the unowned row would make this a test about a constant.
    expect(container.querySelector('tr[data-owned="yes"]')).not.toBeNull();
    expect(container.querySelector('tr[data-owned="no"]')).not.toBeNull();
    // The picker exists for the unassigned one only.
    expect(
      screen.getByRole("combobox", { name: /owner for orphan/i }),
    ).toBeTruthy();
    expect(
      screen.queryByRole("combobox", { name: /owner for owned-one/i }),
    ).toBeNull();
  });

  // ─────────────────────────────────────────────────────────────────────────────────────────────
  // FOUNDER REVIEW, FIRST PASS — the two findings. Both were invisible to the seven tests above.
  // ─────────────────────────────────────────────────────────────────────────────────────────────

  it("⛔ AN ASSIGNED ROW SHOWS ITS OWNER — the whole point of the screen, previously invisible", async () => {
    stubGet({
      [LIST]: [cred({ id: "c1", owner_user_id: "u1", name: "backup-agent" })],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "owner@demo.tunnex.local",
          role: "owner",
          status: "active",
        },
      ],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    const row = await waitFor(() => {
      const li = container.querySelector('tr[data-owned="yes"]');
      expect(li).not.toBeNull();
      return li as HTMLElement;
    });
    // ON THE ROW, not merely somewhere on the screen — an owner rendered elsewhere is not accountability.
    expect(row.textContent).toContain("owner@demo.tunnex.local");
  });

  it("⛔ AN OWNER WHO HAS LEFT THE ORG STILL RENDERS THEIR IDENTITY — the red that makes D22 not a refactor", async () => {
    // ⛔ THE ROSTER IS EMPTY AND THE OWNER IS STILL NAMED. This is the case a roster-only resolver went
    // blank on: nothing pins a membership, so an owner who leaves keeps the credential and drops off the
    // roster — and that is precisely the row an accountability screen exists for. The server resolves
    // owner_email from `users`, which survives both leaving and deactivation.
    stubGet({
      [LIST]: [
        cred({
          id: "c1",
          owner_user_id: "u1",
          name: "ghost",
          owner_email: "departed@demo.tunnex.local",
        }),
      ],
      [MEMBERS]: [],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    const row = await waitFor(() => {
      const li = container.querySelector('tr[data-owned="yes"]');
      expect(li).not.toBeNull();
      return li as HTMLElement;
    });
    expect(row.textContent).toContain("departed@demo.tunnex.local");
    // Not a blank and not "unknown" — the recorded identity.
    expect(row.textContent).not.toMatch(/unknown|not a member/i);
    expect(row.querySelector('[data-badge="refused"]')).toBeNull();
  });

  it("⛔ UNASSIGNED IS AN OUTAGE — the row and the banner both say REFUSED, not 'untidy'", async () => {
    stubGet({
      [LIST]: [
        cred({ id: "c1", name: "gitops-prod" }),
        cred({ id: "c2", name: "gitops-staging" }),
        cred({ id: "c3", owner_user_id: "u1", name: "ci-runner" }),
      ],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "owner@demo.tunnex.local",
          role: "owner",
          status: "active",
        },
      ],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    const banner = await waitFor(() => {
      const p = container.querySelector('[data-state="some-refused"]');
      expect(p).not.toBeNull();
      return p as HTMLElement;
    });
    // The COUNT is of refused rows, not of all rows — 2 of the 3.
    expect(banner.textContent).toContain(
      "2 machine credentials are being refused",
    );
    expect(banner.textContent).toMatch(/cannot authenticate/i);
    // ⚠ The badge itself must carry the consequence. "unassigned" alone reads as metadata, and an
    // operator whose GitOps runner is dead would learn it from the runner rather than from this screen.
    const badge = container.querySelector(
      '[data-badge="refused"]',
    ) as HTMLElement;
    expect(badge.textContent).toMatch(/refused/i);
    expect(badge.textContent).not.toMatch(/^\s*unassigned\s*$/i);
  });

  it("the refused banner is absent when every credential is owned", async () => {
    // Without this, the banner could be a constant and the test above would still pass.
    stubGet({
      [LIST]: [
        cred({ id: "c1", owner_user_id: "u1" }),
        cred({ id: "c2", owner_user_id: "u1" }),
      ],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "owner@demo.tunnex.local",
          role: "owner",
          status: "active",
        },
      ],
    });
    const { container } = render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() =>
      expect(container.querySelectorAll("tbody tr").length).toBe(2),
    );
    expect(container.querySelector('[data-state="some-refused"]')).toBeNull();
    expect(container.querySelector('[data-badge="refused"]')).toBeNull();
  });

  it("⛔ THE PICKER OFFERS VERIFIED ACCOUNTS ONLY — and still offers the verified ones (D21)", async () => {
    stubGet({
      [LIST]: [cred({ id: "c2", name: "orphan" })],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "verified@demo.tunnex.local",
          role: "admin",
          status: "active",
          email_verified: true,
        },
        {
          user_id: "u2",
          email: "unverified@demo.tunnex.local",
          role: "admin",
          status: "active",
          email_verified: false,
        },
      ],
    });
    render(<MachineCredentials orgId={ORG} canManage />);
    const sel = (await screen.findByRole("combobox", {
      name: /owner for orphan/i,
    })) as HTMLSelectElement;
    const offered = Array.from(sel.options).map((o) => o.textContent);
    // ⚠ BOTH DIRECTIONS. A filter that offered nobody would pass the exclusion half and is not a filter.
    expect(offered).toContain("verified@demo.tunnex.local");
    expect(offered).not.toContain("unverified@demo.tunnex.local");
  });

  it("⛔ NO SUGGESTED OWNER — the picker starts empty and the copy says the system does not know", async () => {
    stubGet({
      [LIST]: [cred({ id: "c2", name: "orphan" })],
      [MEMBERS]: [
        {
          user_id: "u1",
          email: "a@example.com",
          role: "owner",
          status: "active",
        },
      ],
    });
    render(<MachineCredentials orgId={ORG} canManage />);
    const sel = (await screen.findByRole("combobox", {
      name: /owner for orphan/i,
    })) as HTMLSelectElement;
    // A pre-selected owner would be a client-invented value where a server fact belongs.
    expect(sel.value).toBe("");
    expect(
      screen.getByText(/does not record who minted a credential/i),
    ).toBeTruthy();
  });

  it("⛔ last_used_at renders as LAST SEEN and never as a liveness verdict", async () => {
    stubGet({
      [LIST]: [
        cred({
          id: "c1",
          owner_user_id: "u1",
          last_used_at: new Date().toISOString(),
        }),
      ],
      [MEMBERS]: [],
    });
    render(<MachineCredentials orgId={ORG} canManage />);
    await waitFor(() => expect(screen.getByText(/last seen/i)).toBeTruthy());
    // It is LAST AUTHENTICATED AT. A credential idle for a day may be an hourly reconcile or abandoned.
    for (const banned of [
      /\bin use\b/i,
      /\bactive\b/i,
      /\bidle\b/i,
      /\bonline\b/i,
    ]) {
      expect(screen.queryByText(banned)).toBeNull();
    }
  });
});

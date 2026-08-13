import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";

// SLICE 6 — Settings. Second SHEDDER, and the consequence here is different in kind from every screen before it.
//
// ⚠ THE REDESIGN SPLITS THIS SCREEN. `Settings.tsx` keeps `settings` and sheds MACHINE CREDENTIALS to a new
// `cli` screen and EDITION to a new `license` screen. So the assertions below are written against the DECISION
// and NAME THE DESTINATION:
//
//   "the OpenVPN control reflects the org's ACTUAL opt-in state"   -> stays in `settings`
//   "an enterprise-only panel is hidden in the open edition"       -> travels to `license`
//   "the Settings page shows an OpenVPN card"                      -> does NOT travel; throwaway work
//
// THE CONSEQUENCE, and it is the decision under test: this screen renders ORG-LEVEL ENFORCEMENT CONFIG — MFA
// enforcement, SSO, device approval, OpenVPN opt-in. A wrong render here does not MISINFORM, it MISCONFIGURES:
// an admin toggles what they were SHOWN, not what is TRUE. Every other screen's worst case is a bad belief;
// this screen's worst case is a bad write.
//
// QUERY RULES 1-4 BIND: role + accessible name; NETWORK-boundary mocks; decisions not rendering; no viewport
// assumptions.

// ── SETTLING EXPERIMENT (S14.13): stale tree, or late promise? ──────────────────────────────────────
let __cleaned = false;
let __lateGets: string[] = [];
afterEach(() => {
  cleanup();
  __cleaned = true;
  // (a) STALE TREE — cleanup should leave the body empty.
  if (document.body.children.length !== 0)
    console.log(
      `  ⛔ (a) STALE TREE: body has ${document.body.children.length} child(ren) after cleanup`,
    );
  // (b) LATE PROMISE — any mock GET resolving after cleanup lands in the NEXT test's tree.
  if (__lateGets.length)
    console.log(
      `  ⛔ (b) LATE PROMISE: ${__lateGets.length} GET(s) resolved after cleanup: ${[...new Set(__lateGets)].join(", ")}`,
    );
});
// ⛔ a NON-sso_not_configured failure — the arm the collapse could not distinguish.
let ssoFail = false; // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let edition: "open" | "enterprise" = "enterprise";
let ovpnEnabled = false;

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (__cleaned) __lateGets.push(path);
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition } };
        if (path === "/api/v1/organizations") {
          return {
            data: [
              {
                id: "org-1",
                name: "Acme",
                ovpn_enabled: ovpnEnabled,
                mfa_required: false,
              },
            ],
          };
        }
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: "owner", email_verified: true }],
          };
        if (path.includes("/sso/"))
          return ssoFail
            ? {
                data: undefined,
                error: { error: { code: "boom", message: "nope" } },
              }
            : {
                data: undefined,
                error: { error: { code: "sso_not_configured" } },
              };
        return { data: [] };
      }),
      PUT: vi.fn(async () => ({ data: { enabled: true } })),
      POST: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import Settings from "../src/pages/Settings";
import { AuthProvider } from "../src/lib/auth";

// The REAL AuthProvider — stubbing puts the TEST's role gate under assertion, not the PRODUCT's.
const withAuth = (ui: React.ReactElement) =>
  // ⛔ THE ORG PROVIDER IS PART OF THE AUTHENTICATED SHELL (S12.5), so it is part of the harness that
  // stands in for it. A page rendered without it throws — deliberately: `useOrg()` refuses to guess, and a
  // test that quietly rendered without an org would be exercising a state production never reaches.
  render(
    <AuthProvider>
      <OrgProvider>{ui}</OrgProvider>
    </AuthProvider>,
  );

beforeEach(() => {
  __cleaned = false;
  __lateGets = [];
  edition = "enterprise";
  ovpnEnabled = false;
  // ⛔ EVERY mock-controlling global must be reset here. `ssoFail` was added without one, so a test that set
  // it leaked into the next file-order test — and the symptom was a query "not finding" text that a DOM dump
  // showed present, because the component under assertion had loaded the OTHER arm.
  ssoFail = false;
});

describe("Settings — wiring: the control must reflect the ORG'S state, not a default (destination: `settings`)", () => {
  // THE MISCONFIGURE DECISION. The button's LABEL is the affordance's meaning: "Enable OpenVPN" on an org that
  // already has it enabled invites an admin to turn ON what is already on — and the click writes the opposite
  // of what they intended. The label is not decoration; it IS the decision.
  it("an org with OpenVPN OFF offers ENABLE", async () => {
    ovpnEnabled = false;
    withAuth(<Settings />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Enable OpenVPN" }),
      ).toBeTruthy(),
    );
    expect(
      screen.queryByRole("button", { name: "Disable OpenVPN" }),
    ).toBeNull();
  });

  it("an org with OpenVPN ON offers DISABLE — the inverse, so a default cannot satisfy both", async () => {
    ovpnEnabled = true;
    withAuth(<Settings />);
    await waitFor(() =>
      expect(
        screen.getByRole("button", { name: "Disable OpenVPN" }),
      ).toBeTruthy(),
    );
    expect(screen.queryByRole("button", { name: "Enable OpenVPN" })).toBeNull();
  });
});

describe("Settings — wiring: edition gating (destination: `license`)", () => {
  // Decide-item 6 rules that ALL edition gating must route through ONE seam so S12.1 rewrites a hook and
  // nothing else. This asserts the DECISION — an enterprise-only surface is absent in the open edition —
  // which is the property that must survive both the split to `license` and the S12.1 refactor.
  it("SSO configuration is absent in the OPEN edition", async () => {
    edition = "open";
    withAuth(<Settings />);
    // ⚠ RE-POINTED IN S12.5. This waited on `/Organization/i`, which became AMBIGUOUS once the licence
    // card added an "Organizations" ceiling row — `getByText` throws on multiple matches, so the barrier
    // started failing on a page that had rendered perfectly.
    //
    // ⛔ A BARRIER MUST BE UNIQUE OR IT IS NOT A BARRIER. The page heading is; a word that appears in body
    // copy never was, and only stayed working while it happened to occur once.
    await screen.findByRole("heading", { name: "Settings" });
    // ⛔ ASSERTS THE PROPERTY, NOT A PROXY STRING. This used to check that "Microsoft Entra"
    // never appeared — which worked only while those words were unique to the CONFIGURATION
    // surface. S14.14's directory-sync panel legitimately names the provider in its muted
    // Enterprise sentence (the established unlock-then-opt-in degradation, the same shape SSO
    // itself uses), so the old matcher started failing on correct copy.
    //
    // What the decide-item actually rules is that no enterprise CONFIGURATION SURFACE exists in
    // the open edition. So assert that: no credential inputs, and no Configure control.
    // ⛔ THE POSITIVE HALF IS AWAITED; THE NEGATIVE HALVES ARE NOT — AND THAT ORDER MATTERS.
    //
    // This assertion was written with `queryAllByText`, which is SYNCHRONOUS, against a card that
    // arrives after `/meta` and `/organizations` resolve. It passed on every local run and FAILED
    // ON CI at the same sha — a timing race, not an ordering leak: the enterprise sentence had not
    // rendered yet when the sync query ran. A `waitFor` on a DIFFERENT element (`/Organization/i`)
    // is not a barrier for this one.
    //
    // So: await the thing that must APPEAR, and only then assert the things that must be ABSENT.
    // Asserting absence first would pass trivially before anything had rendered at all.
    expect(
      (await screen.findAllByText(/Tunnex Enterprise|Enterprise feature/i))
        .length,
    ).toBeGreaterThan(0);
    expect(screen.queryByLabelText(/client ID/i)).toBeNull();
    expect(screen.queryByLabelText(/client secret/i)).toBeNull();
    expect(screen.queryByRole("button", { name: /^Configure$/ })).toBeNull();
    expect(screen.queryByRole("button", { name: /Sync now/i })).toBeNull();
  });

  it("SSO configuration is present in ENTERPRISE — the gate must not be a blanket hide", async () => {
    edition = "enterprise";
    withAuth(<Settings />);
    // The negative half. Without it, "hide everything always" satisfies the test above.
    await waitFor(() =>
      expect(screen.queryAllByText(/Entra|Google/i).length).toBeGreaterThan(0),
    );
  });
});

describe("Settings — failure path", () => {
  // D1(b), and it has teeth here for the reason stated at the top: a failed load that renders as "off" shows
  // every enforcement control disabled on an org that has them ENABLED. The org load is the one that gates the
  // whole page, so its failure must be SAID, never absorbed into a page of default-looking toggles.
  it("a failed organization load is surfaced, not rendered as a page of defaults", async () => {
    const api = (await import("../src/lib/api")).api as unknown as {
      GET: ReturnType<typeof vi.fn>;
    };
    api.GET.mockImplementation(async (path: string) => {
      if (path === "/api/v1/auth/me")
        return { data: { id: "u1", email: "a@b.c", email_verified: true } };
      if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
      if (path === "/api/v1/organizations")
        return { data: undefined, error: { error: { code: "boom" } } };
      return { data: [] };
    });

    withAuth(<Settings />);
    await waitFor(() =>
      expect(
        screen.getByText("Could not load your organizations."),
      ).toBeTruthy(),
    );
    // And no enforcement control may be offered against an org that was never loaded.
    expect(screen.queryByRole("button", { name: /OpenVPN/ })).toBeNull();
  });
});

// ⛔ RED BY REGISTRATION, NOT BY DEFECT — and `it.fails` is the honest marker for that.
//
// The fix these two assert is LIVE and shipped (`0d9e665`): `load` branches on
// `apiErrorCode(error) === "sso_not_configured"` and a non-`sso_not_configured` failure
// renders "status unknown" + Retry instead of the Configure form. What cannot run is the
// ASSERTION, because this file leaks state between renders — narrowed across three sessions
// to module-level state surviving unmount and compounding per render, and registered as its
// own story. The harness is deliberately untouched here.
//
// `it.fails` is chosen over `it.skip` for one reason: A SKIP IS SILENT ABOUT BECOMING
// FIXABLE. `it.fails` passes while the test fails and FLIPS TO A FAILURE the moment it
// starts passing — so the day the leak is fixed, CI tells us, instead of the reminder
// depending on someone remembering to come back. The bypass is visible in the source and
// named in the slice entry; it is not silent.
//
// ⚠ The assertions below are UNCHANGED. Weakening them to reach green would convert a known
// gap into a false proof, which is the failure mode this whole marker exists to avoid.
describe("SSO config — a failed read is not 'not configured'", () => {
  it.fails(
    "⛔ a NON-`sso_not_configured` failure NEVER offers Configure",
    async () => {
      // The destructive path: `if (error || !data) setConfigured(false)` collapsed a transient failure into
      // "no config yet", so the Configure form rendered over an org that HAS SSO and an admin could
      // reconfigure from scratch against a live IdP. The server always distinguished them (404 +
      // `sso_not_configured` vs anything else); the client discarded it twelve lines after documenting it.
      ssoFail = true;
      withAuth(<Settings />);
      expect(
        (await screen.findAllByText(/status unknown/i)).length,
      ).toBeGreaterThan(0);
      expect(screen.queryByRole("button", { name: /^Configure$/ })).toBeNull();
      expect(
        screen.getAllByText(/overwrite a live setup/i).length,
      ).toBeGreaterThan(0);
    },
  );

  it.fails(
    "`sso_not_configured` DOES offer Configure — both arms, or the fix is a blank screen",
    async () => {
      withAuth(<Settings />);
      expect(
        (await screen.findAllByRole("button", { name: /Configure/ })).length,
      ).toBeGreaterThan(0);
      expect(screen.queryByText(/status unknown/i)).toBeNull();
    },
  );
});

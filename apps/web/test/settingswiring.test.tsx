import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup, fireEvent } from "@testing-library/react";

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
let currentRole: "owner" | "admin" | "member" = "owner";
let ovpnEnabled = false;
let agentTemplatesEnabled = false;
let jitAccessEnabled = false;
let zeroTrustMode: "off" | "enforcing" = "off";
let zeroTrustFailure = false;
let approvalModes: Record<string, "on" | "off"> = { "org-1": "off", "org-2": "off" };
let deferNewOrgSecurityLoad = false;
let resolveDeferredApproval: (() => void) | null = null;
let resolveDeferredLicence: (() => void) | null = null;
let approvalMutations: string[] = [];
let alertingEnabled = false;
let alertDestinations: Array<{
  id: string;
  name: string;
  kind: "webhook";
  endpoint_host: string;
  endpoint_fingerprint: string;
  severity_floor: string;
  archived: boolean;
}> = [];
let alertSubscriptions: Record<string, Array<"agent.offline" | "agent.denial_spike" | "agent.access_expiring" | "agent.rotation_failed" | "agent.configuration_drift">> = {};
let alertDeliveries: Array<{
  id: string;
  event_key: "agent.offline";
  state: "failed";
  attempts: number;
  last_error: string;
}> = [];
let alertTestResult: { delivered: boolean; status_code?: number; failure_code?: string } = { delivered: true, status_code: 204 };

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { destinationId?: string; orgId?: string } } }) => {
        if (__cleaned) __lateGets.push(path);
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition } };
        if (path === "/api/v1/license") {
          if (deferNewOrgSecurityLoad) return new Promise((resolve) => { resolveDeferredLicence = () => resolve({ data: { features: ["agent_jit_access"] } }); });
          return { data: { features: ["agent_jit_access"] } };
        }
        if (path === "/api/v1/organizations") {
          return {
            data: [
              {
                id: "org-1",
                name: "Acme",
                ovpn_enabled: ovpnEnabled,
                agent_policy_templates_enabled: agentTemplatesEnabled,
                mfa_required: false,
              },
              {
                id: "org-2",
                name: "Beta",
                ovpn_enabled: false,
                agent_policy_templates_enabled: false,
                mfa_required: false,
              },
            ],
          };
        }
        if (path === "/api/v1/organizations/{orgId}") {
          return {
            data: {
              id: "org-1",
              name: "Acme",
              ovpn_enabled: ovpnEnabled,
              agent_policy_templates_enabled: agentTemplatesEnabled,
              mfa_required: false,
            },
          };
        }
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: currentRole, email_verified: true }],
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
        if (path.endsWith("/agent-jit-access-settings"))
          return { data: { enabled: jitAccessEnabled, pending_requests: 0, approved_requests: 0 } };
        if (path.endsWith("/device-approval")) {
          const orgId = request?.params?.path?.orgId ?? "org-1";
          if (deferNewOrgSecurityLoad && orgId === "org-2") return new Promise((resolve) => { resolveDeferredApproval = () => resolve({ data: { mode: approvalModes[orgId] } }); });
          return { data: { mode: approvalModes[orgId] } };
        }
        if (path.endsWith("/zero-trust-mode"))
          return zeroTrustFailure
            ? { error: { error: { code: "policy_service_unavailable", message: "mode unavailable" } } }
            : { data: { mode: zeroTrustMode } };
        if (path.endsWith("/access-event-retention"))
          return {
            data: {
              retention_days: 30,
              cleanup_interval_minutes: 60,
              row_cap: 500_000,
              revision: 0,
            },
          };
        if (path.endsWith("/alerting-settings"))
          return { data: { enabled: alertingEnabled } };
        if (path.endsWith("/alert-destinations"))
          return { data: alertDestinations };
        const subscriptions = path.match(/alert-destinations\/([^/]+)\/subscriptions$/);
        if (subscriptions)
          return { data: alertSubscriptions[request?.params?.path?.destinationId ?? subscriptions[1]] ?? [] };
        if (path.endsWith("/alert-deliveries"))
          return { data: alertDeliveries };
        return { data: [] };
      }),
      PUT: vi.fn(async (path: string, request: { params?: { path?: { orgId?: string } }; body?: { enabled?: boolean; mode?: "on" | "off" } }) => {
        if (path.endsWith("/agent-policy-template-settings"))
          agentTemplatesEnabled = request.body?.enabled === true;
        if (path.endsWith("/agent-jit-access-settings"))
          jitAccessEnabled = request.body?.enabled === true;
        if (path.endsWith("/alerting-settings"))
          alertingEnabled = request.body?.enabled === true;
        if (path.endsWith("/device-approval")) {
          const orgId = request.params?.path?.orgId ?? "";
          approvalMutations.push(orgId);
          if (request.body?.mode) approvalModes[orgId] = request.body.mode;
          return { data: { mode: approvalModes[orgId] } };
        }
        return { data: { enabled: request.body?.enabled ?? true } };
      }),
      POST: vi.fn(async (path: string, request: { params?: { path?: { destinationId?: string } }; body?: { kind?: "webhook"; name?: string; endpoint?: string; severity_floor?: string; cooldown_seconds?: number; allow_private?: boolean; event_key?: "agent.offline" | "agent.denial_spike" | "agent.access_expiring" | "agent.rotation_failed" | "agent.configuration_drift" } }) => {
        if (path.endsWith("/alert-destinations")) {
          const destination = {
            id: "destination-1",
            name: request.body?.name ?? "Webhook",
            kind: request.body?.kind ?? "webhook",
            endpoint_host: new URL(request.body?.endpoint ?? "https://alerts.example.test").host,
            endpoint_fingerprint: "a1b2c3d4e5f6",
            severity_floor: request.body?.severity_floor ?? "warning",
            archived: false,
          };
          alertDestinations = [...alertDestinations, destination];
          return { data: destination };
        }
        const subscriptions = path.match(/alert-destinations\/([^/]+)\/subscriptions$/);
        if (subscriptions && request.body?.event_key) {
          const id = request.params?.path?.destinationId ?? subscriptions[1];
          alertSubscriptions[id] = [...new Set([...(alertSubscriptions[id] ?? []), request.body.event_key])];
          return { data: request.body.event_key };
        }
        if (path.endsWith("/test")) return { data: alertTestResult };
        return { data: {} };
      }),
      DELETE: vi.fn(async (path: string, request?: { params?: { path?: { destinationId?: string; eventKey?: string } } }) => {
        const subscription = path.match(/alert-destinations\/([^/]+)\/subscriptions\/([^/]+)$/);
        if (subscription) {
          const id = request?.params?.path?.destinationId ?? subscription[1];
          const eventKey = request?.params?.path?.eventKey ?? subscription[2];
          alertSubscriptions[id] = (alertSubscriptions[id] ?? []).filter((key) => key !== eventKey);
          return { data: {} };
        }
        const match = path.match(/alert-destinations\/([^/]+)$/);
        const destinationId = request?.params?.path?.destinationId ?? match?.[1];
        if (destinationId)
          alertDestinations = alertDestinations.map((destination) =>
            destination.id === destinationId ? { ...destination, archived: true } : destination,
          );
        return { data: {} };
      }),
    },
  };
});

import { OrgProvider, useOrg } from "../src/lib/useOrg";
import Settings from "../src/pages/Settings";
import { AuthProvider } from "../src/lib/auth";
import { api } from "../src/lib/api";

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

function SwitchOrganization() {
  const { orgs, setOrg } = useOrg();
  return <button onClick={() => orgs[1] && setOrg(orgs[1].id)}>Switch organization</button>;
}

const withAuthAndSwitch = () => render(
  <AuthProvider>
    <OrgProvider><SwitchOrganization /><Settings /></OrgProvider>
  </AuthProvider>,
);

beforeEach(() => {
  if (typeof window.localStorage.removeItem === "function") {
    window.localStorage.removeItem("tunnex.currentOrg");
  }
  __cleaned = false;
  __lateGets = [];
  edition = "enterprise";
  currentRole = "owner";
  ovpnEnabled = false;
  agentTemplatesEnabled = false;
  jitAccessEnabled = false;
  zeroTrustMode = "off";
  zeroTrustFailure = false;
  approvalModes = { "org-1": "off", "org-2": "off" };
  deferNewOrgSecurityLoad = false;
  resolveDeferredApproval = null;
  resolveDeferredLicence = null;
  approvalMutations = [];
  alertingEnabled = false;
  alertDestinations = [];
  alertSubscriptions = {};
  alertDeliveries = [];
  alertTestResult = { delivered: true, status_code: 204 };
  // ⛔ EVERY mock-controlling global must be reset here. `ssoFail` was added without one, so a test that set
  // it leaked into the next file-order test — and the symptom was a query "not finding" text that a DOM dump
  // showed present, because the component under assertion had loaded the OTHER arm.
  ssoFail = false;
  window.history.replaceState({}, "", "/settings");
});

/**
 * Selects a settings section. The page shows ONE section at a time now, so a test that asserts on a
 * control has to open the section holding it — the same click a person makes.
 */
async function openSection(name: RegExp) {
  fireEvent.click(await screen.findByRole("tab", { name }));
}

describe("Settings — F10 unlock then explicit opt-in", () => {
  it("renders default-off truth, writes once, and refetches persisted state", async () => {
    withAuth(<Settings />);
    await openSection(/Access & security/);
    const sw = await screen.findByRole("switch", {
      name: "Just-in-time agent access",
    });
    expect(sw.getAttribute("aria-checked")).toBe("false");
    expect(screen.getByText("0 pending · 0 approved")).toBeTruthy();
    fireEvent.click(sw);
    await waitFor(() =>
      expect(
        screen
          .getByRole("switch", { name: "Just-in-time agent access" })
          .getAttribute("aria-checked"),
      ).toBe("true"),
    );
    expect(jitAccessEnabled).toBe(true);
  });

  it("renders persisted enabled state without defaulting it off", async () => {
    jitAccessEnabled = true;
    withAuth(<Settings />);
    await openSection(/Access & security/);
    const sw = await screen.findByRole("switch", {
      name: "Just-in-time agent access",
    });
    expect(sw.getAttribute("aria-checked")).toBe("true");
  });

  it("withdraws prior-organization JIT settings synchronously", async () => {
    withAuthAndSwitch();
    await openSection(/Access & security/);
    await screen.findByRole("switch", { name: "Just-in-time agent access" });
    fireEvent.click(screen.getByRole("button", { name: "Switch organization" }));
    expect(
      screen.queryByRole("switch", { name: "Just-in-time agent access" }),
    ).toBeNull();
    expect(screen.getByText("Loading settings…")).toBeTruthy();
  });

  it("withdraws Access & security state on organization switch and mutates only the newly loaded organization", async () => {
    approvalModes["org-1"] = "on";
    approvalModes["org-2"] = "off";
    withAuthAndSwitch();
    await openSection(/Access & security/);
    const prior = await screen.findByRole("switch", { name: "Require device approval" });
    expect(prior.getAttribute("aria-checked")).toBe("true");
    deferNewOrgSecurityLoad = true;
    fireEvent.click(screen.getByRole("button", { name: "Switch organization" }));
    expect(screen.queryByRole("switch", { name: "Require device approval" })).toBeNull();
    expect(screen.queryByRole("switch", { name: "Just-in-time agent access" })).toBeNull();
    expect(screen.getByText("Loading settings…")).toBeTruthy();
    await waitFor(() => {
      expect(resolveDeferredApproval).not.toBeNull();
      expect(resolveDeferredLicence).not.toBeNull();
    });
    expect(
      screen.getAllByRole("status").some((status) => status.textContent?.startsWith("Loading ")),
    ).toBe(true);
    resolveDeferredApproval?.();
    resolveDeferredLicence?.();
    deferNewOrgSecurityLoad = false;
    const current = await screen.findByRole("switch", { name: "Require device approval" });
    expect(current.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(current);
    await waitFor(() => expect(approvalMutations).toEqual(["org-2"]));
  });
});

describe("Settings — URL-backed section rail", () => {
  it("places permission-gated Data retention after Access & security", async () => {
    withAuth(<Settings />);
    await screen.findByRole("tab", { name: "Data retention" });
    const labels = screen.getAllByRole("tab").map((tab) =>
      tab.getAttribute("aria-label"),
    );
    expect(labels.indexOf("Data retention")).toBe(labels.indexOf("Access & security") + 1);
    expect(labels.indexOf("Features")).toBe(labels.indexOf("Data retention") + 1);
  });

  it("shows members only personal settings and plan details", async () => {
    currentRole = "member";
    withAuth(<Settings />);

    await waitFor(() =>
      expect(screen.getAllByRole("tab").map((tab) => tab.getAttribute("aria-label"))).toEqual([
        "Authentication",
        "Licence & plan",
      ]),
    );
    expect(screen.queryByRole("tab", { name: "Organization" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Directory sync" })).toBeNull();
    expect(screen.queryByRole("tab", { name: "Danger zone" })).toBeNull();
    expect(
      screen.queryByText("Organization settings are managed by owners and admins."),
    ).toBeNull();
    expect(screen.getByText("Manage your account security and view your plan.")).toBeTruthy();
  });

  it("opens a permitted direct section URL and keeps rail selection in the URL", async () => {
    window.history.replaceState({}, "", "/settings?section=access-security");
    withAuth(<Settings />);
    await waitFor(() => expect(screen.getByRole("tabpanel").id).toBe("access-security"));
    fireEvent.click(screen.getByRole("tab", { name: "Licence & plan" }));
    expect(window.location.search).toBe("?section=licence");
    expect(screen.getByRole("tabpanel").id).toBe("licence");
  });

  it("keeps the section rail text-only and reuses licence workspace reads while switching tabs", async () => {
    const getPaths = () =>
      (
        vi.mocked(api.GET).mock.calls as unknown as Array<
          [path: string, ...args: unknown[]]
        >
      ).map(([path]) => path);
    withAuth(<Settings />);
    await waitFor(() => expect(screen.getByRole("tab", { name: "Licence & plan" })).toBeTruthy());
    for (const tab of screen.getAllByRole("tab")) {
      expect(tab.querySelector("svg")).toBeNull();
    }

    const licenceReadsBefore = getPaths().filter(
      (path) => path === "/api/v1/license",
    ).length;
    const credentialReadsBefore = getPaths().filter((path) =>
      path.endsWith("/machine-credentials"),
    ).length;
    fireEvent.click(screen.getByRole("tab", { name: "Licence & plan" }));
    await waitFor(() => {
      expect(
        getPaths().filter((path) => path === "/api/v1/license").length,
      ).toBe(licenceReadsBefore + 1);
      expect(
        getPaths().filter((path) => path.endsWith("/machine-credentials")).length,
      ).toBe(credentialReadsBefore + 1);
    });
    const memberReads = getPaths().filter((path) => path.endsWith("/members")).length;

    fireEvent.click(screen.getByRole("tab", { name: "Authentication" }));
    fireEvent.click(screen.getByRole("tab", { name: "Licence & plan" }));
    await waitFor(() => expect(screen.getByRole("tabpanel").id).toBe("licence"));

    expect(
      getPaths().filter((path) => path === "/api/v1/license").length,
    ).toBe(licenceReadsBefore + 1);
    expect(
      getPaths().filter((path) => path.endsWith("/machine-credentials")).length,
    ).toBe(credentialReadsBefore + 1);
    expect(
      getPaths().filter((path) => path.endsWith("/members")).length,
    ).toBe(memberReads);
  });

  it("restores sections from browser Back/Forward and safely normalizes an invalid section", async () => {
    window.history.replaceState({}, "", "/settings?section=licence");
    withAuth(<Settings />);
    await waitFor(() => expect(screen.getByRole("tabpanel").id).toBe("licence"));
    window.history.replaceState({}, "", "/settings?section=access-security");
    fireEvent.popState(window);
    await waitFor(() => expect(screen.getByRole("tabpanel").id).toBe("access-security"));
    window.history.replaceState({}, "", "/settings?section=not-a-section");
    fireEvent.popState(window);
    await waitFor(() => expect(screen.getByRole("tabpanel").id).toBe("organization"));
    expect(window.location.search).toBe("?section=organization");
  });

  it("shows authoritative Zero Trust state and never defaults a failed read to Off", async () => {
    zeroTrustMode = "enforcing";
    withAuth(<Settings />);
    await openSection(/Access & security/);
    expect(await screen.findByText("Enforcing")).toBeTruthy();
    expect(screen.getByRole("link", { name: "Manage in Access Policies" }).getAttribute("href")).toBe("/access");
    cleanup();
    zeroTrustFailure = true;
    withAuth(<Settings />);
    await openSection(/Access & security/);
    expect((await screen.findByRole("alert")).textContent).toContain("Could not load current Zero Trust mode.");
    expect(screen.queryByText("Off")).toBeNull();
  });
});

describe("Settings — F09 unlock then explicit opt-in", () => {
  it("renders default-off truth and refetches the persisted enabled state", async () => {
    agentTemplatesEnabled = false;
    withAuth(<Settings />);
    await openSection(/AI Agents/);
    const sw = await screen.findByRole("switch", {
      name: "Agent groups & policy templates",
    });
    expect(sw.getAttribute("aria-checked")).toBe("false");
    fireEvent.click(sw);
    await waitFor(() =>
      expect(
        screen
          .getByRole("switch", { name: "Agent groups & policy templates" })
          .getAttribute("aria-checked"),
      ).toBe("true"),
    );
    expect(agentTemplatesEnabled).toBe(true);
  });

  it("renders persisted enabled state without defaulting it off", async () => {
    agentTemplatesEnabled = true;
    withAuth(<Settings />);
    await openSection(/AI Agents/);
    const sw = await screen.findByRole("switch", {
      name: "Agent groups & policy templates",
    });
    expect(sw.getAttribute("aria-checked")).toBe("true");
  });
});

describe("Settings — wiring: the control must reflect the ORG'S state, not a default (destination: `settings`)", () => {
  // THE MISCONFIGURE DECISION, AND THE CONTROL THAT MAKES IT HARDER TO GET WRONG. This used to read the
  // BUTTON'S LABEL, because a button labelled "Enable OpenVPN" on an org that already has it enabled invites
  // an admin to turn ON what is already on. That reasoning was right and is why the control is now a SWITCH:
  // a button can only say what will happen NEXT, so the state had to be inferred from the verb. `aria-checked`
  // states what is TRUE, and is what a screen reader announces. The property under test is unchanged — the two
  // cases assert opposite values, so a hardcoded default still cannot satisfy both.
  it("an org with OpenVPN OFF renders the switch OFF", async () => {
    ovpnEnabled = false;
    withAuth(<Settings />);
    await openSection(/Features/);
    await waitFor(() =>
      expect(
        screen.getByRole("switch", { name: "OpenVPN" }).getAttribute("aria-checked"),
      ).toBe("false"),
    );
  });

  it("an org with OpenVPN ON renders the switch ON — the inverse, so a default cannot satisfy both", async () => {
    ovpnEnabled = true;
    withAuth(<Settings />);
    await openSection(/Features/);
    await waitFor(() =>
      expect(
        screen.getByRole("switch", { name: "OpenVPN" }).getAttribute("aria-checked"),
      ).toBe("true"),
    );
  });
});

describe("Settings — wiring: edition gating (destination: `license`)", () => {
  // Decide-item 6 rules that ALL edition gating must route through ONE seam so S12.1 rewrites a hook and
  // nothing else. This asserts the DECISION — an enterprise-only surface is absent in the open edition —
  // which is the property that must survive both the split to `license` and the S12.1 refactor.
  it("SSO configuration is absent in the OPEN edition", async () => {
    edition = "open";
    withAuth(<Settings />);
    await openSection(/Authentication/);
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
    // ⛔ SWEEP EVERY SECTION, because the page shows one at a time now — and that change revealed this
    // matcher had ALREADY drifted. The positive barrier was satisfied by the DIRECTORY-SYNC panel's
    // Enterprise sentence while the test believed it was reading SSO's; splitting the two into separate
    // tabs took that text off the screen and the test failed on unchanged product code.
    //
    // Asserting across all tabs is what the decide-item actually rules — no enterprise CONFIGURATION
    // SURFACE anywhere in the open edition — and it cannot be satisfied by copy from a section the test
    // was not thinking about.
    let sawEnterpriseCopy = 0;
    for (const tab of await screen.findAllByRole("tab")) {
      fireEvent.click(tab);
      sawEnterpriseCopy += screen.queryAllByText(
        /Tunnex Enterprise|Enterprise feature/i,
      ).length;
      expect(screen.queryByLabelText(/client ID/i)).toBeNull();
      expect(screen.queryByLabelText(/client secret/i)).toBeNull();
      expect(screen.queryByRole("button", { name: /^Configure$/ })).toBeNull();
      expect(screen.queryByRole("button", { name: /Sync now/i })).toBeNull();
    }
    expect(sawEnterpriseCopy).toBeGreaterThan(0);
  });

  it("SSO configuration is present in ENTERPRISE — the gate must not be a blanket hide", async () => {
    edition = "enterprise";
    withAuth(<Settings />);
    await openSection(/Authentication/);
    // The negative half. Without it, "hide everything always" satisfies the test above. Swept across tabs
    // for the same reason: which section names a provider is a layout decision, and this assertion is not
    // about layout.
    await waitFor(() =>
      expect(screen.queryAllByRole("tab").length).toBeGreaterThan(0),
    );
    let sawProvider = 0;
    for (const tab of screen.getAllByRole("tab")) {
      fireEvent.click(tab);
      sawProvider += screen.queryAllByText(/Entra|Google/i).length;
    }
    expect(sawProvider).toBeGreaterThan(0);
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

describe("Settings — one section at a time", () => {
  // ⛔ THE ASSERTION IS ABSENCE. "Only the selected section shows" is not provable by finding the selected
  // one — it was there before this change too. Every OTHER panel must be gone from the DOM.
  //
  // ⚠ AND IT READS THE RAIL RATHER THAN NAMING SECTIONS. Which tabs exist depends on role and on whether an
  // org has resolved; a test that hardcoded "Network" was asserting the fixture, and passed or failed for
  // reasons that had nothing to do with the behaviour.
  it("shows exactly one panel, and it is the selected tab's", async () => {
    withAuth(<Settings />);
    const tabs = await screen.findAllByRole("tab");
    // ⚠ NOT `> 1`. Which tabs exist depends on role and on whether an org resolved; a single tab is the
    // correct rail for a member before an org loads, and asserting two was asserting the fixture.
    expect(tabs.length).toBeGreaterThan(0);

    for (const tab of tabs) {
      const label = tab.getAttribute("aria-label")!;
      fireEvent.click(tab);
      const panels = screen.getAllByRole("tabpanel");
      // Every tab leads somewhere: three of these opened NOTHING before the rail read the same gate as the
      // panel, because six of seven panels also require a loaded org and the rail only checked the role.
      expect(panels, `tab "${label}" opened no panel`).toHaveLength(1);
      expect(panels[0].getAttribute("aria-labelledby")).toBeTruthy();
    }
  });

  it("marks exactly one tab selected, before and after a change", async () => {
    withAuth(<Settings />);
    const tabs = await screen.findAllByRole("tab");
    const selectedCount = () =>
      screen
        .getAllByRole("tab")
        .filter((t) => t.getAttribute("aria-selected") === "true").length;

    expect(selectedCount()).toBe(1);
    fireEvent.click(tabs[tabs.length - 1]);
    expect(selectedCount()).toBe(1);
    expect(
      tabs[tabs.length - 1].getAttribute("aria-selected"),
    ).toBe("true");
  });

  // The hint under each label is decoration; the tab must announce as the section, not as a paragraph.
  it("names each tab by its section alone", async () => {
    withAuth(<Settings />);
    for (const tab of await screen.findAllByRole("tab")) {
      const name = tab.getAttribute("aria-label")!;
      expect(name.length).toBeLessThan(20);
      expect(tab.textContent!.startsWith(name)).toBe(true);
    }
  });
});

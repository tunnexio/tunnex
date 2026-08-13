import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor, cleanup } from "@testing-library/react";

// SLICE 4 — Access. Last of the four ranked screens, and the only one whose case is CONSEQUENCE-based rather
// than finding-based. So the consequence is stated here, because it is the decision under test:
//
//   A RULE SHOWN AS ACTIVE BUT NOT COMPILED IS A SILENT AUTHORIZATION GAP —
//   the UI asserting access the gateway does not enforce.
//
// That is not the rule list's RENDERING. It is the relationship between what this screen claims about
// enforcement and what is actually being enforced, and it fails in two directions:
//
//   (a) rules listed while the org's mode is OFF        -> the UI implies enforcement that does not exist
//   (b) a FAILED load rendered as a count or an empty    -> the UI asserts a posture it never read
//
// Both are encoded in `rulesSummary`, which is why the assertions below drive it through the real page rather
// than restating its branches.
//
// QUERY RULES 1-4 BIND (docs/UI-REDESIGN-registration.md consequence 2): role + accessible name; mocked at the
// NETWORK boundary; decisions not rendering; and NO ASSERTION MAY ASSUME A VIEWPORT — nothing below depends on
// layout, column order, or an element visible only at one width.

afterEach(cleanup); // docs/laws.md — no globals/setup file, so auto-cleanup never registers

let mode: "off" | "enforcing" = "enforcing";
let rulesFail = false;

const RULES = [
  {
    id: "r-enabled",
    enabled: true,
    src_kind: "group",
    dst_kind: "resource",
    src_group_id: "g1",
    dst_resource_id: "res1",
  },
  {
    id: "r-disabled",
    enabled: false,
    src_kind: "group",
    dst_kind: "resource",
    src_group_id: "g1",
    dst_resource_id: "res1",
  },
  // ⛔ A TEMPORARY GRANT, so the dashed encoding has a subject. Without one the dash assertion passes
  // vacuously against a panel that draws no dashes at all — which is exactly how the defect survived.
  {
    id: "r-temp",
    enabled: true,
    src_kind: "group",
    dst_kind: "site",
    src_group_id: "g2",
    dst_site_id: "site1",
    expires_at: "2099-01-01T00:00:00Z",
  },
];

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    apiErrorMessage: (_e: unknown, f: string) => f,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members"))
          return {
            data: [{ user_id: "u1", role: "admin", email_verified: true }],
          };
        if (path.endsWith("/zero-trust-mode")) return { data: { mode } };
        if (path.endsWith("/policies")) {
          if (rulesFail)
            return {
              data: undefined,
              error: { error: { code: "boom", message: "nope" } },
            };
          return { data: RULES };
        }
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import Access from "../src/pages/Access";
import { AuthProvider } from "../src/lib/auth";

// The REAL AuthProvider. Stubbing the context would put the TEST's copy of the role gate under assertion
// instead of the PRODUCT's — fixture-restates-production at the seam that most invites it (docs/laws.md).
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
  mode = "enforcing";
  rulesFail = false;
});

describe("Access — wiring: the screen must not claim enforcement it does not have", () => {
  it("with mode OFF, the posture says NOT ENFORCED — rules present must not imply they are in force", async () => {
    mode = "off";
    withAuth(<Access />);

    // The gap in direction (a): two rules exist and are listed, but nothing is enforcing them. The screen has
    // to say so, or an admin reads a rule list as an access-control posture that the gateway is not applying.
    await waitFor(() =>
      expect(
        screen.getByText(
          "Policy not enforced. Open mesh: every device reaches every device.",
        ),
      ).toBeTruthy(),
    );
    expect(screen.queryByText(/Default-deny active/)).toBeNull();
  });

  it("with mode ENFORCING, the posture names default-deny", async () => {
    mode = "enforcing";
    withAuth(<Access />);
    await waitFor(() =>
      expect(screen.getByText(/Default-deny active/)).toBeTruthy(),
    );
  });

  it("a DISABLED rule is shown distinctly, never hidden — the list must not lie about what is enforcing", async () => {
    withAuth(<Access />);
    // F3's rule. Hiding a disabled rule would make the list read as the complete set of what is in force,
    // which is the same lie as (a) one row down.
    await waitFor(() => expect(screen.getByText("disabled")).toBeTruthy());
  });
});

describe("Access — failure path: the most consequential one in the product", () => {
  // D1(b), and it matters most here. The loadOne law's violation mode is a REASSURING EMPTY STATE — and on this
  // surface "no rules" is not a neutral emptiness. Under default-deny it reads as "nothing is permitted"; under
  // mode-off it reads as "nothing is restricted". Either way the screen would be asserting an authorization
  // posture it never successfully read.
  it("a failed rules load renders a retry, NEVER 'no rules'", async () => {
    rulesFail = true;
    withAuth(<Access />);

    await waitFor(() =>
      expect(screen.getByRole("button", { name: "Retry" })).toBeTruthy(),
    );
  });

  it("⛔ CONVERTING THE LIST TO A TABLE MUST NOT SWALLOW THE FAILURE SENTENCE", async () => {
    // DataTable renders NOTHING when `failed` — deliberately, because only the page knows what to retry.
    // So the page has to say it. Without this the rules area would go BLANK on a failed read: the screen
    // saying nothing at all about a load that failed, which is the reassuring-empty defect wearing its
    // quietest possible face, and it would pass every other test in this file.
    rulesFail = true;
    withAuth(<Access />);
    await waitFor(() =>
      expect(
        screen.getByText("Rules could not be loaded. refresh to try again."),
      ).toBeTruthy(),
    );
    // ⚠ And it must never be the table's own emptiness, which claims none EXIST.
    expect(screen.queryByText(/No rules yet/)).toBeNull();
    expect(screen.queryByText(/0 rules while enforcing/)).toBeNull();
  });

  it("a failed load never renders a defaulted rule COUNT — it says the status is unavailable", async () => {
    rulesFail = true;
    withAuth(<Access />);

    await waitFor(() =>
      expect(
        screen.getByText("Rule status unavailable. Refresh to try again."),
      ).toBeTruthy(),
    );
    // The specific lie this prevents: "0 rules — ALL traffic denied." on a load that never returned. A count
    // derived from a failure is an authorization claim invented by the client.
    expect(screen.queryByText(/ALL traffic denied/)).toBeNull();
  });
});

// ⛔ THE TWO CLAIMS A SCREENSHOT WOULD PROVE AND A SECOND HUMAN PASS WOULD MISS.
//
// The wrong-type-tag defect was LIVE FOR A FULL REVIEW CYCLE and the founder caught it by eye. The next one
// may not be visible — a glyph is small, and "USER" beside a resource name reads as plausible. These assert
// at the DOM what the eye was doing.
//
// Backed out once already, because they could not reach the panel: a DOM assertion that cannot reach its
// subject is NO evidence, and tuning it until it passes is the tautological-guard shape. Re-added only after
// the mock actually renders the section.
describe("Access flow panel — the geometry contract and the type tags", () => {
  it("⛔ the SVG is a FIXED 600x312 — one user unit is one pixel", async () => {
    // `className="w-full"` over a viewBox let the container stretch 152x36 boxes to ~490x130 and truncate
    // every name. THE SCALE IS A CONTRACT. Second occurrence after the Sites map.
    withAuth(<Access />);
    const svg = await waitFor(() => {
      const el = document.querySelector('svg[role="img"]');
      if (!el) throw new Error("flow SVG not rendered");
      return el;
    });
    expect(svg.getAttribute("width")).toBe("600");
    expect(svg.getAttribute("height")).toBe("312");
    expect(svg.getAttribute("viewBox")).toBe("0 0 600 312");
    // ⛔ CLASS TOKENS, NOT SUBSTRINGS. `max-w-full` CONTAINS "w-full" and is CORRECT — it caps the element
    // on a narrow viewport without stretching it. My first regex matched the substring and reported the
    // right code as wrong, which is the inverted-finding shape one law down.
    const cls = (svg.getAttribute("class") ?? "").split(/\s+/);
    expect(cls).not.toContain("w-full");
    expect(cls).toContain("max-w-full"); // and the correct cap IS present
  });

  it("⛔ a RESOURCE destination renders R / RESOURCE, never U / USER", async () => {
    // The shipped defect: the kind was guessed by matching the label against member names, and
    // `label.startsWith(m.name)` is ALWAYS TRUE when a member has an empty name — which users.name
    // (NOT NULL DEFAULT '') produces for 144 rows. Every resource read USER.
    withAuth(<Access />);
    const svg = await waitFor(() => {
      const el = document.querySelector('svg[role="img"]');
      if (!el) throw new Error("flow SVG not rendered");
      return el;
    });
    const texts = Array.from(svg.querySelectorAll("text")).map(
      (t) => t.textContent,
    );
    // The fixture's rules are group -> resource, so both arms must be present and neither may be USER.
    expect(texts).toContain("RESOURCE");
    expect(texts).toContain("GROUP");
    expect(texts.filter((t) => t === "USER")).toHaveLength(0);
    expect(texts.filter((t) => t === "U")).toHaveLength(0);
  });

  it("⛔ a TEMPORARY grant renders DASHED, and the entry animation must not steal the property", async () => {
    // THE DEFECT: the reveal animated `stroke-dashoffset` with `stroke-dasharray: 1600`, and a CSS
    // declaration beats an SVG PRESENTATION ATTRIBUTE — so `strokeDasharray="5 6"` was silently overridden
    // and every temporary edge drew SOLID while the legend promised "- - - temporary".
    //   AN ANIMATION AND A SEMANTIC ENCODING MUST NOT SHARE A PROPERTY.
    withAuth(<Access />);
    const svg = await waitFor(() => {
      const el = document.querySelector('svg[role="img"]');
      if (!el) throw new Error("flow SVG not rendered");
      return el;
    });
    const paths = Array.from(svg.querySelectorAll("path"));
    const dashed = paths.filter(
      (p) => p.getAttribute("stroke-dasharray") === "5 6",
    );
    const solid = paths.filter((p) => !p.getAttribute("stroke-dasharray"));
    // BOTH arms: the fixture has a temporary rule and permanent ones, so each encoding must appear.
    expect(dashed.length).toBeGreaterThan(0);
    expect(solid.length).toBeGreaterThan(0);
    // And no path may carry the animation's old dasharray, which is what did the overriding.
    expect(
      paths.some((p) => p.getAttribute("stroke-dasharray") === "1600"),
    ).toBe(false);
    // The reveal lives on the GROUP, on a property nothing else encodes.
    expect(svg.querySelector("g.tnx-flow-edges")).toBeTruthy();
  });
});

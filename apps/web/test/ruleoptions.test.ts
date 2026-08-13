import { describe, expect, it } from "vitest";
import {
  sourceOptions,
  destinationOptions,
  SELF_SITE_REASON,
  ruleEffectSummary,
  ruleEffectCaution,
  DST_SCOPED,
  DST_WIDE,
} from "../src/lib/policyview";

/**
 * ⛔ THE VALIDITY RULES, TESTED WITHOUT A DOM — which is why they are pure functions rather than logic inside
 * the picker. The matrix they implement is measured from the compiler (`docs/rule-validity-matrix.md`), never
 * from what the old form happened to offer.
 */
const G = [{ id: "g1", name: "Engineering" }];
const M = [
  { user_id: "u1", email: "ana@x.com", name: "Ana" },
  { user_id: "u2", email: "bo@x.com" },
];
const S = [
  { id: "s1", name: "eu-lan" },
  { id: "s2", name: "ap-lan" },
];
const A = [{ device_id: "d1", name: "mcp-agent", gateway_name: "gw-1" }];
const R = [{ id: "r1", name: "gitlab" }];
const K = [{ id: "k1", name: "payments" }];

describe("rule option lists — one picker per side", () => {
  it("every source kind appears in ONE list, each carrying its kind as text", () => {
    // ⛔ THE TAG IS THE ONLY THING distinguishing a site named eu-lan from a group named eu-lan, and the two
    // behave completely differently in the compiler. It must be text, never a colour alone.
    const o = sourceOptions({
      groups: G,
      members: M,
      sites: S,
      agents: A,
      dstKind: "group",
      dstSite: "",
    });
    expect(o.map((x) => x.kind)).toEqual([
      "group",
      "user",
      "user",
      "site",
      "site",
      "agent",
    ]);
    expect(o.every((x) => x.tag.length > 0)).toBe(true);
  });

  it("a person's email rides along even when a display name exists", () => {
    // It is what an operator searches by, and the only disambiguator between two people with one name.
    const o = sourceOptions({
      groups: [],
      members: M,
      sites: [],
      agents: [],
      dstKind: "",
      dstSite: "",
    });
    expect(o[0].label).toBe("Ana");
    expect(o[0].detail).toBe("ana@x.com");
    // ⚠ And a member with no name falls back to the email rather than rendering blank.
    expect(o[1].label).toBe("bo@x.com");
  });

  it("an agent names the gateway it connects through", () => {
    const o = sourceOptions({
      groups: [],
      members: [],
      sites: [],
      agents: A,
      dstKind: "",
      dstSite: "",
    });
    expect(o[0].detail).toBe("via gw-1");
  });

  it("⭐ A SITE CANNOT REACH ITSELF — and the option is SHOWN, DISABLED, WITH THE REASON", () => {
    // Hiding it would teach nothing: the operator changes the other side and an entry silently vanishes.
    // Saying why teaches the rule. This mirrors the server's invalid_rule_self_site — the API is the guard.
    const src = sourceOptions({
      groups: G,
      members: [],
      sites: S,
      agents: [],
      dstKind: "site",
      dstSite: "s1",
    });
    const eu = src.find((o) => o.value === "s1")!;
    expect(eu.unavailable).toBe(SELF_SITE_REASON);
    // ⛔ THE OTHER SITE IS UNTOUCHED. Site-to-site transit is S8.2's whole subject and is proven on the
    // wire; a guard that disabled every site would delete a shipped feature while passing the line above.
    expect(src.find((o) => o.value === "s2")!.unavailable).toBeUndefined();
  });

  it("…and symmetrically on the destination side", () => {
    const dst = destinationOptions({
      groups: G,
      resources: R,
      sites: S,
      services: K,
      srcKind: "site",
      srcSite: "s2",
    });
    expect(dst.find((o) => o.value === "s2")!.unavailable).toBe(
      SELF_SITE_REASON,
    );
    expect(dst.find((o) => o.value === "s1")!.unavailable).toBeUndefined();
  });

  it("⚠ NOTHING IS DISABLED WHEN THE OTHER SIDE IS NOT A SITE", () => {
    // Without this, "disable everything" would satisfy the assertions above and make the form unusable —
    // the guard-that-is-an-outage shape.
    const dst = destinationOptions({
      groups: G,
      resources: R,
      sites: S,
      services: K,
      srcKind: "group",
      srcSite: "",
    });
    expect(dst.every((o) => !o.unavailable)).toBe(true);
  });

  it("every destination kind is offered, including k8s services", () => {
    const dst = destinationOptions({
      groups: G,
      resources: R,
      sites: S,
      services: K,
      srcKind: "group",
      srcSite: "",
    });
    expect(new Set(dst.map((o) => o.kind))).toEqual(
      new Set(["group", "resource", "site", "k8s_service"]),
    );
  });
});

/**
 * ⛔ THE EFFECT SENTENCE — the form's answer to "why was I able to create that?"
 *
 * `agent rajan → group Contractors` was creatable and looked ordinary. It grants one machine principal
 * unrestricted access to every device owned by every Contractor, because a group destination is port-unscoped
 * by construction (`compiler.go:442`, `Protocol: ProtoAny`). Nothing was wrong with the software; everything
 * was wrong with what the screen let someone believe they were doing.
 */
describe("rule effect summary", () => {
  it("⭐ A GROUP DESTINATION SAYS *ALL PORTS*, BECAUSE IT IS", () => {
    const e = ruleEffectSummary({
      srcKind: "agent",
      srcLabel: "rajan",
      dstKind: "group",
      dstLabel: "Contractors",
    });
    expect(e.wide).toBe(true);
    expect(e.text).toContain("AI agent rajan");
    expect(e.text).toContain(
      "every device belonging to every member of Contractors",
    );
    expect(e.text).toContain("ALL ports");
  });

  it("a site destination is equally unbounded", () => {
    expect(
      ruleEffectSummary({
        srcKind: "group",
        srcLabel: "Eng",
        dstKind: "site",
        dstLabel: "eu-lan",
      }).wide,
    ).toBe(true);
  });

  it("⛔ AND A RESOURCE IS NOT — the distinction is the whole point", () => {
    // Without this, marking everything `wide` would satisfy the assertions above and destroy the signal:
    // a warning that fires on every rule is one nobody reads.
    const e = ruleEffectSummary({
      srcKind: "agent",
      srcLabel: "rajan",
      dstKind: "resource",
      dstLabel: "gitlab",
    });
    expect(e.wide).toBe(false);
    expect(e.text).toContain("declared ports only");
  });

  it("a k8s service is port-scoped too", () => {
    expect(
      ruleEffectSummary({
        srcKind: "user",
        srcLabel: "Ana",
        dstKind: "k8s_service",
        dstLabel: "pay",
      }).wide,
    ).toBe(false);
  });

  it("⚠ THE CAUTION FIRES ONLY FOR THE SHAPE THAT IS USUALLY A MISTAKE", () => {
    // A machine principal granted unrestricted access to humans' own devices. Legitimate when deliberate,
    // which is why it is a question about intent rather than a refusal.
    expect(ruleEffectCaution("agent", "group")).toMatch(/machine principal/);
    expect(ruleEffectCaution("agent", "site")).toMatch(/machine principal/);
    // ⛔ And NOT otherwise. A caution on every rule is a caution nobody reads.
    expect(ruleEffectCaution("agent", "resource")).toBeNull();
    expect(ruleEffectCaution("group", "group")).toBeNull();
    expect(ruleEffectCaution("user", "site")).toBeNull();
  });
});

describe("option sections — where port scope becomes visible", () => {
  it("⛔ THE TWO DESTINATION SECTIONS SAY WHICH IS UNBOUNDED", () => {
    const dst = destinationOptions({
      groups: G,
      resources: R,
      sites: S,
      services: K,
      srcKind: "group",
      srcSite: "",
    });
    const scoped = dst.filter(
      (o) => o.kind === "resource" || o.kind === "k8s_service",
    );
    const wide = dst.filter((o) => o.kind === "group" || o.kind === "site");
    expect(new Set(scoped.map((o) => o.section))).toEqual(
      new Set([DST_SCOPED]),
    );
    expect(new Set(wide.map((o) => o.section))).toEqual(new Set([DST_WIDE]));
    // The heading carries the fact a per-row tag cannot.
    expect(DST_WIDE).toMatch(/ALL ports/);
  });

  it("sources are filed as People / Machines / Networks", () => {
    // ⛔ An agent gets its OWN section: filing it under People would imply an owner carrying it, and under
    // Networks would imply a subnet. It is one machine, and that is a third thing.
    const src = sourceOptions({
      groups: G,
      members: M,
      sites: S,
      agents: A,
      dstKind: "",
      dstSite: "",
    });
    expect(src.find((o) => o.kind === "agent")!.section).toBe("Machines");
    expect(src.find((o) => o.kind === "user")!.section).toBe("People");
    expect(src.find((o) => o.kind === "group")!.section).toBe("People");
    expect(src.find((o) => o.kind === "site")!.section).toBe("Networks");
  });
});

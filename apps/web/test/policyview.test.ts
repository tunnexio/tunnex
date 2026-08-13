import { describe, it, expect } from "vitest";
import {
  modeEnableConfirm,
  policyGate,
  ruleRow,
  swapRule,
  roleFromMembers,
  sectionRender,
  staleNoticeText,
  pruneStaleRuleIds,
  accessView,
  grantExpiry,
  extendErrorCopy,
  attributionLabel,
  activeMembers,
  rulesSummary,
  rulesEmptyState,
  rulesEmptyCopy,
  flowGraphState,
  flowGraphNote,
  flowLayout,
  flowCrossings,
  flowGlyph,
  flowTag,
  cascadeConfirmCopy,
  cascadeConfirmSatisfied,
  srcGroupEmptyWarn,
  srcGroupEmptyBadge,
  srcGroupEmptyExplain,
  FLOW_COLUMN_CAP,
  FLOW_MIN_COVERAGE,
  FLOW_GRAPH_MAX_RULES,
  ruleBody,
  grantControls,
  type LoadState,
} from "../src/lib/policyview";
import { loadOne, type Loaded } from "../src/lib/api";
import type { PolicyRule, UserGroup, Resource, Member } from "../src/lib/api";

const G = (id: string, name: string) => ({ id, name }) as UserGroup;
const R = (id: string, name: string) => ({ id, name }) as Resource;
const LOADED: LoadState = { groupsLoaded: true, resourcesLoaded: true };

describe("D-a4 mode-enable confirm = pure function of the rule COUNT", () => {
  it("N>0 → generic count copy, not danger", () => {
    const c = modeEnableConfirm(3);
    expect(c.danger).toBe(false);
    expect(c.body).toContain("3 allow rules");
    expect(c.body).not.toMatch(/no allow rules/i);
  });
  it("singular vs plural", () => {
    expect(modeEnableConfirm(1).body).toContain("1 allow rule");
    expect(modeEnableConfirm(1).body).not.toContain("1 allow rules");
  });
  it("ZERO rules → the STRONG danger gate naming self-lockout", () => {
    const c = modeEnableConfirm(0);
    expect(c.danger).toBe(true);
    expect(c.body).toMatch(/denies ALL traffic/i);
    expect(c.body).toMatch(/your own access/i);
  });
  it("never computes a blast radius (no device names / counts of affected devices)", () => {
    // Copy is a function of the RULE count only — it must not claim which devices are hit.
    expect(modeEnableConfirm(5).body).not.toMatch(/device/i);
  });
});

describe("policyGate — enterprise + RBAC + verified-email", () => {
  it("open edition → nothing, even for an owner", () => {
    const g = policyGate({
      role: "owner",
      emailVerified: true,
      edition: "open",
    });
    expect(g.isEnterprise).toBe(false);
    expect(g.canView).toBe(false);
    expect(g.canManagePolicy).toBe(false);
    expect(g.canManageDevices).toBe(false);
  });
  it("enterprise member → no view (policy is admin/owner only)", () => {
    const g = policyGate({
      role: "member",
      emailVerified: true,
      edition: "enterprise",
    });
    expect(g.canView).toBe(false);
    expect(g.canManagePolicy).toBe(false);
  });
  it("enterprise admin, verified → view + manage", () => {
    const g = policyGate({
      role: "admin",
      emailVerified: true,
      edition: "enterprise",
    });
    expect(g.canView).toBe(true);
    expect(g.canManagePolicy).toBe(true);
    expect(g.canManageDevices).toBe(true);
  });
  it("enterprise admin, UNVERIFIED email → can view but NOT manage (mirrors server)", () => {
    const g = policyGate({
      role: "admin",
      emailVerified: false,
      edition: "enterprise",
    });
    expect(g.canView).toBe(true);
    expect(g.canManagePolicy).toBe(false);
    expect(g.canManageDevices).toBe(false);
  });
});

describe("D-a6 rule label — NEVER omit; DELETED ≠ UNRESOLVED", () => {
  const groups = [G("g-eng", "Engineering"), G("g-db", "Databases")];
  const resources = [R("r-net", "10.0.5.0/24")];

  it("resolves group→group and group→resource to names", () => {
    const g2g: PolicyRule = {
      id: "1",
      src_group_id: "g-eng",
      dst_kind: "group",
      dst_group_id: "g-db",
    } as PolicyRule;
    const row = ruleRow(g2g, groups, resources, [], [], LOADED);
    expect(row.src.label).toBe("Engineering");
    expect(row.dst.label).toBe("Databases");
    expect(row.broken).toBe(false);

    const g2r: PolicyRule = {
      id: "2",
      src_group_id: "g-eng",
      dst_kind: "resource",
      dst_resource_id: "r-net",
    } as PolicyRule;
    expect(ruleRow(g2r, groups, resources, [], [], LOADED).dst.label).toBe(
      "10.0.5.0/24",
    );
  });

  it("carries managed_by_operator onto the row (S10.2 D2 cond 1 — badge + withhold-edit source)", () => {
    const managed = {
      id: "m",
      src_group_id: "g-eng",
      dst_kind: "group",
      dst_group_id: "g-db",
      managed_by_operator: true,
    } as PolicyRule;
    const human = {
      id: "h",
      src_group_id: "g-eng",
      dst_kind: "group",
      dst_group_id: "g-db",
    } as PolicyRule;
    expect(
      ruleRow(managed, groups, resources, [], [], LOADED).managedByOperator,
    ).toBe(true);
    expect(
      ruleRow(human, groups, resources, [], [], LOADED).managedByOperator,
    ).toBeFalsy();
  });

  it("WF-8: site rules resolve to NAMES, and two UUIDv7-prefix-sharing sites render distinguishably", () => {
    // UUIDv7 (time-ordered) — created seconds apart, so they SHARE the first 8 chars (the demo bug).
    const azure = {
      id: "019f762b-b62b-7aa8-9362-249ecf231395",
      name: "azure-site",
    } as any;
    const aws = {
      id: "019f762b-c00c-7fff-8888-000000000000",
      name: "aws-site",
    } as any;
    const rule: PolicyRule = {
      id: "s",
      src_kind: "site",
      src_site_id: azure.id,
      dst_kind: "site",
      dst_site_id: aws.id,
    } as PolicyRule;
    const row = ruleRow(rule, [], [], [], [azure, aws], {
      groupsLoaded: true,
      resourcesLoaded: true,
      sitesLoaded: true,
    });
    expect(row.src.label).toBe("site azure-site");
    expect(row.dst.label).toBe("site aws-site");
    expect(row.src.label).not.toBe(row.dst.label); // the prefix-collision no longer makes them identical
    expect(row.broken).toBe(false);
    // sites set FAILED to load → honest "refresh", not a fake name.
    const un = ruleRow(rule, [], [], [], [], {
      groupsLoaded: true,
      resourcesLoaded: true,
      sitesLoaded: false,
    });
    expect(un.src.state).toBe("unresolved");
    expect(un.src.label).toMatch(/refresh/);
  });

  it("referent ABSENT from a LOADED set → 'deleted' (not omitted, broken=true)", () => {
    const rule: PolicyRule = {
      id: "3",
      src_group_id: "g-gone",
      dst_kind: "group",
      dst_group_id: "g-db",
    } as PolicyRule;
    const row = ruleRow(rule, groups, resources, [], [], LOADED);
    expect(row.src.state).toBe("deleted");
    expect(row.src.label).toMatch(/deleted group/i);
    expect(row.broken).toBe(true);
    expect(row.id).toBe("3"); // still present — never hidden
  });

  it("set FAILED TO LOAD → 'unresolved — refresh', NOT 'deleted' (no false alarm)", () => {
    const rule: PolicyRule = {
      id: "4",
      src_group_id: "g-eng",
      dst_kind: "group",
      dst_group_id: "g-db",
    } as PolicyRule;
    const row = ruleRow(rule, [], resources, [], [], {
      groupsLoaded: false,
      resourcesLoaded: true,
    });
    expect(row.src.state).toBe("unresolved");
    expect(row.src.label).toMatch(/unresolved group.*refresh/i);
    expect(row.src.label).not.toMatch(/deleted/i); // must NOT lie about why
  });

  it("resource set failed to load → dst unresolved, not deleted", () => {
    const rule: PolicyRule = {
      id: "5",
      src_group_id: "g-eng",
      dst_kind: "resource",
      dst_resource_id: "r-net",
    } as PolicyRule;
    const row = ruleRow(rule, groups, [], [], [], {
      groupsLoaded: true,
      resourcesLoaded: false,
    });
    expect(row.dst.state).toBe("unresolved");
    expect(row.dst.label).toMatch(/refresh/i);
  });
});

describe("S8.7 ruleRow — cidr source: literal label + read-time warn badge (served verbatim, no client re-derivation)", () => {
  const grp = [G("g1", "Eng")];
  const cidrRule = (outside: boolean): PolicyRule =>
    ({
      id: "c1",
      src_kind: "cidr",
      src_cidr: "172.31.17.64/32",
      dst_kind: "group",
      dst_group_id: "g1",
      cidr_outside_org_ranges: outside,
    }) as PolicyRule;
  it("src renders the LITERAL CIDR, always ok (a value, never a deletable referent)", () => {
    const row = ruleRow(cidrRule(false), grp, [], [], [], LOADED);
    expect(row.src.label).toBe("172.31.17.64/32");
    expect(row.src.state).toBe("ok");
    expect(row.broken).toBe(false); // an out-of-world cidr is NOT broken — a valid rule that WARNS
  });
  it("the warn badge is the SERVED field verbatim — appears when outside, clears when inside (both directions)", () => {
    expect(
      ruleRow(cidrRule(true), grp, [], [], [], LOADED).cidrOutsideRanges,
    ).toBe(true);
    expect(
      ruleRow(cidrRule(false), grp, [], [], [], LOADED).cidrOutsideRanges,
    ).toBe(false);
    // still not "broken" even when warning — warn-not-refuse
    expect(ruleRow(cidrRule(true), grp, [], [], [], LOADED).broken).toBe(false);
  });
});

describe("S10.3 ruleRow — k8s_service dst: FQDN label + vanished warn badge (served verbatim)", () => {
  const grp = [G("g1", "Eng")];
  const svc = [
    {
      id: "k1",
      cluster_id: "c1",
      name: "api",
      namespace: "prod",
      protocol: "tcp",
      vip: "100.64.0.5",
      fqdn: "api.prod.svc.prod.k8s.acme.com",
    },
  ] as never[];
  const k8sRule = (vanished: boolean): PolicyRule =>
    ({
      id: "ks1",
      src_group_id: "g1",
      dst_kind: "k8s_service",
      dst_k8s_service_id: "k1",
      dst_k8s_service_vanished: vanished,
    }) as PolicyRule;
  const L: LoadState = {
    groupsLoaded: true,
    resourcesLoaded: true,
    k8sServicesLoaded: true,
  };
  it("dst renders the server FQDN (copy-not-construct), state ok", () => {
    const row = ruleRow(k8sRule(false), grp, [], [], [], L, svc);
    expect(row.dst.label).toBe("api.prod.svc.prod.k8s.acme.com");
    expect(row.dst.state).toBe("ok");
    expect(row.broken).toBe(false);
  });
  it("the vanished badge is the SERVED field verbatim, both directions", () => {
    expect(
      ruleRow(k8sRule(true), grp, [], [], [], L, svc).k8sServiceVanished,
    ).toBe(true);
    expect(
      ruleRow(k8sRule(false), grp, [], [], [], L, svc).k8sServiceVanished,
    ).toBe(false);
  });
  it("a Service absent from the LIVE set resolves as removed (deleted), still not a load failure", () => {
    const row = ruleRow(k8sRule(true), grp, [], [], [], L, []);
    expect(row.dst.state).toBe("deleted");
    expect(row.dst.label).toMatch(/removed service/i);
  });
  it("services set failed to load → dst unresolved, not deleted", () => {
    const row = ruleRow(
      k8sRule(false),
      grp,
      [],
      [],
      [],
      { groupsLoaded: true, resourcesLoaded: true, k8sServicesLoaded: false },
      [],
    );
    expect(row.dst.state).toBe("unresolved");
    expect(row.dst.label).toMatch(/refresh/i);
  });
});

describe("loadOne — the class armed-guard: a failure NEVER reads as absence", () => {
  it("non-2xx (error present, data undefined) → NOT ok (never a reassuring empty)", async () => {
    const r = await loadOne(async () => ({
      data: undefined,
      error: { error: { message: "boom" } },
    }));
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toBe("boom");
  });
  it("data undefined with no error → NOT ok", async () => {
    const r = await loadOne(async () => ({ data: undefined }));
    expect(r.ok).toBe(false);
  });
  it("network REJECT (openapi-fetch throws) → NOT ok, legible message", async () => {
    const r = await loadOne(async () => {
      throw new Error("ECONNREFUSED");
    });
    expect(r.ok).toBe(false);
    if (!r.ok) expect(r.error).toMatch(/reach the API/i);
  });
  it("data present → ok with the data", async () => {
    const r = await loadOne(async () => ({ data: [1, 2, 3] }));
    expect(r.ok).toBe(true);
    if (r.ok) expect(r.data).toEqual([1, 2, 3]);
  });
});

describe("S8.3 rulesSummary — states enumerated, derived from Loaded<T> (failed never reads as 0-rules)", () => {
  const ok = <T>(data: T): Loaded<T> => ({ ok: true, data });
  const fail: Loaded<never> = { ok: false, error: "boom" };

  it("either input still loading → loading (no premature posture claim)", () => {
    expect(rulesSummary({ modeResult: null, rulesResult: ok(0) }).state).toBe(
      "loading",
    );
    expect(
      rulesSummary({ modeResult: ok("enforcing"), rulesResult: null }).state,
    ).toBe("loading");
  });
  it("a FAILED rules load → 'failed', NEVER the 0-rules message (the reassuring-empty class on the loud line)", () => {
    const s = rulesSummary({ modeResult: ok("enforcing"), rulesResult: fail });
    expect(s.state).toBe("failed");
    expect(s.loud).toBe(false);
    expect(s.text).not.toMatch(/0 rules/);
  });
  it("a failed MODE load → failed (can't claim off or enforcing)", () => {
    expect(rulesSummary({ modeResult: fail, rulesResult: ok(3) }).state).toBe(
      "failed",
    );
  });
  it("off → open-mesh copy, not loud", () => {
    const s = rulesSummary({ modeResult: ok("off"), rulesResult: ok(0) });
    expect(s.state).toBe("off");
    expect(s.text).toMatch(/open mesh/i);
    expect(s.loud).toBe(false);
  });
  it("enforcing + 0 rules → LOUD 'all traffic denied' (the legibility-law lockout state)", () => {
    const s = rulesSummary({ modeResult: ok("enforcing"), rulesResult: ok(0) });
    expect(s.state).toBe("enforcing_empty");
    expect(s.loud).toBe(true);
    expect(s.text).toMatch(/denied/i);
  });
  it("enforcing + N rules → 'N rules — default-deny active', not loud; singular at 1", () => {
    expect(
      rulesSummary({ modeResult: ok("enforcing"), rulesResult: ok(3) }).text,
    ).toMatch(/3 rules/);
    expect(
      rulesSummary({ modeResult: ok("enforcing"), rulesResult: ok(1) }).text,
    ).toMatch(/1 rule\b/);
    expect(
      rulesSummary({ modeResult: ok("enforcing"), rulesResult: ok(3) }).loud,
    ).toBe(false);
  });
});

describe("S8.2c D5 ruleBody — the Access builder now creates SITE-subject rules (via the API, not a DB insert)", () => {
  const base = {
    src: "g1",
    srcUser: "u1",
    srcSite: "s1",
    srcCidr: "172.31.17.64/32",
    srcAgent: "",
    dstGroup: "g2",
    dstResource: "r1",
    dstSite: "s2",
    dstK8sService: "k1",
    expiresAt: "",
    editing: false,
  };
  it("site → site sets ONLY the site ids (the demo's DB-insert path, now first-class in the UI)", () => {
    const b = ruleBody({ ...base, srcKind: "site", dstKind: "site" });
    expect(b).toMatchObject({
      src_kind: "site",
      src_site_id: "s1",
      dst_kind: "site",
      dst_site_id: "s2",
    });
    expect("src_group_id" in b).toBe(false);
    expect("dst_resource_id" in b).toBe(false);
  });
  it("group → site (a device group reaching a site LAN)", () => {
    expect(
      ruleBody({ ...base, srcKind: "group", dstKind: "site" }),
    ).toMatchObject({
      src_kind: "group",
      src_group_id: "g1",
      dst_kind: "site",
      dst_site_id: "s2",
    });
  });
  it("S8.7 cidr → resource sets ONLY src_cidr (the /32-precise source)", () => {
    const b = ruleBody({ ...base, srcKind: "cidr", dstKind: "resource" });
    expect(b).toMatchObject({
      src_kind: "cidr",
      src_cidr: "172.31.17.64/32",
      dst_kind: "resource",
      dst_resource_id: "r1",
    });
    expect("src_group_id" in b).toBe(false);
    expect("src_site_id" in b).toBe(false);
  });
  it("existing kinds unchanged (group→group, user→resource)", () => {
    expect(
      ruleBody({ ...base, srcKind: "group", dstKind: "group" }),
    ).toMatchObject({
      src_kind: "group",
      dst_kind: "group",
      dst_group_id: "g2",
    });
    expect(
      ruleBody({ ...base, srcKind: "user", dstKind: "resource" }),
    ).toMatchObject({
      src_kind: "user",
      src_user_id: "u1",
      dst_kind: "resource",
      dst_resource_id: "r1",
    });
  });
  it("expiry is create-only", () => {
    expect(
      "expires_at" in
        ruleBody({
          ...base,
          srcKind: "site",
          dstKind: "site",
          expiresAt: "2030-01-01T00:00",
          editing: false,
        }),
    ).toBe(true);
    expect(
      "expires_at" in
        ruleBody({
          ...base,
          srcKind: "site",
          dstKind: "site",
          expiresAt: "2030-01-01T00:00",
          editing: true,
        }),
    ).toBe(false);
  });
  it("S10.3 group → k8s_service sets ONLY the Service id (never a resource/site id)", () => {
    const b = ruleBody({ ...base, srcKind: "group", dstKind: "k8s_service" });
    expect(b).toMatchObject({
      src_kind: "group",
      src_group_id: "g1",
      dst_kind: "k8s_service",
      dst_k8s_service_id: "k1",
    });
    expect("dst_resource_id" in b).toBe(false);
    expect("dst_site_id" in b).toBe(false);
  });
});

describe("[291] sectionRender — legibility signals COMPOSE, never compete", () => {
  it("loadError + notice both set → retry shows AND notice STILL shows (content hidden)", () => {
    const v = sectionRender(
      "couldn't load",
      "old rule still active — retry removal",
    );
    expect(v.showRetry).toBe(true);
    expect(v.showNotice).toBe(true); // the partial-swap warning is NOT masked by the load failure
    expect(v.showContent).toBe(false); // only CONTENT is replaced by retry
  });
  it("no error, notice set → content + notice", () => {
    expect(sectionRender(null, "note")).toEqual({
      showRetry: false,
      showContent: true,
      showNotice: true,
    });
  });
  it("no error, no notice → content only", () => {
    expect(sectionRender(null, null)).toEqual({
      showRetry: false,
      showContent: true,
      showNotice: false,
    });
  });
});

describe("notices reduction — derived from staleRuleIds (single source of truth)", () => {
  const R = (id: string) => ({ id }) as PolicyRule;

  it("staleNoticeText: none → null; one → the partial message; many → a count line", () => {
    expect(staleNoticeText([])).toBeNull();
    expect(staleNoticeText(["abcdef12"])).toMatch(
      /could not be removed.*still active/i,
    );
    expect(staleNoticeText(["a", "b"])).toMatch(
      /^2 rules could not be removed/i,
    );
  });

  it("[371] a clean create never drops the warning — the set is only pruned by pruneStaleRuleIds", () => {
    // onDone(clean) adds nothing; the derived notice still reflects the live set.
    const set = ["X"];
    expect(staleNoticeText(set)).not.toBeNull(); // still shown after any unrelated success
  });

  it("[A] pruneStaleRuleIds NEVER clears on a FAILED load (loadOk=false) — persists", () => {
    expect(pruneStaleRuleIds(["X"], false, [])).toEqual(["X"]);
    expect(pruneStaleRuleIds(["X"], false, [R("Y")])).toEqual(["X"]);
  });

  it("[A] on a SUCCESSFUL load, an absent stale id CLEARS; a still-present one persists", () => {
    expect(pruneStaleRuleIds(["X"], true, [R("Y")])).toEqual([]); // X gone → cleared
    expect(pruneStaleRuleIds(["X"], true, [R("X"), R("Y")])).toEqual(["X"]); // unrelated Y present, X kept
  });

  it("[B] sequential partials — per-id prune, the first stale id is NOT orphaned", () => {
    // Two partials tracked; a successful load where only Z resolved keeps X.
    expect(pruneStaleRuleIds(["X", "Z"], true, [R("X")])).toEqual(["X"]);
  });
});

describe("[75]+[101] accessView — upsell needs only edition; role in-flight is not the gate", () => {
  const base = {
    fatal: false,
    loadError: false,
    editionReady: true,
    isEnterprise: true,
    roleError: false,
    roleResolved: true,
    canView: true,
    role: "owner" as const,
  };

  // ⛔ [75] IS REVERSED, AND IT PINNED THE DEFECT. It asserted "non-enterprise + members-fail -> upsell, NOT
  // role_retry", on the reasoning that role is irrelevant once the edition gate fires. THAT REASONING IS THE
  // BUG (S14.12 D2): the server answers `forbidden` to an open-edition MEMBER and `edition_required` to an
  // open-edition OWNER, so the role decides WHICH refusal is true — and when the role failed to load we do
  // not know which. `upsell` there asserts "you would get this if you upgraded", which is FALSE for a member.
  it("⛔ non-enterprise + role UNKNOWN -> role_retry, because which refusal is true depends on the role", () => {
    expect(
      accessView({
        ...base,
        isEnterprise: false,
        roleError: true,
        roleResolved: false,
      }),
    ).toBe("role_retry");
  });

  it("⛔ OPEN + MEMBER -> member_gate, NEVER upsell — the S14.12 defect, measured on the open stack", () => {
    // GET /policies as member@ on :8081 answers 403 forbidden, not edition_required. Selling Enterprise to a
    // caller whose role forbids the feature on ANY edition is the S14.5 halt running forward.
    expect(
      accessView({
        ...base,
        isEnterprise: false,
        role: "member",
        canView: false,
      }),
    ).toBe("member_gate");
  });

  it("OPEN + OWNER -> upsell — the upsell reaches whoever could actually use it", () => {
    // Both arms of the same gate. Without this, "always member_gate" would satisfy the assertion above.
    expect(
      accessView({
        ...base,
        isEnterprise: false,
        role: "owner",
        canView: false,
      }),
    ).toBe("upsell");
  });

  it("ENTERPRISE + member -> member_gate — the role answer is the same on both editions", () => {
    expect(
      accessView({
        ...base,
        isEnterprise: true,
        role: "member",
        canView: false,
      }),
    ).toBe("member_gate");
  });
  it("[101] enterprise + role in-flight → role_loading, NOT member_gate", () => {
    expect(accessView({ ...base, roleResolved: false, canView: false })).toBe(
      "role_loading",
    );
  });
  it("enterprise + roleError → role_retry", () => {
    expect(accessView({ ...base, roleError: true, roleResolved: false })).toBe(
      "role_retry",
    );
  });
  it("enterprise admin resolved → admin_body; member resolved → member_gate", () => {
    expect(accessView({ ...base, canView: true })).toBe("admin_body");
    expect(accessView({ ...base, canView: false })).toBe("member_gate");
  });
  it("meta/org not ready → loading; fatal → fatal; loadError → load_retry", () => {
    expect(accessView({ ...base, editionReady: false })).toBe("loading");
    expect(accessView({ ...base, fatal: true })).toBe("fatal");
    expect(accessView({ ...base, loadError: true })).toBe("load_retry");
  });
});

describe("[0] roleFromMembers — a FAILED members load is NOT 'member' (no false lockout)", () => {
  const me = "u-me";
  it("failed load → failed:true, NO role (caller shows retry, not the manage-gate)", () => {
    const res = roleFromMembers(
      { ok: false, error: "boom" } as Loaded<Member[]>,
      me,
    );
    expect(res.failed).toBe(true);
    expect(res.role).toBeUndefined();
    // Critical: policyGate must NOT be fed this as role=undefined-treated-as-member.
  });
  it("ok load, actor is admin → role admin, not failed", () => {
    const members = [{ user_id: me, role: "admin" } as Member];
    const res = roleFromMembers({ ok: true, data: members }, me);
    expect(res).toEqual({ role: "admin", failed: false });
  });
  it("ok load, actor absent from roster → role undefined but NOT failed", () => {
    const res = roleFromMembers({ ok: true, data: [] as Member[] }, me);
    expect(res.failed).toBe(false);
    expect(res.role).toBeUndefined();
  });
});

describe("D-a5 swapRule — CREATE-THEN-DELETE, gap-free, LEGIBLE partial", () => {
  it("happy path: create then delete → replaced", async () => {
    const calls: string[] = [];
    const out = await swapRule(
      "old-1",
      async () => {
        calls.push("create");
        return { id: "new-1" };
      },
      async () => {
        calls.push("delete");
        return;
      },
    );
    expect(out).toEqual({ outcome: "replaced", newId: "new-1" });
    expect(calls).toEqual(["create", "delete"]); // create STRICTLY before delete
  });

  it("create fails → old rule is NEVER deleted (no gap), edit aborts", async () => {
    let deleted = false;
    const out = await swapRule(
      "old-1",
      async () => ({ error: "boom" }),
      async () => {
        deleted = true;
      },
    );
    expect(out).toEqual({ outcome: "create_failed", error: "boom" });
    expect(deleted).toBe(false); // delete-old must NOT run when create failed
  });

  it("create ok + delete FAILS → 'partial': duplicate persists, LEGIBLE, both ids returned", async () => {
    const out = await swapRule(
      "old-1",
      async () => ({ id: "new-1" }),
      async () => ({ error: "delete failed" }),
    );
    expect(out).toEqual({
      outcome: "partial",
      newId: "new-1",
      oldId: "old-1",
      error: "delete failed",
    });
    // Caller uses this to show BOTH rules + a retry — never a silent duplicate.
  });
});

const M = (
  id: string,
  name: string,
  status: "active" | "deactivated" = "active",
) => ({ user_id: id, name, email: `${name}@x`, status }) as Member;

describe("S7.5.4 ruleRow user subject", () => {
  const rule = {
    id: "r1",
    src_kind: "user",
    src_user_id: "u1",
    dst_kind: "resource",
    dst_resource_id: "res1",
  } as PolicyRule;
  const resources = [R("res1", "db")];
  it("resolves a per-user subject to the member name", () => {
    const row = ruleRow(rule, [], resources, [M("u1", "alice")], [], {
      groupsLoaded: true,
      resourcesLoaded: true,
      membersLoaded: true,
    });
    expect(row.src.label).toBe("alice");
    expect(row.src.state).toBe("ok");
  });
  it("a removed user (not in a loaded roster) shows distinctly, never mislabeled", () => {
    const row = ruleRow(rule, [], resources, [], [], {
      groupsLoaded: true,
      resourcesLoaded: true,
      membersLoaded: true,
    });
    expect(row.src.label).toMatch(/removed user/);
    expect(row.src.state).toBe("deleted");
    expect(row.broken).toBe(true);
  });
  it("a FAILED roster load reads unresolved (refresh), not removed", () => {
    const row = ruleRow(rule, [], resources, [], [], {
      groupsLoaded: true,
      resourcesLoaded: true,
      membersLoaded: false,
    });
    expect(row.src.state).toBe("unresolved");
  });
});

describe("S7.5.4 grantExpiry (linger model)", () => {
  const now = 1_000_000_000_000;
  it("no expiry = permanent, not extendable", () => {
    expect(grantExpiry({ expires_at: null }, now)).toEqual({
      state: "permanent",
      label: "permanent",
      extendable: false,
    });
  });
  it("future expiry = active, extendable", () => {
    const g = grantExpiry(
      { expires_at: new Date(now + 3 * 3600_000).toISOString() },
      now,
    );
    expect(g.state).toBe("active");
    expect(g.label).toMatch(/expires in 3h/);
    expect(g.extendable).toBe(true);
  });
  it("past expiry = expired-but-EXTENDABLE (linger: shown + the extend 409s legibly)", () => {
    const g = grantExpiry(
      { expires_at: new Date(now - 2 * 3600_000).toISOString() },
      now,
    );
    expect(g.state).toBe("expired");
    expect(g.label).toMatch(/expired 2h ago/);
    expect(g.extendable).toBe(true); // the server refuses with 409 grant_lapsed, surfaced legibly
  });
});

describe("S7.5.4 extendErrorCopy", () => {
  it("maps typed 409 codes to legible copy, never a raw error", () => {
    expect(extendErrorCopy("grant_lapsed")).toMatch(/already expired/);
    expect(extendErrorCopy("not_temporary")).toMatch(/permanent grant/);
    expect(extendErrorCopy(undefined)).toMatch(/Could not extend/);
  });
});

describe("S7.5.4 attributionLabel (rider 1 — absence is visible)", () => {
  it("device present + user unresolved shows 'device X · user unknown', never blank", () => {
    expect(attributionLabel({ deviceId: "dev-abc12345", userId: null })).toBe(
      "device dev-abc1… · user unknown",
    );
    expect(
      attributionLabel({
        deviceId: "d",
        userId: null,
        deviceName: "alice-laptop",
      }),
    ).toBe("alice-laptop · user unknown");
  });
  it("both resolved shows device · user", () => {
    expect(
      attributionLabel({
        deviceId: "d",
        userId: "u",
        deviceName: "laptop",
        userName: "alice",
      }),
    ).toBe("laptop · alice");
  });
  it("no device stamped reads 'unattributed', not a blank/dash", () => {
    expect(attributionLabel({ deviceId: null, userId: null })).toBe(
      "unattributed",
    );
  });
});

describe("S7.5.4 activeMembers (D1 picker constraint)", () => {
  it("offers only current active members", () => {
    const out = activeMembers([
      M("u1", "alice"),
      M("u2", "bob", "deactivated"),
    ]);
    expect(out.map((m) => m.user_id)).toEqual(["u1"]);
  });
});

import { canEditRuleInModal } from "../src/lib/policyview";

describe("canEditRuleInModal — site rules are NOT editable in the group/resource modal (S8.1 dst, S8.2 src)", () => {
  it("group and resource rules (with a group/user source) are editable", () => {
    expect(canEditRuleInModal({ src_kind: "group", dst_kind: "group" })).toBe(
      true,
    );
    expect(canEditRuleInModal({ src_kind: "user", dst_kind: "resource" })).toBe(
      true,
    );
  });
  it("a site-DST rule is NOT editable here (would silently rewrite it — write-guard, not display)", () => {
    expect(canEditRuleInModal({ src_kind: "group", dst_kind: "site" })).toBe(
      false,
    );
  });
  it("a site-SRC rule (S8.2) is NOT editable here either (same write-guard)", () => {
    expect(canEditRuleInModal({ src_kind: "site", dst_kind: "group" })).toBe(
      false,
    );
  });
});

// (The duplicate `import { ruleRow }` that stood here was removed 2026-08-01: it re-imported the SAME symbol
// already imported at the top of this file, from the same module. A genuine TS2300 that no gate had ever seen,
// because tsconfig included only `src`. Behaviourally benign — both bindings resolved to production `ruleRow`,
// so these assertions were exercising production all along.)

describe("ruleRow — a site-dst rule renders as a site, NEVER a broken 'deleted resource' (S8.1 #2)", () => {
  it("dst_kind='site' → site label, state ok, not broken", () => {
    const rule = {
      id: "r1",
      org_id: "o",
      src_kind: "group",
      src_group_id: "g1",
      dst_kind: "site",
      dst_site_id: "00000000-0000-0000-0000-0000000051e1",
      created_at: "x",
    } as any;
    const site = {
      id: "00000000-0000-0000-0000-0000000051e1",
      name: "hq-site",
    } as any;
    const row = ruleRow(
      rule,
      [{ id: "g1", name: "Admins" } as any],
      [],
      [],
      [site],
      { groupsLoaded: true, resourcesLoaded: true, sitesLoaded: true } as any,
    );
    expect(row.dst.state).toBe("ok");
    expect(row.dst.label).toBe("site hq-site"); // WF-8: resolved to the NAME, never a broken 'deleted resource'
    expect(row.broken).toBe(false);
  });
});

import { defaultDstKind, defaultSrcKind } from "../src/lib/policyview";

describe("defaultSrcKind / defaultDstKind — the modal opens on a kind that HAS options (re-review #4)", () => {
  it("an editing rule's kind always wins", () => {
    expect(
      defaultDstKind({
        editingKind: "site",
        hasGroups: true,
        hasResources: true,
        hasSites: true,
      }),
    ).toBe("site");
    expect(
      defaultSrcKind({ editingKind: "user", hasGroups: true, hasSites: true }),
    ).toBe("user");
  });
  it("groups present → groups is the primary default (both sides)", () => {
    expect(
      defaultDstKind({ hasGroups: true, hasResources: true, hasSites: true }),
    ).toBe("group");
    expect(defaultSrcKind({ hasGroups: true, hasSites: true })).toBe("group");
  });
  it("THE FIX: no groups + resources → dst defaults to resource, NOT the empty group select (the dead-end)", () => {
    expect(
      defaultDstKind({ hasGroups: false, hasResources: true, hasSites: true }),
    ).toBe("resource");
    expect(
      defaultDstKind({ hasGroups: false, hasResources: true, hasSites: false }),
    ).toBe("resource");
  });
  it("no groups, no resources, sites only → dst defaults to site (both sides site-first)", () => {
    expect(
      defaultDstKind({ hasGroups: false, hasResources: false, hasSites: true }),
    ).toBe("site");
    expect(defaultSrcKind({ hasGroups: false, hasSites: true })).toBe("site");
  });
});

import { disableConfirmText } from "../src/lib/policyview";

describe("disableConfirmText (F3)", () => {
  it("NAMES the rule's own subject→destination + the immediate effect, no generic/placeholder string", () => {
    const t = disableConfirmText("nykaa", "aws-server");
    expect(t).toContain("nykaa");
    expect(t).toContain("aws-server");
    expect(t).toMatch(/stops immediately/i);
    expect(t).not.toMatch(/\{|\}|placeholder|undefined/); // never a generic/templated leftover
  });
});

import { resPortsValid } from "../src/lib/policyview";

describe("resPortsValid (Feature 1 — resource port scope, client UX gate; server authoritative)", () => {
  it("both blank = all ports (valid)", () =>
    expect(resPortsValid("", "")).toBe(true));
  it("a high without a low is invalid", () =>
    expect(resPortsValid("", "80")).toBe(false));
  it("a low alone = a single port (valid)", () =>
    expect(resPortsValid("80", "")).toBe(true));
  it("low <= high range is valid", () =>
    expect(resPortsValid("8000", "8100")).toBe(true));
  it("high < low is invalid", () =>
    expect(resPortsValid("8100", "8000")).toBe(false));
  it("out of range 0 / 65536 invalid", () => {
    expect(resPortsValid("0", "")).toBe(false);
    expect(resPortsValid("1", "65536")).toBe(false);
  });
  it("non-integer invalid", () =>
    expect(resPortsValid("80.5", "")).toBe(false));
});

describe("grantControls — the withhold decision (M3)", () => {
  it("withholds every mutation on a managed grant, offers them otherwise", () => {
    expect(grantControls({ managedByOperator: true }).withheld).toBe(true);
    expect(grantControls({ managedByOperator: false }).withheld).toBe(false);
  });
});

// ── D3: THE THREE EMPTY STATES, BOTH DIRECTIONS ─────────────────────────────────────────────────────────
// The founder's framing is the assertion: "failed — retry" says WE DO NOT KNOW; "0 rules while enforcing"
// says WE KNOW, AND THE ANSWER IS EVERYTHING IS DENIED. Rendering the first as the second is
// reassuring-empty; rendering the second as the first is alarming about a state that is correct.
describe("rulesEmptyState — three claims about knowledge, never one message", () => {
  const ok = <T>(data: T) => ({ ok: true as const, data });
  const bad = { ok: false as const, error: "boom" };

  it("⛔ a FAILED rules read is `failed`, NEVER an empty-rules claim", () => {
    // The defect direction: a failed read leaves renderedCount at 0, which is exactly how a failure
    // disguises itself as an answer.
    expect(
      rulesEmptyState({
        rulesResult: bad,
        modeResult: ok("enforcing" as const),
        renderedCount: 0,
      }).kind,
    ).toBe("failed");
    expect(rulesEmptyCopy({ kind: "failed" }).text).not.toMatch(
      /no rules|0 rules|denied/i,
    );
    expect(rulesEmptyCopy({ kind: "failed" }).loud).toBe(false);
  });

  it("⛔ 0 rules WHILE ENFORCING is LOUD and says everything is denied", () => {
    // The opposite direction: this state is CORRECT and must not be softened into "couldn't load".
    const s = rulesEmptyState({
      rulesResult: ok(0),
      modeResult: ok("enforcing" as const),
      renderedCount: 0,
    });
    expect(s.kind).toBe("enforcing_empty");
    const c = rulesEmptyCopy(s);
    expect(c.loud).toBe(true);
    expect(c.text).toMatch(/denied by default/i);
    expect(c.text).not.toMatch(/could not|refresh/i);
  });

  it("⛔ 0 rules with mode OFF denies NOTHING — the old copy asserted the opposite", () => {
    // `rules.length === 0` used to print "under Enforcing, all device-to-device traffic is denied"
    // regardless of mode. The demo org's mode is `off`, so that sentence was false.
    const c = rulesEmptyCopy(
      rulesEmptyState({
        rulesResult: ok(0),
        modeResult: ok("off" as const),
        renderedCount: 0,
      }),
    );
    expect(c.loud).toBe(false);
    expect(c.text).toMatch(/nothing is being denied/i);
  });

  it("an UNKNOWN mode is `failed` — the consequence sentence depends on it", () => {
    expect(
      rulesEmptyState({ rulesResult: ok(0), modeResult: bad, renderedCount: 0 })
        .kind,
    ).toBe("failed");
    expect(
      rulesEmptyState({
        rulesResult: ok(0),
        modeResult: null,
        renderedCount: 0,
      }).kind,
    ).toBe("failed");
  });

  it("rows present → `rows`, and the three empty copies are all DISTINCT", () => {
    expect(
      rulesEmptyState({
        rulesResult: ok(3),
        modeResult: ok("enforcing" as const),
        renderedCount: 3,
      }).kind,
    ).toBe("rows");
    const texts = (["failed", "enforcing_empty", "off_empty"] as const).map(
      (k) => rulesEmptyCopy({ kind: k }).text,
    );
    expect(new Set(texts).size).toBe(3);
    for (const t of texts) expect(t.trim().length).toBeGreaterThan(0);
  });
});

describe("flowGraphState — the threshold is a variable, not a constant", () => {
  it("⛔ BOTH SIDES OF THE THRESHOLD, in one test — mechanism ⑨", () => {
    // A test that only ever sees the graph drawn cannot tell a threshold from a constant. Asserting the
    // boundary exactly is what makes it a threshold.
    expect(flowGraphState(FLOW_GRAPH_MAX_RULES).kind).toBe("draw");
    expect(flowGraphState(FLOW_GRAPH_MAX_RULES + 1).kind).toBe(
      "withheld_too_many",
    );
  });

  it("⛔ WITHHELD SAYS WHY, and names both the count and the limit", () => {
    const n = flowGraphNote(flowGraphState(FLOW_GRAPH_MAX_RULES + 1))!;
    expect(n).toMatch(/too many rules to draw legibly/i);
    expect(n).toContain(String(FLOW_GRAPH_MAX_RULES + 1));
    expect(n).toContain(String(FLOW_GRAPH_MAX_RULES));
    expect(n).toMatch(/table below is authoritative/i);
    // Drawn = no note. A note that always renders explains nothing.
    expect(flowGraphNote(flowGraphState(3))).toBeNull();
  });

  it("zero rules is WITHHELD-EMPTY, not withheld-too-many — different reasons, different copy", () => {
    expect(flowGraphState(0).kind).toBe("withheld_empty");
    expect(flowGraphNote(flowGraphState(0))).not.toMatch(/too many/i);
  });

  it("the threshold is DERIVED, so it is pinned — changing it silently must fail", () => {
    // The derivation lives beside the constant; this pins the value so a bump is a deliberate edit with a
    // test change, never a drive-by.
    expect(FLOW_GRAPH_MAX_RULES).toBe(24);
  });
});

describe("a deactivated per-user subject is a FACT, never a warning", () => {
  const mk = (status: string) =>
    [
      { user_id: "u9", name: "Grace Okafor", email: "g@x.io", status },
    ] as unknown as Member[];
  const refs = (status: string) =>
    ruleRow(
      {
        id: "r1",
        src_kind: "user",
        src_user_id: "u9",
        dst_kind: "group",
        dst_group_id: "g1",
      } as never,
      [{ id: "g1", name: "Eng" }] as never,
      [],
      mk(status),
      [],
      {
        membersLoaded: true,
        groupsLoaded: true,
        resourcesLoaded: true,
        sitesLoaded: true,
        servicesLoaded: true,
      } as never,
      [],
    );

  it("\u26d4 renders '(deactivated)' \u2014 and does NOT become a warn state", () => {
    // MEASURED before deciding: the compiler matches on DEVICE OWNERSHIP (`r.SrcUserID == d.UserID`,
    // compiler.go:397) with no user-status filter, and deactivation revokes sessions + sweeps CLI creds. The
    // grant therefore compiles to exactly what it says. OUTSIDE RANGES and VANISHED describe rules that
    // COMPILE TO NOTHING WHILE LOOKING LIVE; this is not one.
    //   A WARN KIND THAT FIRES ON A CORRECT RULE IS HOW THE REAL ONES STOP BEING READ.
    const j = JSON.stringify(refs("deactivated"));
    expect(j).toContain("Grace Okafor (deactivated)");
    // The row is NOT marked broken, because it is not broken.
    expect(j).not.toContain('"state":"deleted"');
    expect(j).not.toContain('"state":"unresolved"');
  });

  it("an ACTIVE subject renders the bare name \u2014 both values of the same condition", () => {
    const j = JSON.stringify(refs("active"));
    expect(j).toContain("Grace Okafor");
    expect(j).not.toContain("deactivated");
  });
});

describe("flowLayout — the cap and the ordering, both ours to design", () => {
  const e = (id: string, src: string, dst: string, temp = false) => ({
    id,
    src,
    dst,
    temp,
    srcKind: "group" as const,
    dstKind: "resource" as const,
  });

  it("⛔ THE CAP AT BOTH SIDES — 4 fits whole, 5 is capped and the remainder is COUNTED", () => {
    const four = flowLayout(
      ["a", "b", "c", "d"].map((x) => e(x, "s" + x, "d" + x)),
    );
    expect(four.srcs).toHaveLength(4);
    expect(four.hidden).toBe(0);
    const five = flowLayout(
      ["a", "b", "c", "d", "z"].map((x) => e(x, "s" + x, "d" + x)),
    );
    expect(five.srcs).toHaveLength(FLOW_COLUMN_CAP);
    expect(five.hidden).toBe(1); // never silently dropped
  });

  it("⛔ chosen by EDGE DEGREE, not insertion order", () => {
    // `hub` appears last but carries 3 edges; a degree cap must keep it and drop a 1-edge source.
    const l = flowLayout(
      [
        e("1", "a", "x"),
        e("2", "b", "x"),
        e("3", "c", "x"),
        e("4", "d", "x"),
        e("5", "hub", "x"),
        e("6", "hub", "y"),
        e("7", "hub", "z"),
      ],
      2,
    );
    expect(l.srcs[0].label).toBe("hub");
  });

  it("⛔ THE PROPERTY, NOT THE PROXY: crossings go DOWN versus insertion order, counted", () => {
    // "the ordering function ran" is a proxy. "crossings went down" is the property — the same distinction
    // the coverage threshold turns on. MEASURED on the live 11-rule fixture: insertion 8 -> ordered 2.
    //
    // ⛔ AND IT DOES NOT REACH ZERO, WHICH IS HONEST. A bipartite graph with genuinely tangled edges cannot;
    // the wireframe reaches zero because a human chose five edges that do not cross. Asserting `=== 0` here
    // would pin an outcome the algorithm cannot guarantee and would fail on the next fixture row.
    const R = [
      ["Engineering", "Internal Gitlab"],
      ["DevOps", "Contractors"],
      ["192.168.99.0/24", "Staging Database"],
      ["Engineering", "removed service 0"],
      ["Grace Okafor", "Staging Database"],
      ["site eu-lan", "site ap-lan"],
      ["Contractors", "EU LAN Services"],
      ["DevOps", "Internal Gitlab"],
      ["Demo Member", "Engineering"],
      ["Contractors", "Contractors"],
      ["Engineering", "Staging Database"],
    ].map(([s2, d], i) => ({
      id: String(i),
      src: s2,
      dst: d,
      temp: false,
      srcKind: "group" as const,
      dstKind: "resource" as const,
    }));
    const ordered = flowLayout(R);
    const insertion = {
      ...ordered,
      srcs: [...new Set(R.map((r) => r.src))]
        .filter((x) => ordered.srcs.some((n) => n.label === x))
        .map((label) => ({ label, kind: "group" as const })),
      dsts: [...new Set(R.map((r) => r.dst))]
        .filter((x) => ordered.dsts.some((n) => n.label === x))
        .map((label) => ({ label, kind: "resource" as const })),
    };
    const before = flowCrossings(insertion),
      after = flowCrossings(ordered);
    expect(after).toBeLessThan(before); // the property
    expect(before).toBeGreaterThan(0); // and the input really does tangle, or the claim is vacuous
    expect(after).toBeLessThanOrEqual(2); // pinned at the measured value; a regression is a red
  });

  it("⛔ A KNOWN-CROSSING INPUT COMES OUT ORDERED — the cap alone does not fix the tangle", () => {
    // Deliberately reversed: insertion order puts every destination opposite its source.
    const edges = [
      e("1", "s1", "d4"),
      e("2", "s2", "d3"),
      e("3", "s3", "d2"),
      e("4", "s4", "d1"),
    ];
    const ordered = flowLayout(edges);
    expect(flowCrossings(ordered)).toBe(0);
    // And prove the metric is not vacuous: the UNORDERED arrangement really does cross.
    const unordered = {
      ...ordered,
      dsts: ["d1", "d2", "d3", "d4"].map((l) => ({
        label: l,
        kind: "resource" as const,
      })),
    };
    expect(flowCrossings(unordered)).toBeGreaterThan(0);
  });

  it("the handoff's own five edges lay out with ZERO crossings, as the design shows", () => {
    const l = flowLayout([
      e("1", "engineering", "gitlab.internal"),
      e("2", "dana@acme.io", "eu-lan", true),
      e("3", "us-lan", "eu-lan"),
      e("4", "oncall-grp", "engineering"),
      e("5", "oncall-grp", "db-prod.internal", true),
    ]);
    expect(flowCrossings(l)).toBe(0);
  });
});

describe("flowGlyph / flowTag — every arm of BOTH unions, exhaustively", () => {
  // ⛔ THE DEFECT THIS REPLACES: the kind was guessed by matching the label against members, and
  // `label.startsWith(m.name)` is ALWAYS TRUE when a member has an empty name — which `users.name`
  // (NOT NULL DEFAULT '') produces for 144 rows. Every resource rendered as USER.
  //   A WRONG TYPE TAG IS NOT STYLING. IT IS A FALSE CLAIM ABOUT WHAT A RULE POINTS AT.
  const SRC = ["group", "user", "site", "cidr"] as const; // policy_rules_src_kind_check
  const DST = ["resource", "group", "site", "k8s_service"] as const; // policy_rules_dst_kind_check

  it("every src_kind and dst_kind the CHECK constraints allow has a DISTINCT glyph", () => {
    const all = [...new Set([...SRC, ...DST])];
    const glyphs = all.map(flowGlyph);
    expect(new Set(glyphs).size).toBe(all.length); // no two kinds share a letter
    for (const g of glyphs) expect(g).toMatch(/^[A-Z]$/);
  });

  it("⛔ a RESOURCE is never labelled USER — the exact defect, both arms", () => {
    expect(flowGlyph("resource")).toBe("R");
    expect(flowTag("resource")).toBe("RESOURCE");
    expect(flowGlyph("user")).toBe("U");
    expect(flowTag("user")).toBe("USER");
    expect(flowTag("resource")).not.toBe(flowTag("user"));
  });

  it("k8s_service reads as two words, not a snake_case identifier", () => {
    expect(flowTag("k8s_service")).toBe("K8S SERVICE");
    expect(flowTag("k8s_service")).not.toContain("_");
  });

  it("the layout carries each node's kind THROUGH, never re-derives it", () => {
    const l = flowLayout([
      {
        id: "1",
        src: "eng",
        dst: "gitlab",
        temp: false,
        srcKind: "group",
        dstKind: "resource",
      },
      {
        id: "2",
        src: "10.0.0.0/8",
        dst: "hq",
        temp: false,
        srcKind: "cidr",
        dstKind: "site",
      },
    ]);
    expect(l.srcs.map((n) => n.kind).sort()).toEqual(["cidr", "group"]);
    expect(l.dsts.map((n) => n.kind).sort()).toEqual(["resource", "site"]);
  });
});

describe("the SECOND threshold is COVERAGE, not count", () => {
  // ⛔ "At what rule count does the panel stop saying anything?" is the WRONG QUESTION. Degree-ranking's
  // meaningfulness depends on the DEGREE DISTRIBUTION, not on N: 900 rules hub-and-spoke through 4 gateways
  // are perfectly summarised by top-4; 900 distinct pairs are not summarised by anything. A fixed second
  // COUNT would withhold from the first org for a property it does not have.
  it("⛔ BOTH SIDES OF THE COVERAGE BOUNDARY, in one test", () => {
    expect(FLOW_MIN_COVERAGE).toBe(0.5); // pinned: a bump is a deliberate edit
    // exactly half is still drawn; below half is withheld.
    expect(flowGraphState(10, 5).kind).toBe("draw");
    expect(flowGraphState(10, 4).kind).toBe("withheld_unrepresentative");
  });

  it("a HUB-AND-SPOKE set stays drawn no matter how many rules — the whole argument", () => {
    // 20 rules, all through one source: top-4 covers everything, so nothing is withheld.
    const edges = Array.from({ length: 20 }, (_, i) => ({
      id: String(i),
      src: "hub",
      dst: "d" + (i % 3),
      temp: false,
      srcKind: "group" as const,
      dstKind: "resource" as const,
    }));
    const l = flowLayout(edges);
    expect(flowGraphState(edges.length, l.shown.length).kind).toBe("draw");
  });

  it("a FULLY-DISTINCT set of the same size is withheld — same N, opposite verdict", () => {
    // Same 20 rules, every pair distinct: top-4 x top-4 covers a minority.
    const edges = Array.from({ length: 20 }, (_, i) => ({
      id: String(i),
      src: "s" + i,
      dst: "d" + i,
      temp: false,
      srcKind: "group" as const,
      dstKind: "resource" as const,
    }));
    const l = flowLayout(edges);
    expect(flowGraphState(edges.length, l.shown.length).kind).toBe(
      "withheld_unrepresentative",
    );
  });

  it("the withheld note names the drawn count AND the total — never just disappears", () => {
    const n = flowGraphNote(flowGraphState(20, 8))!;
    expect(n).toContain("8");
    expect(n).toContain("20");
    expect(n).toMatch(/table below is authoritative/);
  });

  it("coverage is only judged when the caller supplies what was drawn", () => {
    // One-arg calls keep the old behaviour, so no existing caller changes meaning.
    expect(flowGraphState(9).kind).toBe("draw");
  });
});

describe("srcGroupEmptyWarn — the fourth warn kind, admitted by the test that refused the third", () => {
  it("⛔ BOTH DIRECTIONS: an empty source group warns, a populated one does NOT", () => {
    // A warn kind that only ever fires cannot be told from a constant.
    expect(srcGroupEmptyWarn(0)).toBe("empty");
    expect(srcGroupEmptyWarn(3)).toBe("populated");
    expect(srcGroupEmptyBadge(srcGroupEmptyWarn(0))).toBe("SOURCE GROUP EMPTY");
    expect(srcGroupEmptyBadge(srcGroupEmptyWarn(3))).toBeNull();
  });

  it("⛔ a FAILED or UNFETCHED count is `unknown` and NEVER warns — 'could not check' is not 'empty'", () => {
    // The third loadOne arm, one level over. Warning here would call a WORKING rule broken.
    expect(srcGroupEmptyWarn(null)).toBe("unknown");
    expect(srcGroupEmptyWarn(undefined)).toBe("unknown");
    expect(srcGroupEmptyBadge("unknown")).toBeNull();
    expect(srcGroupEmptyExplain("unknown")).toBeNull();
  });

  it("it derives from the COUNT, not from group existence", () => {
    // 0 is a fetched answer; null is the absence of one. They must not collapse.
    expect(srcGroupEmptyWarn(0)).not.toBe(srcGroupEmptyWarn(null));
  });

  it("the explanation says what compiles and what to do — never just 'empty'", () => {
    const t = srcGroupEmptyExplain("empty")!;
    expect(t).toMatch(/matches no device/i);
    expect(t).toMatch(/grants nothing/i);
    expect(t).toMatch(/add members|delete the rule/i);
  });
});

describe("cascadeConfirmCopy — names the risk, never a count we do not own", () => {
  it("⛔ states that rules are DELETED, and never asserts a number", () => {
    const c = cascadeConfirmCopy("group", "Interns");
    expect(c.body).toMatch(/deletes every access rule/i);
    expect(c.body).toMatch(/cannot be undone/i);
    // NO cascade-preview endpoint exists; a client-computed count would be a second source of truth about
    // what the server is about to do.
    expect(c.body).not.toMatch(/\d+ rule/);
  });

  it("says rules VANISH rather than becoming reviewable-broken — the measured behaviour", () => {
    // ON DELETE CASCADE: the rows go. An operator who expects orphaned-but-visible rules is wrong.
    expect(cascadeConfirmCopy("group", "X").body).toMatch(/do not remain/i);
  });

  it("group and resource differ in the ROLE they name", () => {
    expect(cascadeConfirmCopy("group", "X").body).toMatch(
      /source or destination/,
    );
    expect(cascadeConfirmCopy("resource", "X").body).toMatch(
      /rule destination/,
    );
  });

  it("⛔ the typed guard requires an EXACT name — both directions", () => {
    expect(cascadeConfirmSatisfied("Interns", "Interns")).toBe(true);
    expect(cascadeConfirmSatisfied("interns", "Interns")).toBe(false);
    expect(cascadeConfirmSatisfied("Intern", "Interns")).toBe(false);
    expect(cascadeConfirmSatisfied("", "Interns")).toBe(false);
    // a trailing space is a typo, not a refusal
    expect(cascadeConfirmSatisfied("  Interns  ", "Interns")).toBe(true);
  });
});

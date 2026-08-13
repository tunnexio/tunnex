import { describe, expect, it } from "vitest";
import {
  groupGateways,
  gatewayFilterCounts,
  applyGatewayFilter,
  toGatewayRow,
  groupNotes,
} from "../src/lib/gatewaysview";
import type { Node } from "../src/lib/api";

const node = (p: Partial<Node> & { id: string; name: string }): Node =>
  ({
    status: "active",
    agent_version: "0.3.0",
    enrolled_at: "2026-01-01T00:00:00Z",
    ...p,
  }) as Node;

describe("⛔ DEGRADED FIRST — the ACTING surface leads with what is wrong", () => {
  it("orders the groups degraded, healthy, revoked", () => {
    const g = groupGateways([
      node({ id: "a", name: "ok-1" }),
      node({ id: "b", name: "bad-1", policy_degraded: true }),
      node({ id: "c", name: "gone", status: "revoked" }),
    ]);
    expect(g.map((x) => x.key)).toEqual(["degraded", "healthy", "revoked"]);
    expect(g[0]!.rows.map((r) => r.name)).toEqual(["bad-1"]);
    expect(g[1]!.rows.map((r) => r.name)).toEqual(["ok-1"]);
    expect(g[2]!.rows.map((r) => r.name)).toEqual(["gone"]);
  });
});

describe("⛔ OVPN IS A DIFFERENT AXIS FROM POLICY HEALTH", () => {
  it("an OVPN fault puts a policy-clean gateway in DEGRADED, not healthy", () => {
    // The defect this pins: reading only `health` here would file an opted-in gateway that is NOT SERVING
    // into the healthy group, because its OTHER axis happens to be fine. S9.1 4d exists precisely so that
    // gateway says why instead of reading green.
    const g = groupGateways([
      node({ id: "a", name: "ovpn-broken", ovpn_health: "ovpn_certs_absent" }),
    ]);
    expect(g[0]!.key).toBe("degraded");
    expect(g[0]!.rows.map((r) => r.name)).toEqual(["ovpn-broken"]);
    expect(g[1]!.rows).toEqual([]);
  });

  it("and a genuinely clean gateway IS healthy — the other side of the same question", () => {
    // Mechanism 9: if the degraded case were the only one observed, the grouping could be a constant.
    const g = groupGateways([node({ id: "a", name: "fine" })]);
    expect(g[0]!.rows).toEqual([]);
    expect(g[1]!.rows.map((r) => r.name)).toEqual(["fine"]);
  });

  it("moves a stale, policy-clean gateway into degraded", () => {
    const now = Date.parse("2026-08-10T00:00:00Z");
    const g = groupGateways(
      [
        node({
          id: "a",
          name: "stopped",
          last_seen_at: new Date(now - 90_001).toISOString(),
        }),
      ],
      undefined,
      now,
    );
    expect(g[0]!.rows.map((r) => r.name)).toEqual(["stopped"]);
    expect(g[0]!.rows[0]!.health).toEqual({ label: "offline", tone: "danger" });
    expect(g[1]!.rows).toEqual([]);
  });
});

describe("⛔ A REVOKED GATEWAY CARRIES NO HEALTH BADGE (WF-S11-10)", () => {
  it("suppresses the badge even when the node still reports degraded", () => {
    // `revoked` IS the state. A degradation badge beside it has the row asserting two things at once, and
    // prescribing a remedy for a gateway an operator deliberately retired.
    const r = toGatewayRow(
      node({
        id: "a",
        name: "gone",
        status: "revoked",
        policy_degraded: true,
        policy_degraded_kind: "site_link_down",
        ovpn_health: "ovpn_certs_absent",
        is_site_hub: true,
      }),
    );
    expect(r.health).toBeNull();
    expect(r.ovpnHealth).toBeNull();
    expect(r.isHub).toBe(true);
  });

  it("and an ACTIVE node with the same fields DOES carry them", () => {
    const r = toGatewayRow(
      node({
        id: "a",
        name: "live",
        policy_degraded: true,
        policy_degraded_kind: "site_link_down",
        ovpn_health: "ovpn_certs_absent",
      }),
    );
    expect(r.health).not.toBeNull();
    expect(r.ovpnHealth).toBe("ovpn_certs_absent");
  });
});

describe("gateway egress mode is carried to the rendered row", () => {
  it("preserves dual-stack capability for the Gateways page", () => {
    expect(
      toGatewayRow(
        node({ id: "a", name: "dual", egress_mode: "dual_stack" }),
      ).egressMode,
    ).toBe("dual_stack");
  });

  it("keeps an unreported capability explicit as checking", () => {
    expect(toGatewayRow(node({ id: "a", name: "new" })).egressMode).toBeNull();
  });
});

describe("⛔ THE CHIP COUNTS AND THE GROUPING ARE ONE DERIVATION", () => {
  it("healthy + degraded + revoked === all", () => {
    const nodes = [
      node({ id: "a", name: "ok-1" }),
      node({ id: "b", name: "ok-2" }),
      node({ id: "c", name: "bad", policy_degraded: true }),
      node({ id: "d", name: "gone", status: "revoked" }),
    ];
    const c = gatewayFilterCounts(nodes);
    expect(c).toEqual({ all: 4, healthy: 2, degraded: 1, revoked: 1 });
    // The arithmetic the screen has to explain: `all` includes revoked, the other two do not.
    expect(c.healthy + c.degraded + c.revoked).toBe(c.all);
  });

  it("a filter chip narrows to exactly its group", () => {
    const nodes = [
      node({ id: "a", name: "ok" }),
      node({ id: "b", name: "bad", policy_degraded: true }),
    ];
    const g = groupGateways(nodes);
    expect(
      applyGatewayFilter(g, "degraded").flatMap((x) =>
        x.rows.map((r) => r.name),
      ),
    ).toEqual(["bad"]);
    expect(
      applyGatewayFilter(g, "healthy").flatMap((x) =>
        x.rows.map((r) => r.name),
      ),
    ).toEqual(["ok"]);
    // ⛔ "ALL" MEANS EVERY GROUP THAT HAS ROWS, NOT EVERY GROUP. An empty group under All is a heading and
    // a sentence saying nothing is here, costing a screen of scrolling between the groups that do have
    // rows — and the CHIP already reports "Healthy (0)". Rendering a card to repeat the count is the answer
    // twice, the second time in the space where content should be.
    expect(applyGatewayFilter(g, "all").map((x) => x.key)).toEqual([
      "degraded",
      "healthy",
    ]);

    // ⚠ AND THE EXCEPTION, WHICH IS WHY THIS IS NOT A ONE-LINE FILTER: an EXPLICITLY SELECTED group renders
    // even when empty. Its emptiness is the answer to the question the operator just asked, and a chosen
    // filter that produces a blank page is indistinguishable from a page that failed to load.
    //
    // ⚠ `revoked` is deliberately NOT a value of GatewayFilter — only All / Healthy / Needs attention are
    // selectable — so the exception is exercised through `healthy` on a fleet with none.
    const noneHealthy = groupGateways([
      node({ id: "b", name: "bad", policy_degraded: true }),
    ]);
    expect(
      applyGatewayFilter(noneHealthy, "healthy").map((x) => x.key),
    ).toEqual(["healthy"]);
    expect(applyGatewayFilter(noneHealthy, "healthy")[0].rows).toEqual([]);
  });
});

describe("⛔ THE NOTES RENDER PER KIND, NOT PER ROW", () => {
  const n = (id: string, name: string, kind?: string): Node =>
    ({
      id,
      name,
      status: "active",
      agent_version: "0.3.0",
      enrolled_at: "2026-01-01T00:00:00Z",
      ...(kind ? { policy_degraded: true, policy_degraded_kind: kind } : {}),
    }) as Node;

  it("four rows of ONE kind produce ONE note, not four", () => {
    // The whole reason the note moved to the group header. Four `site link down` gateways is one org-level
    // fact (see the registered finding), and four copies of its sentence is the per-row repetition the
    // placement test forbids.
    const g = groupGateways([
      n("a", "gw1", "site_link_down"),
      n("b", "gw2", "site_link_down"),
      n("c", "gw3", "site_link_down"),
      n("d", "gw4", "site_link_down"),
    ]);
    const notes = groupNotes(g[0]!.rows);
    expect(notes).toHaveLength(1);
    expect(notes[0]).toMatch(/never shown as green/);
  });

  it("a MIXED group returns one note PER KIND — never one note for the group", () => {
    // Collapsing a mixed group to a single note would attach one kind's explanation to another kind's row.
    const g = groupGateways([
      n("a", "gw1", "site_link_down"),
      n("b", "gw2", "apply_failing"),
    ]);
    expect(groupNotes(g[0]!.rows)).toHaveLength(2);
  });

  it("a healthy group has NO notes — there is nothing to explain", () => {
    // Mechanism 9: the empty side observed, so the function is not just "always returns something".
    const g = groupGateways([n("a", "gw1")]);
    expect(groupNotes(g[1]!.rows)).toEqual([]);
  });
});

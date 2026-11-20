import { describe, expect, it } from "vitest";
import { allRanges, cloudVpnBySite, gatewayRoles, networkStatus, networkSummary, type SiteCard } from "../src/lib/sitesview";
import { MAP_DIAGRAM_MAX, networkMapLayout } from "../src/lib/networkmapview";

// SSI-13 — the Networks list and the map read the same pure projections of what the page already loads.
const NOW = Date.parse("2026-11-20T12:00:00Z");
const gw = (id: string, name = id, extra: Record<string, unknown> = {}) => ({ id, name, status: "active", isHub: false, health: null, lastSeenAt: "2026-11-20T11:59:50Z", ...extra }) as never;
const card = (id: string, gateways: unknown[], subnets: Array<[string, "approved" | "pending"]> = [["10.0.0.0/24", "approved"]]): SiteCard =>
  ({ id, name: id, gateways, subnets: subnets.map(([cidr, status], i) => ({ id: `${id}-${i}`, cidr, status })), lanEgress: "preserve_source" }) as never;
const hub = (...members: Array<[string, "primary" | "standby", "fresh" | "stale" | "unobserved"]>) =>
  ({ members: members.map(([node_id, role, liveness]) => ({ node_id, role, liveness })) }) as never;

describe("gatewayRoles", () => {
  it("reads the role as served and lets the controller's verdict override it", () => {
    const roles = gatewayRoles(hub(["a", "primary", "fresh"], ["b", "standby", "fresh"], ["c", "standby", "stale"]));
    expect([...roles]).toEqual([["a", "primary"], ["b", "standby"], ["c", "not_answering"]]);
    expect(gatewayRoles(null).size).toBe(0);
  });
});

describe("networkStatus", () => {
  const roles = gatewayRoles(hub(["p", "primary", "fresh"], ["s", "standby", "fresh"]));
  it("every gateway reporting is 'Gateways online': what was measured, never 'Healthy' or 'Up'", () => {
    expect(networkStatus(card("n", [gw("p"), gw("s")]), roles, NOW)).toEqual({ tone: "ok", label: "Gateways online", detail: "Failover ready", attention: false });
    expect(networkStatus(card("n", [gw("x")]), roles, NOW).detail).toBe("One gateway, no standby");
  });
  it("two gateways that are not both failover candidates are not called a pair", () => {
    expect(networkStatus(card("n", [gw("p"), gw("x")]), roles, NOW).detail).toBe("Second gateway is not a failover candidate");
  });
  it("a gateway that stopped reporting is offline, by the same clock as the Gateways page", () => {
    const old = { lastSeenAt: "2026-11-20T11:50:00Z" };
    expect(networkStatus(card("n", [gw("x", "gw-x", old)]), roles, NOW)).toMatchObject({ tone: "danger", label: "Offline", attention: true });
    expect(networkStatus(card("n", [gw("x", "gw-x", old), gw("y")]), roles, NOW)).toMatchObject({ tone: "warn", label: "Gateway offline", detail: "gw-x has not reported recently" });
    expect(networkStatus(card("n", [gw("x", "gw-x", { lastSeenAt: null })]), roles, NOW).label).toBe("Offline");
  });
  it("no gateway needs one", () => {
    expect(networkStatus(card("n", []), roles, NOW)).toMatchObject({ label: "Needs a gateway", attention: true });
  });
  it("a silent gateway with another answering is 'Running on standby'; all silent is 'Not answering'", () => {
    const failed = gatewayRoles(hub(["s", "primary", "fresh"], ["p", "standby", "stale"]));
    expect(networkStatus(card("n", [gw("p", "gw-1"), gw("s", "gw-2")]), failed, NOW)).toMatchObject({ tone: "warn", label: "Running on standby", detail: "gw-1 not answering", attention: true });
    const dead = gatewayRoles(hub(["p", "primary", "stale"]));
    expect(networkStatus(card("n", [gw("p")]), dead, NOW)).toMatchObject({ tone: "danger", label: "Not answering" });
  });
  it("a raised health badge is shown as it is", () => {
    expect(networkStatus(card("n", [gw("x", "x", { health: { label: "site link down", tone: "danger" } })]), new Map(), NOW)).toMatchObject({ tone: "danger", label: "site link down", attention: true });
  });
});

describe("networkSummary, cloudVpnBySite, allRanges", () => {
  const roles = gatewayRoles(hub(["p", "primary", "fresh"], ["s", "standby", "fresh"]));
  const cards = [card("a", [gw("p"), gw("s")]), card("b", [gw("x")], [["10.1.0.0/24", "pending"], ["10.2.0.0/24", "approved"]]), card("c", [], [])];
  it("counts what the list shows", () => {
    expect(networkSummary(cards, roles, NOW)).toEqual({ networks: 3, withStandby: 1, pendingRanges: 1, attention: 1 });
  });
  it("groups cloud VPNs under their network, drops removed ones, and names the configuration state", () => {
    const by = cloudVpnBySite([
      { id: "1", name: "to-aws", site_id: "a", desired_intent: "enabled", application_state: "applied" },
      { id: "2", name: "to-azure", site_id: "a", desired_intent: "disabled", application_state: "applied" },
      { id: "3", name: "gone", site_id: "a", desired_intent: "deleted", application_state: "applied" },
      { id: "4", name: "orphan", site_id: null, desired_intent: "enabled", application_state: "pending" },
      { id: "5", name: "new", site_id: "b", desired_intent: "enabled", application_state: "pending" },
    ]);
    expect(by.get("a")).toEqual([{ id: "1", name: "to-aws", state: "applied" }, { id: "2", name: "to-azure", state: "off" }]);
    expect(by.get("b")).toEqual([{ id: "5", name: "new", state: "applying" }]);
  });
  it("lists every range, waiting ones first", () => {
    expect(allRanges(cards).map((row) => `${row.network} ${row.cidr} ${row.status}`)).toEqual(["b 10.1.0.0/24 pending", "a 10.0.0.0/24 approved", "b 10.2.0.0/24 approved"]);
  });
});

describe("networkMapLayout", () => {
  const roles = gatewayRoles(hub(["p", "primary", "fresh"], ["s", "standby", "fresh"]));
  it("the network holding the acting primary is the hub; every other network with a gateway links to it", () => {
    const layout = networkMapLayout([card("aws", [gw("p"), gw("s")]), card("gcp", [gw("g")]), card("empty", [])], roles, new Map());
    expect(layout.mode).toBe("diagram");
    expect(layout.hubId).toBe("aws");
    expect(layout.links).toEqual([{ from: "aws", to: "gcp", tone: "linked" }]); // a network with no gateway has NO link, not a red one
    expect(layout.boxes.get("gcp")!.x).toBeGreaterThan(layout.boxes.get("aws")!.x);
    expect(layout.networks[0].id).toBe("empty"); // problems first
  });
  it("gateways are inside their network with their role, and a cloud VPN adds height to its box", () => {
    const vpns = new Map([["aws", [{ id: "1", name: "to-azure", state: "applied" }]]]);
    const withVpn = networkMapLayout([card("aws", [gw("p"), gw("s")]), card("gcp", [gw("g")])], roles, vpns);
    const without = networkMapLayout([card("aws", [gw("p"), gw("s")]), card("gcp", [gw("g")])], roles, new Map());
    expect(withVpn.networks.find((n) => n.id === "aws")!.gateways.map((g) => g.role)).toEqual(["primary", "standby"]);
    expect(withVpn.boxes.get("aws")!.height).toBeGreaterThan(without.boxes.get("aws")!.height);
  });
  it("more than four other networks go on both sides of the hub, and no two boxes overlap", () => {
    const cards = [card("hub", [gw("p")]), ...Array.from({ length: 7 }, (_, i) => card(`n${i}`, [gw(`g${i}`)]))];
    const layout = networkMapLayout(cards, roles, new Map());
    const boxes = [...layout.boxes.values()];
    expect(boxes.some((b) => b.x < layout.boxes.get("hub")!.x)).toBe(true);
    expect(boxes.some((b) => b.x > layout.boxes.get("hub")!.x)).toBe(true);
    for (let i = 0; i < boxes.length; i++) for (let j = i + 1; j < boxes.length; j++) {
      const a = boxes[i]!, b = boxes[j]!;
      expect(a.x + a.width <= b.x || b.x + b.width <= a.x || a.y + a.height <= b.y || b.y + b.height <= a.y).toBe(true);
    }
  });
  it("a failed hub turns its links down; a network on its standby is degraded", () => {
    const failed = gatewayRoles(hub(["p", "primary", "stale"]));
    expect(networkMapLayout([card("aws", [gw("p")]), card("gcp", [gw("g")])], failed, new Map()).links[0].tone).toBe("down");
  });
  it("above the diagram limit the map becomes a grid: no boxes, no links, problems first", () => {
    const many = Array.from({ length: MAP_DIAGRAM_MAX + 1 }, (_, i) => card(`n${String(i).padStart(2, "0")}`, i === 5 ? [] : [gw(`g${i}`)]));
    const layout = networkMapLayout(many, roles, new Map());
    expect(layout.mode).toBe("grid");
    expect(layout.boxes.size).toBe(0);
    expect(layout.links).toEqual([]);
    expect(layout.networks[0].id).toBe("n05");
  });
  it("no networks is empty, not a blank diagram", () => {
    expect(networkMapLayout([], roles, new Map()).mode).toBe("empty");
  });
});

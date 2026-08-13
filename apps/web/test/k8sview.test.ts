import { describe, it, expect } from "vitest";
import {
  k8sGate,
  portLabel,
  assembleClusters,
  serviceFqdnById,
  objectControls,
} from "../src/lib/k8sview";
import type { K8sCluster, K8sService } from "../src/lib/api";

const CL = (id: string, name: string): K8sCluster =>
  ({
    id,
    site_id: "s1",
    name,
    vip_range: "100.64.0.0/16",
    service_cidr: "10.96.0.0/12",
    dns_zone: "k8s.acme.com",
    dns_vip: "100.64.0.2",
  }) as K8sCluster;
const SVC = (
  id: string,
  cluster: string,
  name: string,
  fqdn: string,
): K8sService =>
  ({
    id,
    cluster_id: cluster,
    name,
    namespace: "prod",
    protocol: "tcp",
    vip: "100.64.0.5",
    fqdn,
  }) as K8sService;

describe("k8sGate — CORE (no edition bit): org:view reads, k8s:manage + verified email mutates", () => {
  it("a member reads but cannot manage", () => {
    const g = k8sGate({ role: "member", emailVerified: true });
    expect(g.canView).toBe(true);
    expect(g.canManage).toBe(false);
  });
  it("an admin with a verified email manages", () => {
    const g = k8sGate({ role: "admin", emailVerified: true });
    expect(g.canView).toBe(true);
    expect(g.canManage).toBe(true);
  });
  it("an unverified admin cannot manage (mirrors the server mutating gate)", () => {
    expect(k8sGate({ role: "admin", emailVerified: false }).canManage).toBe(
      false,
    );
  });
  it("no role → neither (fail-closed)", () => {
    const g = k8sGate({ role: undefined, emailVerified: true });
    expect(g.canView).toBe(false);
    expect(g.canManage).toBe(false);
  });
});

describe("portLabel — the wire port_low/port_high projection", () => {
  it("both null/absent = any", () => {
    expect(portLabel(null, null)).toBe("any");
    expect(portLabel(undefined, undefined)).toBe("any");
  });
  it("single port (low only, or low==high)", () => {
    expect(portLabel(80, null)).toBe("80");
    expect(portLabel(80, 80)).toBe("80");
  });
  it("a range renders low–high", () => {
    expect(portLabel(8000, 8100)).toBe("8000–8100");
  });
});

describe("assembleClusters — group Services under their cluster (the wire-truth join)", () => {
  it("services attach to their own cluster; the FQDN is READ, never constructed", () => {
    const clusters = [CL("c1", "prod"), CL("c2", "staging")];
    const services = [
      SVC("k1", "c1", "api", "api.prod.svc.prod.k8s.acme.com"),
      SVC("k2", "c2", "web", "web.prod.svc.staging.k8s.acme.com"),
    ];
    const cards = assembleClusters(clusters, services);
    expect(cards).toHaveLength(2);
    expect(cards[0].services).toHaveLength(1);
    expect(cards[0].services[0].fqdn).toBe("api.prod.svc.prod.k8s.acme.com");
    expect(cards[0].dnsVip).toBe("100.64.0.2");
    // c2 got only its own Service (no cross-cluster bleed).
    expect(cards[1].services.map((s) => s.id)).toEqual(["k2"]);
  });
  it("a cluster with no exposed Services renders an empty list, not an error", () => {
    expect(assembleClusters([CL("c1", "prod")], [])[0].services).toEqual([]);
  });
});

describe("serviceFqdnById — the grant-picker label source", () => {
  const svc = [SVC("k1", "c1", "api", "api.prod.svc.prod.k8s.acme.com")];
  it("resolves a live id to its fqdn", () => {
    expect(serviceFqdnById(svc, "k1")).toBe("api.prod.svc.prod.k8s.acme.com");
  });
  it("an absent id resolves to null (the vanished case)", () => {
    expect(serviceFqdnById(svc, "gone")).toBeNull();
  });
});

describe("managed-by-operator ownership surface (S10.2 D2 cond 1)", () => {
  it("carries managed_by_operator from the wire onto clusters and services", () => {
    const cl = { ...CL("c1", "prod"), managed_by_operator: true } as K8sCluster;
    const managed = {
      ...SVC("k1", "c1", "api", "api.prod.svc.prod.k8s.acme.com"),
      managed_by_operator: true,
    } as K8sService;
    const human = {
      ...SVC("k2", "c1", "web", "web.prod.svc.prod.k8s.acme.com"),
      managed_by_operator: false,
    } as K8sService;
    const cards = assembleClusters([cl], [managed, human]);
    expect(cards[0].managedByOperator).toBe(true);
    expect(
      cards[0].services.find((s) => s.id === "k1")!.managedByOperator,
    ).toBe(true);
    expect(
      cards[0].services.find((s) => s.id === "k2")!.managedByOperator,
    ).toBe(false);
  });
});

describe("objectControls — the withhold decision (M3)", () => {
  it("withholds the destructive control on a managed object, offers it otherwise", () => {
    expect(objectControls(true).withheld).toBe(true);
    expect(objectControls(false).withheld).toBe(false);
  });
});

// ── S14.8 SECTION PASS ──────────────────────────────────────────────────────────────────────────────────

import {
  clusterReachability,
  serviceRowClass,
  statTiles,
} from "../src/lib/k8sview";

const card = (name: string, services: number, siteId = "s1") =>
  ({
    id: name,
    siteId,
    name,
    vipRange: "10.50.0.0/24",
    serviceCidr: "10.96.0.0/16",
    dnsZone: "k8s.demo.local",
    dnsVip: "10.50.0.2",
    managedByOperator: false,
    services: Array.from({ length: services }, (_, i) => ({
      id: `${name}-${i}`,
      name: `svc${i}`,
      namespace: "default",
      protocol: "tcp" as const,
      ports: "80",
      vip: `10.50.0.${i + 3}`,
      fqdn: `svc${i}.default.svc.${name}.k8s.demo.local`,
      managedByOperator: false,
    })),
  }) as ReturnType<typeof statTiles> extends never ? never : any;

describe("statTiles", () => {
  it("is THREE tiles — the operator version is cut because it is not served", () => {
    const t = statTiles([card("a", 2), card("b", 1)], 1);
    expect(t).toHaveLength(3);
    expect(t.map((x) => x.label)).toEqual([
      "Clusters",
      "Exposed Services",
      "Machine credentials",
    ]);
    // A tile whose value would be invented is the render-floor violation, and a version number is the most
    // quietly authoritative thing a screen can invent.
    expect(t.some((x) => /operator|version/i.test(x.label))).toBe(false);
  });

  it("counts Services ACROSS clusters, not per cluster", () => {
    expect(statTiles([card("a", 2), card("b", 1)], 0)[1].value).toBe(3);
  });

  it("⛔ null and 0 are DIFFERENT for machine credentials — both arms", () => {
    // 0 means "we looked, there are none"; null means "we could not look". A zero standing in for unknown is
    // the reassuring-empty defect in numeric form.
    const zero = statTiles([], 0)[2];
    const unknown = statTiles([], null)[2];
    expect(zero.value).toBe(0);
    expect(unknown.value).toBeNull();
    expect(unknown.hint).toMatch(/could not read/i);
    expect(zero.hint).not.toMatch(/could not read/i);
  });

  it("N=0 clusters says 'none registered' rather than an empty hint", () => {
    expect(statTiles([], 0)[0].hint).toMatch(/none registered/i);
  });
});

describe("clusterReachability — D9", () => {
  const gw = (id: string, endpointsUnavailable = false, revoked = false) => ({
    id,
    endpointsUnavailable,
    revoked,
  });

  it("⛔ reachable and UNREACHABLE are both observed, in one test", () => {
    // Mechanism ⑨: a function that always returned reachable:true would pass a happy-path-only test.
    expect(
      clusterReachability({ connectorNodeId: "connector", gateways: [gw("connector")] }).reachable,
    ).toBe(true);
    expect(
      clusterReachability({ connectorNodeId: "connector", gateways: [gw("connector", true)] })
        .reachable,
    ).toBe(false);
  });

  it("NEVER blames the cluster — the kind has three causes and only one is 'cluster down'", () => {
    const r = clusterReachability({ connectorNodeId: "connector", gateways: [gw("connector", true)] });
    expect(r.why).toMatch(/no endpoint view/i);
    // Measured at dnat_linux.go:174 — the kind is also true for RBAC denial and an unsynced watch.
    expect(r.why).not.toMatch(
      /cluster is down|cluster down|unreachable cluster/i,
    );
  });

  it("no selected connector is UNREACHABLE, with a different reason than a failed watch", () => {
    const none = clusterReachability({ connectorNodeId: null, gateways: [] });
    const failed = clusterReachability({
      connectorNodeId: "connector",
      gateways: [gw("connector", true)],
    });
    expect(none.reachable).toBe(false);
    // Two distinct facts: nothing is bound, versus something is bound and blind.
    expect(none.why).not.toBe(failed.why);
    expect(none.why).toMatch(/no in-cluster connector is selected/i);
  });

  it("ignores an unselected gateway — another same-site gateway's blindness is not this cluster's problem", () => {
    expect(
      clusterReachability({
        connectorNodeId: "connector",
        gateways: [gw("other", true), gw("connector", false)],
      }).reachable,
    ).toBe(true);
  });

  it("a revoked or absent selected connector is unavailable — never substitute another gateway", () => {
    expect(
      clusterReachability({
        connectorNodeId: "connector",
        gateways: [gw("other", false)],
      }).reachable,
    ).toBe(false);
    expect(
      clusterReachability({
        connectorNodeId: "connector",
        gateways: [gw("connector", false, true), gw("other", false)],
      }).reachable,
    ).toBe(false);
  });
});

describe("serviceRowClass", () => {
  it("recedes an unreachable cluster's rows and only those", () => {
    expect(serviceRowClass(true)).toBe("");
    expect(serviceRowClass(false)).not.toBe("");
  });
});

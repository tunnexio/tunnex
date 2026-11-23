import { describe, expect, it } from "vitest";
import {
  DST_SCOPED,
  canEditRuleInModal,
  destinationOptions,
  flowGlyph,
  flowTag,
  ruleBody,
  ruleEffectSummary,
  ruleRow,
  sourceOptions,
  type LoadState,
  type RuleBodyInput,
} from "../src/lib/policyview";
import {
  K8S_API_OFF_REASON,
  K8S_API_SOURCE_REASON,
  K8S_API_UNREAD_REASON,
  k8sApiSourceAllowed,
  type K8sApiTarget,
} from "../src/lib/k8sapiaccess";
import { auditActionLabel, auditChangeConsequence, auditChangeLabel, auditK8sApiDestination } from "../src/lib/auditview";
import { blockerAdvice } from "../src/lib/accesstest";
import type { PolicyRule, UserGroup } from "../src/lib/api";

// K8N-3 stage 1 — a cluster's Kubernetes API as a rule destination. The kind is its own: it is never
// rendered, offered or sent as a Kubernetes Service, and only a person or a group can be its source.

const FQDN = "kubernetes.default.svc.prod.k8s.acme.com";
const PROD: K8sApiTarget = { clusterId: "c-prod", clusterName: "prod", access: { enabled: true, fqdn: FQDN, vip: "100.66.0.9" } };
const STAGING: K8sApiTarget = { clusterId: "c-staging", clusterName: "staging", access: { enabled: false, fqdn: "kubernetes.default.svc.staging.k8s.acme.com", vip: null } };
const UNREAD: K8sApiTarget = { clusterId: "c-unread", clusterName: "edge", access: null };
const APIS = [PROD, STAGING, UNREAD];
const CLUSTERS = APIS.map((target) => ({ id: target.clusterId, name: target.clusterName }));

const groups = [{ id: "g1", name: "Engineering" }] as unknown as UserGroup[];
const LOADED: LoadState = { groupsLoaded: true, resourcesLoaded: true, k8sClustersLoaded: true };
const apiRule = (over: Partial<PolicyRule> = {}): PolicyRule => ({
  id: "r-api", enabled: true, src_kind: "group", src_group_id: "g1", dst_kind: "k8s_api", dst_k8s_api_cluster_id: "c-prod",
  cidr_outside_org_ranges: false, dst_k8s_service_vanished: false, ...over,
}) as PolicyRule;

function options(srcKind: string) {
  return destinationOptions({ groups: [], resources: [], sites: [], services: [{ id: "k1", name: "payments" }], k8sApis: APIS, srcKind, srcSite: "" })
    .filter((option) => option.kind === "k8s_api");
}

const BODY: RuleBodyInput = {
  srcKind: "group", dstKind: "k8s_api", src: "g1", srcUser: "u1", srcSite: "", srcCidr: "", srcAgent: "",
  dstGroup: "", dstResource: "", dstSite: "", dstK8sService: "k1", dstK8sApiCluster: "c-prod", expiresAt: "", editing: false,
};

describe("rule builder — Kubernetes API destination", () => {
  it("sends dst_kind k8s_api with the cluster id and no other destination", () => {
    expect(ruleBody(BODY)).toEqual({ src_kind: "group", src_group_id: "g1", dst_kind: "k8s_api", dst_k8s_api_cluster_id: "c-prod" });
    expect(ruleBody({ ...BODY, srcKind: "user" })).toEqual({ src_kind: "user", src_user_id: "u1", dst_kind: "k8s_api", dst_k8s_api_cluster_id: "c-prod" });
    // The Service id the form may still hold is never sent with it.
    expect(ruleBody(BODY)).not.toHaveProperty("dst_k8s_service_id");
  });

  it("carries an expiry like any other grant", () => {
    const body = ruleBody({ ...BODY, expiresAt: "2026-12-01T10:00" });
    expect(body.dst_kind).toBe("k8s_api");
    expect(body.expires_at).toBe(new Date("2026-12-01T10:00").toISOString());
  });

  it("offers a cluster's API to a person or a group, labelled as its own kind on TCP 443", () => {
    for (const srcKind of ["group", "user"]) {
      const [prod] = options(srcKind);
      expect(prod).toMatchObject({ value: "c-prod", kind: "k8s_api", tag: "k8s api", label: "Kubernetes API of prod", section: DST_SCOPED });
      expect(prod!.detail).toBe(`${FQDN} · TCP 443`);
      expect(prod!.unavailable).toBeUndefined();
    }
    // It is one more row next to the cluster's Services, never one of them.
    const all = destinationOptions({ groups: [], resources: [], sites: [], services: [{ id: "k1", name: "payments" }], k8sApis: [PROD], srcKind: "group", srcSite: "" });
    expect(all.map((option) => option.kind)).toEqual(["k8s_service", "k8s_api"]);
  });

  it("does not offer it for a site, an address range or an agent source, and says why", () => {
    for (const srcKind of ["site", "cidr", "agent"]) {
      expect(k8sApiSourceAllowed(srcKind)).toBe(false);
      for (const option of options(srcKind)) expect(option.unavailable).toBe(K8S_API_SOURCE_REASON);
    }
    expect(k8sApiSourceAllowed("group")).toBe(true);
    expect(k8sApiSourceAllowed("user")).toBe(true);
  });

  it("shows a cluster whose API access is off, or unread, as unavailable with the reason", () => {
    const [, staging, unread] = options("group");
    expect(staging!.unavailable).toBe(K8S_API_OFF_REASON);
    expect(unread!.unavailable).toBe(K8S_API_UNREAD_REASON);
    expect(unread!.detail).toBe("TCP 443");
  });

  it("with a cluster's API chosen, a site and an agent cannot be picked as the source", () => {
    const sources = sourceOptions({
      groups: [{ id: "g1", name: "Engineering" }],
      members: [{ user_id: "u1", email: "ana@x.com", name: "Ana" }],
      sites: [{ id: "s1", name: "eu-lan" }],
      agents: [{ device_id: "d1", name: "build-bot", gateway_name: "gw-1" }],
      dstKind: "k8s_api",
      dstSite: "",
    });
    expect(sources.filter((option) => option.unavailable).map((option) => [option.kind, option.unavailable])).toEqual([
      ["site", K8S_API_SOURCE_REASON],
      ["agent", K8S_API_SOURCE_REASON],
    ]);
    // Any other destination leaves them selectable, as before.
    const others = sourceOptions({ groups: [], members: [], sites: [{ id: "s1", name: "eu-lan" }], agents: [{ device_id: "d1", name: "build-bot", gateway_name: "gw-1" }], dstKind: "k8s_service", dstSite: "" });
    expect(others.every((option) => option.unavailable === undefined)).toBe(true);
  });

  it("says what the rule allows before it is created: reach on one port, not what people may do", () => {
    const effect = ruleEffectSummary({ srcKind: "group", srcLabel: "Engineering", dstKind: "k8s_api", dstLabel: "Kubernetes API of prod" });
    expect(effect.wide).toBe(false);
    expect(effect.text).toBe("every device of Engineering will be able to reach the Kubernetes API of prod on TCP 443 only. This is a network path: each person's own cluster credential still decides what they may do.");
  });
});

describe("rule list — Kubernetes API destination", () => {
  it("reads 'Kubernetes API of <cluster>', never a Service name or a resource", () => {
    const row = ruleRow(apiRule(), groups, [], [], [], LOADED, [], [], CLUSTERS);
    expect(row.dst).toEqual({ id: "c-prod", label: "Kubernetes API of prod", state: "ok" });
    expect(row.broken).toBe(false);
    expect(row.k8sApiAccessOff).toBe(false);
    expect(row.k8sServiceVanished).toBe(false);
  });

  it("carries the server's 'API access is off' judgment verbatim, only for this kind", () => {
    expect(ruleRow(apiRule({ dst_k8s_api_access_off: true }), groups, [], [], [], LOADED, [], [], CLUSTERS).k8sApiAccessOff).toBe(true);
    expect(ruleRow(apiRule({ dst_k8s_api_access_off: false }), groups, [], [], [], LOADED, [], [], CLUSTERS).k8sApiAccessOff).toBe(false);
    const service = { id: "r-svc", enabled: true, src_kind: "group", src_group_id: "g1", dst_kind: "k8s_service", dst_k8s_service_id: "k1", dst_k8s_api_access_off: true } as unknown as PolicyRule;
    expect(ruleRow(service, groups, [], [], [], LOADED, [], [], CLUSTERS).k8sApiAccessOff).toBe(false);
  });

  it("falls back to a clear label when the cluster's name cannot be resolved", () => {
    const removed = ruleRow(apiRule({ dst_k8s_api_cluster_id: "0197aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee" }), groups, [], [], [], LOADED, [], [], CLUSTERS);
    expect(removed.dst.state).toBe("deleted");
    expect(removed.dst.label).toBe("Kubernetes API of removed cluster 0197aaaa…");
    expect(removed.dst.label).not.toMatch(/resource/i);

    const unread = ruleRow(apiRule(), groups, [], [], [], { groupsLoaded: true, resourcesLoaded: true, k8sClustersLoaded: false }, [], [], []);
    expect(unread.dst.state).toBe("unresolved");
    expect(unread.dst.label).toMatch(/^Kubernetes API of cluster .*refresh$/);

    // A rule with no cluster id at all still says what kind of destination it is.
    const empty = ruleRow(apiRule({ dst_k8s_api_cluster_id: null }), groups, [], [], [], LOADED, [], [], CLUSTERS);
    expect(empty.dst.label).toBe("Kubernetes API of an unnamed cluster");
    expect(empty.broken).toBe(true);
  });

  it("has its own glyph and tag in the access map, distinct from a Service", () => {
    expect(flowGlyph("k8s_api")).toBe("A");
    expect(flowTag("k8s_api")).toBe("K8S API");
    expect(flowGlyph("k8s_api")).not.toBe(flowGlyph("k8s_service"));
    expect(flowTag("k8s_api")).not.toBe(flowTag("k8s_service"));
  });

  it("stays editable in the rule editor: its source is always a person or a group", () => {
    expect(canEditRuleInModal({ src_kind: "group", dst_kind: "k8s_api" })).toBe(true);
    expect(canEditRuleInModal({ src_kind: "user", dst_kind: "k8s_api" })).toBe(true);
  });
});

describe("audit log — Kubernetes API", () => {
  it("names the cluster when API access is turned on or off", () => {
    const on = { action: "k8s.api_access_enabled", details: { cluster: "prod", name: FQDN, vip: "100.66.0.9", port: 443, rules_taking_effect: 2 } };
    const off = { action: "k8s.api_access_disabled", details: { cluster: "prod", name: FQDN, vip: "100.66.0.9", rules_kept: 1 } };
    expect(auditChangeLabel(on)).toBe("Kubernetes API access turned on for prod");
    expect(auditChangeLabel(off)).toBe("Kubernetes API access turned off for prod");
    expect(auditChangeConsequence(on)).toBe("2 rules that already named this cluster's API took effect again.");
    expect(auditChangeConsequence(off)).toBe("1 rule that named this cluster's API was kept and allows nothing until API access is turned on again.");
    expect(auditChangeConsequence({ action: "k8s.api_access_enabled", details: { cluster: "prod", rules_taking_effect: 0 } })).toBe("No access rule named this cluster's API, so nobody could reach it yet.");
  });

  it("does not invent a cluster name or a count the row does not carry", () => {
    expect(auditChangeLabel({ action: "k8s.api_access_disabled", details: {} })).toBe("Kubernetes API access turned off for a cluster whose name was not recorded");
    expect(auditChangeLabel({ action: "k8s.api_access_enabled" })).toBe("Kubernetes API access turned on for a cluster whose name was not recorded");
    expect(auditChangeConsequence({ action: "k8s.api_access_disabled", details: { cluster: "prod" } })).toBeNull();
  });

  it("labels the action alone, with no cluster, where there is no event to read", () => {
    expect(auditActionLabel("k8s.api_access_enabled")).toBe("Kubernetes API access turned on");
    expect(auditActionLabel("k8s.api_access_disabled")).toBe("Kubernetes API access turned off");
    expect(auditActionLabel("policy.rule_created")).toBe("Rule created");
  });

  it.each([
    ["policy.rule_created", "Rule created · Kubernetes API of prod"],
    ["policy.rule_deleted", "Rule deleted · Kubernetes API of prod"],
    ["policy.rule_enabled", "Rule enabled · Kubernetes API of prod"],
    ["policy.rule_disabled", "Rule disabled · Kubernetes API of prod"],
    ["policy.grant_expired", "Grant expired · Kubernetes API of prod"],
  ])("shows the destination of %s as the cluster's Kubernetes API", (action, label) => {
    const row = { action, details: { dst_kind: "k8s_api", dst_k8s_api_cluster: "prod", dst_k8s_api_cluster_id: "c-prod" } };
    expect(auditK8sApiDestination(row)).toBe("Kubernetes API of prod");
    expect(auditChangeLabel(row)).toBe(label);
  });

  it("leaves every other event reading as it did", () => {
    expect(auditChangeLabel({ action: "policy.rule_created", details: { dst_kind: "resource" } })).toBe("Rule created");
    expect(auditChangeLabel({ action: "policy.rule_created" })).toBe("Rule created");
    expect(auditChangeLabel({ action: "org.zero_trust_enabled", details: {} })).toBe("Zero trust enabled");
    expect(auditChangeLabel({ action: "k8s.service_exposed", details: { dst_k8s_api_cluster: "prod" } })).toBe("Service exposed");
    expect(auditK8sApiDestination({ action: "policy.rule_created", details: { dst_kind: "k8s_api" } })).toBe("Kubernetes API of a cluster whose name was not recorded");
    expect(auditChangeConsequence({ action: "policy.rule_created", details: {} })).toBeNull();
  });
});

describe("Test access — Kubernetes API blockers", () => {
  it("API access off: says so and points at the cluster's page", () => {
    const advice = blockerAdvice("k8s_api_not_enabled", { cluster: "prod", name: FQDN });
    expect(advice?.text).toBe("API access is off for that cluster, so its Kubernetes API has no address in the tunnel. Turn it on on the cluster's page.");
    expect(advice?.action).toEqual({ label: "Open Kubernetes", to: "/kubernetes" });
  });

  it("endpoint unavailable: names the control-plane-node case from the check's reason", () => {
    const onNode = blockerAdvice("k8s_api_endpoint_unavailable", { cluster: "prod", gateway: "gw-prod", reason: "endpoints_on_gateway_node" });
    expect(onNode?.text).toBe("The cluster's gateway cannot forward to the API server. The gateway runs on the cluster's only control-plane node; it must run on a worker node.");
    for (const reason of ["no_ready_endpoints", "endpoints_unavailable", "unknown"]) {
      const advice = blockerAdvice("k8s_api_endpoint_unavailable", { cluster: "prod", reason });
      expect(advice?.text).toBe("The cluster's gateway cannot forward to the API server.");
      expect(advice?.text).not.toMatch(/control-plane/);
    }
    expect(blockerAdvice("k8s_api_endpoint_unavailable", { cluster: "prod", reason: "no_gateway" })?.text).toMatch(/The cluster has no gateway assigned, so nothing forwards to its API server\./);
    // The existing one-argument call still answers.
    expect(blockerAdvice("k8s_api_endpoint_unavailable")?.text).toBe("The cluster's gateway cannot forward to the API server.");
  });

  it("endpoint not observed: the gateway has not said, and an older one never does", () => {
    const advice = blockerAdvice("k8s_api_endpoint_not_observed");
    expect(advice?.text).toBe("The cluster's gateway has not reported whether it can reach the API server, so this step cannot be confirmed. An older gateway never reports it.");
  });

  it("keeps the existing advice, with or without facts", () => {
    expect(blockerAdvice("no_matching_grant")?.action?.to).toBe("/access");
    expect(blockerAdvice("no_matching_grant", { cluster: "prod" })?.text).toBe(blockerAdvice("no_matching_grant")?.text);
    expect(blockerAdvice("k8s_api_destination")).toBeNull();
    expect(blockerAdvice("k8s_api_endpoint_ready")).toBeNull();
  });
});

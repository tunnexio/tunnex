import { describe, expect, it } from "vitest";
import {
  EMPTY_ENROLLMENT_DRAFT,
  K8S_PROVIDER_CATALOG,
  changeEnrollmentProvider,
  serviceNetworkHelp,
  suggestedDnsZone,
  suggestedVipRange,
  enrollmentComplete,
} from "../src/lib/k8senrollment";

describe("provider-first Kubernetes enrollment model", () => {
  it("offers only the qualified provider/platform pairs", () => {
    expect(K8S_PROVIDER_CATALOG.map((entry) => [entry.provider, entry.platform])).toEqual([
      ["aws", "eks"],
      ["azure", "aks"],
      ["gcp", "gke_standard"],
      ["self_managed", "kubernetes"],
    ]);
  });

  it("has no silent Site, connector, cluster, or network defaults", () => {
    expect(EMPTY_ENROLLMENT_DRAFT).toEqual({
      provider: "",
      platform: "",
      siteId: "",
      connectorNodeId: "",
      name: "",
      vipRange: "",
      serviceCidr: "",
      dnsZone: "",
    });
    expect(enrollmentComplete(EMPTY_ENROLLMENT_DRAFT)).toBe(false);
  });

  it("changing provider clears every provider-derived selection without inventing network values", () => {
    const next = changeEnrollmentProvider(
      {
        provider: "aws",
        platform: "eks",
        siteId: "site-1",
        connectorNodeId: "node-1",
        name: "prod",
        vipRange: "100.64.0.0/16",
        serviceCidr: "10.96.0.0/12",
        dnsZone: "k8s.example.test",
      },
      "azure",
    );
    // Each provider has one supported Kubernetes service, so it is selected with the provider.
    expect(next).toEqual({
      provider: "azure",
      platform: "aks",
      siteId: "",
      connectorNodeId: "",
      name: "",
      vipRange: "100.64.0.0/16",
      serviceCidr: "10.96.0.0/12",
      dnsZone: "k8s.example.test",
    });
  });

  it("rejects mismatched provider/platform pairs", () => {
    expect(enrollmentComplete({
      provider: "aws",
      platform: "aks",
      siteId: "site-1",
      connectorNodeId: "node-1",
      name: "prod",
      vipRange: "100.64.0.0/16",
      serviceCidr: "10.96.0.0/12",
      dnsZone: "k8s.example.test",
    })).toBe(false);
  });

  it("suggests a free address range and reuses the organization's DNS zone", () => {
    expect(suggestedVipRange([])).toBe("100.64.0.0/16");
    expect(suggestedVipRange(["100.64.0.0/16"])).toBe("100.65.0.0/16");
    // A smaller range inside a /16 and a larger one covering several both count as taken.
    expect(suggestedVipRange(["100.64.32.0/20", "100.65.0.0/16"])).toBe("100.66.0.0/16");
    expect(suggestedVipRange(["100.64.0.0/14"])).toBe("100.68.0.0/16");
    expect(suggestedVipRange(["100.64.0.0/10"])).toBe("");
    expect(suggestedVipRange(["not a range", "10.0.0.0/8"])).toBe("100.64.0.0/16");
    expect(suggestedDnsZone([])).toBe("k8s.internal");
    expect(suggestedDnsZone(["K8s.Corp.Internal", "k8s.corp.internal", "other.test"])).toBe("k8s.corp.internal");
  });

  it("names the command that prints the cluster's Service network for each platform", () => {
    expect(serviceNetworkHelp("eks").command).toContain("aws eks describe-cluster");
    expect(serviceNetworkHelp("aks").command).toContain("az aks show");
    expect(serviceNetworkHelp("gke_standard").command).toContain("servicesIpv4Cidr");
    expect(serviceNetworkHelp("kubernetes").command).toContain("service-cluster-ip-range");
    expect(serviceNetworkHelp("kubernetes").typical).toContain("10.43.0.0/16");
  });
});

import { describe, expect, it } from "vitest";
import {
  EMPTY_ENROLLMENT_DRAFT,
  K8S_PROVIDER_CATALOG,
  changeEnrollmentProvider,
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
    expect(next).toEqual({
      provider: "azure",
      platform: "",
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
});

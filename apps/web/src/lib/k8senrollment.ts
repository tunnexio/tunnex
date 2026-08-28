import type { ProviderMarkName } from "../components/ProviderMarks";

export type EnrollmentProvider = ProviderMarkName;
export type EnrollmentPlatform = "eks" | "aks" | "gke_standard" | "kubernetes";

export interface ProviderCatalogEntry {
  provider: EnrollmentProvider;
  providerLabel: string;
  platform: EnrollmentPlatform;
  platformLabel: string;
  guidance: string;
}

export const K8S_PROVIDER_CATALOG: readonly ProviderCatalogEntry[] = [
  {
    provider: "aws",
    providerLabel: "Amazon Web Services",
    platform: "eks",
    platformLabel: "Amazon Elastic Kubernetes Service (EKS)",
    guidance: "Enroll a connected EKS cluster through a Tunnex connector already bound to the selected Site.",
  },
  {
    provider: "azure",
    providerLabel: "Microsoft Azure",
    platform: "aks",
    platformLabel: "Azure Kubernetes Service (AKS)",
    guidance: "Enroll a connected AKS cluster through a Tunnex connector already bound to the selected Site.",
  },
  {
    provider: "gcp",
    providerLabel: "Google Cloud",
    platform: "gke_standard",
    platformLabel: "Google Kubernetes Engine (GKE Standard)",
    guidance: "Enroll a connected GKE Standard cluster. GKE Autopilot is not offered as qualified support.",
  },
  {
    provider: "self_managed",
    providerLabel: "Self-managed",
    platform: "kubernetes",
    platformLabel: "Kubernetes",
    guidance: "Enroll a generic self-managed Kubernetes cluster through its connected Tunnex connector.",
  },
] as const;

export interface EnrollmentDraft {
  provider: EnrollmentProvider | "";
  platform: EnrollmentPlatform | "";
  siteId: string;
  connectorNodeId: string;
  name: string;
  vipRange: string;
  serviceCidr: string;
  dnsZone: string;
}

export const EMPTY_ENROLLMENT_DRAFT: EnrollmentDraft = {
  provider: "",
  platform: "",
  siteId: "",
  connectorNodeId: "",
  name: "",
  vipRange: "",
  serviceCidr: "",
  dnsZone: "",
};

const DNS_LABEL = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?$/;
const DNS_NAME = /^[a-z0-9](?:[-a-z0-9]*[a-z0-9])?(?:\.[a-z0-9](?:[-a-z0-9]*[a-z0-9])?)*$/;

export function enrollmentValidation(draft: EnrollmentDraft): { name?: string; dnsZone?: string } {
  const issues: { name?: string; dnsZone?: string } = {};
  const name = draft.name.trim();
  const dnsZone = draft.dnsZone.trim();
  if (name && (name.length > 63 || !DNS_LABEL.test(name))) {
    issues.name = "Use one lowercase DNS label: a-z, 0-9, and internal hyphens; maximum 63 characters.";
  }
  if (dnsZone && (dnsZone.length > 253 || !DNS_NAME.test(dnsZone))) {
    issues.dnsZone = "Use a lowercase DNS domain such as k8s.acme.internal.";
  }
  return issues;
}

export function catalogEntry(provider: EnrollmentProvider | ""): ProviderCatalogEntry | null {
  return K8S_PROVIDER_CATALOG.find((entry) => entry.provider === provider) ?? null;
}

export function providerPlatformEntry(
  provider: string,
  platform: string,
): ProviderCatalogEntry | null {
  return K8S_PROVIDER_CATALOG.find(
    (entry) => entry.provider === provider && entry.platform === platform,
  ) ?? null;
}

/** Changing cloud context invalidates every provider-derived identity choice. */
export function changeEnrollmentProvider(
  draft: EnrollmentDraft,
  provider: EnrollmentProvider,
): EnrollmentDraft {
  if (draft.provider === provider) return draft;
  return {
    ...draft,
    provider,
    platform: "",
    siteId: "",
    connectorNodeId: "",
    name: "",
  };
}

export function enrollmentComplete(draft: EnrollmentDraft): boolean {
  const expected = catalogEntry(draft.provider);
  const issues = enrollmentValidation(draft);
  return Boolean(
    expected &&
      draft.platform === expected.platform &&
      draft.siteId &&
      draft.connectorNodeId &&
      draft.name.trim() &&
      draft.vipRange.trim() &&
      draft.serviceCidr.trim() &&
      draft.dnsZone.trim(),
  ) && !issues.name && !issues.dnsZone;
}

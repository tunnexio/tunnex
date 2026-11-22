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
    // Each provider has exactly one supported Kubernetes service, so there is nothing to choose.
    platform: catalogEntry(provider)?.platform ?? "",
    siteId: "",
    connectorNodeId: "",
    name: "",
  };
}

function ipv4Range(cidr: string): [number, number] | null {
  const match = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\/(\d{1,2})$/.exec(cidr.trim());
  if (!match) return null;
  const octets = match.slice(1, 5).map(Number);
  const bits = Number(match[5]);
  if (octets.some((octet) => octet > 255) || bits > 32) return null;
  const address = ((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3];
  const size = 2 ** (32 - bits);
  const start = Math.floor(address / size) * size;
  return [start, start + size - 1];
}

/**
 * A free /16 for a new cluster's Service addresses, from the shared address space 100.64.0.0/10
 * (reserved for exactly this kind of private overlay, so it does not collide with office or cloud
 * networks). Skips ranges other clusters already use. Empty when all 64 are taken.
 */
export function suggestedVipRange(existing: readonly string[]): string {
  const taken = existing.map(ipv4Range).filter((range): range is [number, number] => range !== null);
  for (let second = 64; second <= 127; second += 1) {
    const candidate = ipv4Range(`100.${second}.0.0/16`)!;
    if (!taken.some(([start, end]) => start <= candidate[1] && candidate[0] <= end)) return `100.${second}.0.0/16`;
  }
  return "";
}

/** Reuse the zone the organization already uses for clusters; otherwise a neutral private one. */
export function suggestedDnsZone(existing: readonly string[]): string {
  const counts = new Map<string, number>();
  for (const zone of existing) {
    const name = zone.trim().toLowerCase();
    if (name) counts.set(name, (counts.get(name) ?? 0) + 1);
  }
  let best = "";
  for (const [zone, count] of counts) if (!best || count > (counts.get(best) ?? 0)) best = zone;
  return best || "k8s.internal";
}

/**
 * The Service network is a fact about the cluster, never a choice, so it is not guessed. This is
 * the one command that prints it, per platform, and the usual value where there is one.
 */
export function serviceNetworkHelp(platform: EnrollmentPlatform | ""): { command: string; typical: string } {
  switch (platform) {
    case "eks":
      return { command: "aws eks describe-cluster --name CLUSTER --query cluster.kubernetesNetworkConfig.serviceIpv4Cidr --output text", typical: "usually 172.20.0.0/16 or 10.100.0.0/16" };
    case "aks":
      return { command: "az aks show --resource-group GROUP --name CLUSTER --query networkProfile.serviceCidr --output tsv", typical: "usually 10.0.0.0/16" };
    case "gke_standard":
      return { command: "gcloud container clusters describe CLUSTER --location LOCATION --format='value(servicesIpv4Cidr)'", typical: "for example 34.118.224.0/20" };
    default:
      return { command: "kubectl cluster-info dump | grep -m1 service-cluster-ip-range", typical: "k3s uses 10.43.0.0/16, kubeadm 10.96.0.0/12" };
  }
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

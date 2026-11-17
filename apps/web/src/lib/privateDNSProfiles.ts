import type { FQDNResolverContextConfig, FQDNResolverProfile } from "./api";

export function resolverProfiles(config: FQDNResolverContextConfig): FQDNResolverProfile[] {
  if (config.profiles?.length) return config.profiles;
  return [{
    id: config.id,
    name: `${config.provider_hint === "aws" ? "AWS" : config.provider_hint === "azure" ? "Microsoft Azure" : config.provider_hint === "google_cloud" ? "Google Cloud" : "On-premises"} private DNS`,
    provider_hint: config.provider_hint ?? "on_premises",
    zone_suffixes: [],
    endpoints: config.endpoints ?? [],
    legacy_default: true,
  }];
}

export type ResolverProfileMatch = { profile: FQDNResolverProfile; matchedSuffix: string };

/** Mirrors the server's label-boundary, longest-suffix selection for preview only. */
export function matchResolverProfile(hostname: string, config: FQDNResolverContextConfig): ResolverProfileMatch | null {
  const normalizedHostname = hostname.trim().toLowerCase().replace(/\.$/, "");
  if (!normalizedHostname) return null;

  let selected: ResolverProfileMatch | null = null;
  let legacy: FQDNResolverProfile | null = null;
  const owners = new Map<string, string>();
  for (const profile of resolverProfiles(config)) {
    if (profile.legacy_default) {
      if (legacy) return null;
      legacy = profile;
    }
    for (const rawSuffix of profile.zone_suffixes) {
      const suffix = rawSuffix.trim().toLowerCase().replace(/\.$/, "");
      if (!suffix) return null;
      const owner = owners.get(suffix);
      if (owner && owner !== profile.id) return null;
      owners.set(suffix, profile.id);
      if (normalizedHostname !== suffix && !normalizedHostname.endsWith(`.${suffix}`)) continue;
      if (!selected || suffix.length > selected.matchedSuffix.length) {
        selected = { profile, matchedSuffix: suffix };
      } else if (suffix.length === selected.matchedSuffix.length && profile.id !== selected.profile.id) {
        return null;
      }
    }
  }
  return selected ?? (legacy ? { profile: legacy, matchedSuffix: "" } : null);
}


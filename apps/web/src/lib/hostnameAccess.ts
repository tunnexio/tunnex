import type { components } from "@tunnex/shared";
import type { FQDNResolverContextConfig, FQDNResolverProfileRequest, FQDNResource } from "./api";
import { matchResolverProfile, resolverProfiles } from "./privateDNSProfiles";

export type HostnameRecord = components["schemas"]["FQDNStaticRecord"];
export type ApplicationPath = NonNullable<FQDNResource["application_ipsec_path"]>;
export type HostnameResource = FQDNResource;
export const normalizedHostname = (name: string) => name.trim().toLowerCase().replace(/\.$/, "");
export function validHostname(name: string) {
  const value = normalizedHostname(name);
  return value.length <= 253 && value.includes(".") && !/^\d+(\.\d+){3}$/.test(value)
    && value.split(".").every(label => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label));
}
export function sameRecord(a: HostnameRecord, b: HostnameRecord) {
  return normalizedHostname(a.name) === normalizedHostname(b.name) && a.type === b.type
    && normalizedHostname(a.value) === normalizedHostname(b.value) && a.ttl === b.ttl;
}

/** Preserve every unrelated profile and record. A saved row is an optimistic
 * identity fence, never permission to overwrite a record another admin changed. */
export function hostnameDNSPlan(config: FQDNResolverContextConfig | null, record: HostnameRecord,
  endpoints: FQDNResolverProfileRequest["endpoints"], original?: HostnameRecord): FQDNResolverProfileRequest[] | null {
  const profiles = config ? resolverProfiles(config) : [];
  if (profiles.some(profile => profile.legacy_default)) throw new Error("This resolver uses a legacy catch-all. Update its DNS profiles before adding hostname access.");
  const selected = config ? matchResolverProfile(record.name, config)?.profile : undefined;
  const records = selected?.static_records;
  if (selected && !records) throw new Error("This hostname belongs to a forwarded DNS zone. Add it in that DNS server, or choose a name in a managed-record zone.");
  if (records?.some(item => sameRecord(item, record))) return null;
  const previous = original && records?.findIndex(item => sameRecord(item, original));
  if (original && (previous === undefined || previous < 0)) throw new Error("This DNS record changed. Close and refresh the DNS editor before saving.");
  if (!original && records?.some(item => normalizedHostname(item.name) === normalizedHostname(record.name))) throw new Error("This hostname already has DNS records. Use Grant access on the saved record.");
  const body = profiles.map(profile => ({
    name: profile.name, provider_hint: profile.provider_hint, zone_suffixes: [...profile.zone_suffixes],
    endpoints: profile.endpoints.map(endpoint => ({ ...endpoint })),
    ...(profile.ipsec_path ? { ipsec_path: { ...profile.ipsec_path } } : {}),
    ...(profile.static_records ? { static_records: profile.static_records.map(item => ({ ...item })) } : {}),
    ...(profile.lan_listener ? { lan_listener: { ...profile.lan_listener, allowed_sources: [...profile.lan_listener.allowed_sources] } } : {}),
  }));
  if (selected) {
    const index = profiles.findIndex(profile => profile.id === selected.id);
    const next = body[index].static_records!;
    if (typeof previous === "number" && previous >= 0) next[previous] = record;
    else next.push(record);
    // Existing profile upstream choices remain authoritative. The simple editor
    // never silently opts other aliases into new external DNS lookups.
    if (record.type === "CNAME" && !body[index].endpoints.length) {
      const localTarget = selected.zone_suffixes.some(zone => normalizedHostname(record.value) === zone || normalizedHostname(record.value).endsWith(`.${zone}`));
      if (!localTarget) throw new Error("Enable target lookup in this DNS profile before granting access to its external CNAME.");
    }
    if (next.length > 128) throw new Error("This DNS profile already contains the maximum number of records.");
  } else {
    if (body.length >= 16) throw new Error("This gateway already has 16 DNS profiles. Add the record to a suitable existing profile.");
    body.push({ name: record.name, provider_hint: "on_premises", zone_suffixes: [record.name], endpoints: record.type === "CNAME" ? endpoints : [], static_records: [record] });
  }
  return body;
}

export function matchesHostnameResource(resource: HostnameResource, fqdn: string, siteId: string, gatewayId: string,
  path: ApplicationPath, protocol: "tcp" | "udp", port: number) {
  return resource.fqdn === normalizedHostname(fqdn) && resource.resolver_context?.site_id === siteId
    && resource.resolver_context.gateway_id === gatewayId && resource.protocol === protocol
    && resource.port_low === port && resource.port_high === port
    && resource.application_ipsec_path?.connection_id === path.connection_id
    && resource.application_ipsec_path.configuration_revision === path.configuration_revision;
}

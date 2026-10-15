import { useEffect, useState } from "react";
import type { FQDNResolverProfile, Node } from "../lib/api";
import { Button } from "./ui";

type Props = { gateway?: Node; profiles: readonly FQDNResolverProfile[]; onRefresh: () => void };
export function PrivateDNSLANStatus({ gateway, profiles, onRefresh }: Props) {
  const [now, setNow] = useState(Date.now);
  useEffect(() => { const timer = setInterval(() => setNow(Date.now()), 5000); return () => clearInterval(timer); }, []);
  const configured = profiles.filter(profile => profile.lan_listener);
  if (!configured.length) return null;
  const reported = gateway?.dns_lan_reported_at ? Date.parse(gateway.dns_lan_reported_at) : NaN;
  const fresh = Number.isFinite(reported) && now - reported >= -5000 && now - reported < 90000;
  return <div className="space-y-2 rounded-md border border-line px-3 py-3" aria-label="Office DNS listener status">
    <div className="flex items-center justify-between gap-3"><p className="text-sm font-semibold text-ink-heading">Office DNS listener</p><Button size="sm" variant="ghost" onClick={onRefresh}>Refresh listener status</Button></div>
    {configured.map(profile => {
      const listener = profile.lan_listener!;
      const state = gateway?.dns_lan_listeners?.find(item => item.address === listener.address && item.interface === listener.interface && item.profile_ids.includes(profile.id));
      const label = !fresh ? "Awaiting a current gateway report" : !state ? "Waiting for this profile version to apply" : state.ready ? "Listening on UDP and TCP 53" : `Unavailable: ${state.error || "listener is not bound"}`;
      return <div key={profile.id} className="text-xs"><span className="font-medium text-ink-heading">{profile.name}</span><span className="text-ink-tertiary"> · {listener.address} · {listener.interface}</span><p className={fresh && state && !state.ready ? "text-danger" : "text-ink-tertiary"}>{label}</p><p className="text-ink-tertiary">Private zones: {profile.zone_suffixes.join(", ")}. DNS clients: {listener.allowed_sources.join(", ")}.</p><p className="text-ink-tertiary">{listener.default_upstreams?.length ? `Other domains: ${listener.default_upstreams.join(", ")} · UDP/TCP 53` : "Private zones for this profile · other-domain DNS not enabled here"}</p></div>;
    })}
    <p className="text-xs text-ink-tertiary">Listener status confirms local sockets only. Before switching DHCP DNS to this gateway, ensure a profile on this same DNS address and interface enables Resolve other domains for your client range, then verify private and public names over UDP and TCP. If no profile does, keep your existing office DNS server and add conditional forwarders for the private zones. Cloud DNS also needs a working tunnel, DNS policies and cloud firewall rules.</p>
  </div>;
}

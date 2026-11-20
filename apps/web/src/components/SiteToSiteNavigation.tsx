import { Link } from "react-router-dom";

export type SiteToSiteTab = "overview" | "topology" | "ranges" | "ha" | "dns" | "cloud-vpn";

// SSI-13 D1 — ONE row of tabs for the whole Site-to-site area. There used to be a Networks/Connections
// switch above a second row of tabs, so "how are my networks joined?" had two answers on two levels.
// Existing URLs are kept: every tab but the last is a section of /sites, the last is /site-to-site.
export const SITE_TO_SITE_TABS: ReadonlyArray<readonly [SiteToSiteTab, string, string, string]> = [
  ["overview", "/sites", "Networks", "Your networks, their gateways and how they are linked"],
  ["topology", "/sites?section=topology", "Map", "See how networks connect"],
  ["ranges", "/sites?section=ranges", "Ranges", "Private ranges shared by your networks"],
  ["ha", "/sites?section=ha", "Failover", "Primary and standby gateways"],
  ["dns", "/sites?section=dns", "DNS forwarding", "Resolve private names across networks"],
  ["cloud-vpn", "/site-to-site", "Cloud VPN", "IPsec tunnels to AWS, Google Cloud and Azure"],
];

export function SiteToSiteNavigation({ active }: { active: SiteToSiteTab }) {
  return <nav aria-label="Site-to-site" className="sites-section-nav s2s-networks-sections">
    {SITE_TO_SITE_TABS.map(([id, to, label, description]) => <Link
      key={id}
      to={to}
      title={description}
      aria-current={active === id ? "page" : undefined}
    ><span>{label}</span></Link>)}
  </nav>;
}

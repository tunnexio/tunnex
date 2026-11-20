import { Link } from "react-router-dom";

export type SiteToSiteTab = "overview" | "topology" | "ranges" | "ha" | "dns" | "cloud-vpn";

// SSI-13 D1 — ONE row of tabs for the whole Site-to-site area. There used to be a Networks/Connections
// switch above a second row of tabs, so "how are my networks joined?" had two answers on two levels.
// Existing URLs are kept: every tab but the last is a section of /sites, the last is /site-to-site.
export const SITE_TO_SITE_TABS: ReadonlyArray<readonly [SiteToSiteTab, string, string, string]> = [
  ["overview", "/sites", "Networks", "Your private networks. Each one has a Tunnex gateway running inside it."],
  ["topology", "/sites?section=topology", "Map", "How your networks are joined."],
  ["ranges", "/sites?section=ranges", "Ranges", "The private addresses each network shares with the others."],
  ["ha", "/sites?section=ha", "Failover", "Which gateway is primary and which one stands by."],
  ["dns", "/sites?section=dns", "DNS forwarding", "Send private names to a resolver inside one of your networks."],
  ["cloud-vpn", "/site-to-site", "Cloud VPN", "IPsec tunnels from one of your networks to a cloud provider's VPN gateway, where no Tunnex gateway runs."],
];

/** One line under the tabs: what this tab holds. The two lists (Networks, Cloud VPN) differ in kind, and
 *  nothing on screen said how. */
export function SiteToSiteHint({ active }: { active: SiteToSiteTab }) {
  return <p className="s2s-tab-hint">{SITE_TO_SITE_TABS.find(([id]) => id === active)?.[3]}</p>;
}

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

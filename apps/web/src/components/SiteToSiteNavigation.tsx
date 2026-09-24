import { Link } from "react-router-dom";

/** One workspace, with existing URLs retained for shared site/gateway deep links. */
export function SiteToSiteNavigation({ active }: { active: "networks" | "connectivity" }) {
  return <nav aria-label="Site-to-site workspace" className="flex flex-wrap border-b border-white/10">
    {([
      ["networks", "/sites", "Networks"],
      ["connectivity", "/site-to-site", "Connectivity"],
    ] as const).map(([id, to, label]) => <Link
      key={id}
      to={to}
      aria-current={active === id ? "page" : undefined}
      className={`min-h-10 border-b-2 px-3 py-2 text-cell transition-colors ${active === id ? "border-ink-heading text-ink-heading" : "border-transparent text-ink-tertiary hover:border-white/20 hover:text-ink-heading"}`}
    >{label}</Link>)}
  </nav>;
}

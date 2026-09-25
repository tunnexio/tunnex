import { Link } from "react-router-dom";

/** One workspace, with existing URLs retained for shared site/gateway deep links. */
export function SiteToSiteNavigation({ active }: { active: "networks" | "connectivity" }) {
  return <nav aria-label="Site-to-site workspace" className="workspace-tabs">
    {([
      ["networks", "/sites", "Networks"],
      ["connectivity", "/site-to-site", "Connections"],
    ] as const).map(([id, to, label]) => <Link
      key={id}
      to={to}
      aria-current={active === id ? "page" : undefined}

    >{label}</Link>)}
  </nav>;
}

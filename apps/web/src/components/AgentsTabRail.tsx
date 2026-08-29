import { Link, useLocation } from "react-router-dom";

const items = [
  { href: "/agents", label: "Agents" },
  { href: "/agents/policies", label: "Policy templates" },
  { href: "/agents/mcp", label: "MCP profiles" },
] as const;

/** The primary-domain rail for every AI Agents workspace, including detail. */
export function AgentsTabRail() {
  const { pathname } = useLocation();
  const activeHref = pathname === "/agents/policies" || pathname === "/agents/mcp"
    ? pathname
    : "/agents";
  return <nav aria-label="AI Agents sections" className="overflow-x-auto border-b border-white/[0.08]">
    <div className="flex min-w-max gap-6">
      {items.map((item) => <Link
        key={item.href}
        to={item.href}
        aria-current={activeHref === item.href ? "page" : undefined}
        className={`relative -mb-px px-0.5 py-2.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/35 ${activeHref === item.href
          ? "text-white after:absolute after:inset-x-0 after:bottom-0 after:h-px after:bg-white"
          : "text-ink-tertiary hover:text-ink-heading"}`}
      >{item.label}</Link>)}
    </div>
  </nav>;
}

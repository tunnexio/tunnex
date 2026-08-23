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
  return <nav aria-label="AI Agents sections" className="overflow-x-auto border-b border-white/10">
    <div className="flex min-w-max gap-1">
      {items.map((item) => <Link
        key={item.href}
        to={item.href}
        aria-current={activeHref === item.href ? "page" : undefined}
        className={`min-h-10 border-b-2 px-3 py-2 text-sm transition-colors ${activeHref === item.href
          ? "border-accent-400 text-ink-heading"
          : "border-transparent text-ink-tertiary hover:text-ink-heading"}`}
      >{item.label}</Link>)}
    </div>
  </nav>;
}

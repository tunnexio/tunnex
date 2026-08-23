const items = [{ href: "/access", label: "Rules" }, { href: "/access/groups", label: "Groups" }, { href: "/access/resources", label: "Resources" }] as const;
export function AccessTabRail() {
  const pathname = typeof window === "undefined" ? "/access" : window.location.pathname;
  const active = pathname === "/access/groups" || pathname === "/access/resources" ? pathname : "/access";
  return <nav aria-label="Access sections" className="overflow-x-auto border-b border-white/10"><div className="flex min-w-max gap-1">{items.map((item) => <a key={item.href} href={item.href} aria-current={active === item.href ? "page" : undefined} className={`min-h-10 border-b-2 px-3 py-2 text-sm ${active === item.href ? "border-accent-400 text-ink-heading" : "border-transparent text-ink-tertiary hover:text-ink-heading"}`}>{item.label}</a>)}</div></nav>;
}

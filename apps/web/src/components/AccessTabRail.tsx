const items = [
  { href: "/access", label: "Rules" },
  { href: "/access/groups", label: "Groups" },
  { href: "/access/resources", label: "Resources" },
] as const;
export function AccessTabRail() {
  const pathname = typeof window === "undefined" ? "/access" : window.location.pathname;
  const active = pathname === "/access/groups" || pathname === "/access/resources" ? pathname : "/access";
  return <nav aria-label="Access sections" className="overflow-x-auto border-b border-white/[0.08]">
    <div className="flex min-w-max gap-6">
      {items.map((item) => <a
        key={item.href}
        href={item.href}
        aria-current={active === item.href ? "page" : undefined}
        className={`relative -mb-px px-0.5 py-2.5 text-sm font-medium transition-colors focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-white/35 ${active === item.href
          ? "text-white after:absolute after:inset-x-0 after:bottom-0 after:h-px after:bg-white"
          : "text-ink-tertiary hover:text-ink-heading"}`}
      >{item.label}</a>)}
    </div>
  </nav>;
}

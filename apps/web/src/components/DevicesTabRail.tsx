const items = [
  { href: "/devices", label: "Devices" },
  { href: "/devices/approvals", label: "Approvals" },
  { href: "/devices/posture", label: "Posture" },
] as const;

/** Route-aware without requiring Router context in existing direct page tests. */
export function DevicesTabRail() {
  const pathname = typeof window === "undefined" ? "/devices" : window.location.pathname;
  const active = items.some((item) => item.href === pathname) ? pathname : "/devices";
  return <nav aria-label="Device sections" className="overflow-x-auto border-b border-white/10"><div className="flex min-w-max gap-1">{items.map((item) => <a key={item.href} href={item.href} aria-current={active === item.href ? "page" : undefined} className={`min-h-10 border-b-2 px-3 py-2 text-sm ${active === item.href ? "border-accent-400 text-ink-heading" : "border-transparent text-ink-tertiary hover:text-ink-heading"}`}>{item.label}</a>)}</div></nav>;
}

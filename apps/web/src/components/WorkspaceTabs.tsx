import type { ReactNode } from "react";
import { Link, useLocation } from "react-router-dom";
import "../users-groups-workspace.css";

export function WorkspaceTabs({ label, items, activeHref }: {
  label: string;
  activeHref?:string;
  items: readonly { href: string; label: string }[];
}) {
  const { pathname } = useLocation();
  const active = [...items].sort((a, b) => b.href.length - a.href.length)
    .find((item) => pathname === item.href || pathname.startsWith(item.href + "/"));
  return <nav aria-label={label} className="workspace-tabs">
    {items.map((item) => <Link key={item.href} to={item.href}
      aria-current={(activeHref??active?.href) === item.href ? "page" : undefined}>{item.label}</Link>)}
  </nav>;
}

export function UsersTabRail({ actions }: { actions?: ReactNode } = {}) {
  return <div className="users-workspace-nav"><WorkspaceTabs label="User sections" items={[
    { href: "/users", label: "Users" },
    { href: "/users/groups", label: "Groups" },
    { href: "/users/roles", label: "Roles" },
    { href: "/users/invitations", label: "Invitations" },
  ]} />{actions && <div className="users-workspace-nav-actions">{actions}</div>}</div>;
}

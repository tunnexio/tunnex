import { Link, useLocation } from "react-router-dom";

export function WorkspaceTabs({ label, items }: {
  label: string;
  items: readonly { href: string; label: string }[];
}) {
  const { pathname } = useLocation();
  const active = [...items].sort((a, b) => b.href.length - a.href.length)
    .find((item) => pathname === item.href || pathname.startsWith(item.href + "/"));
  return <nav aria-label={label} className="workspace-tabs">
    {items.map((item) => <Link key={item.href} to={item.href}
      aria-current={active?.href === item.href ? "page" : undefined}>{item.label}</Link>)}
  </nav>;
}

export function UsersTabRail() {
  return <WorkspaceTabs label="Users and groups sections" items={[
    { href: "/users", label: "Users" },
    { href: "/users/groups", label: "Groups" },
    { href: "/users/roles", label: "Roles" },
    { href: "/users/invitations", label: "Invitations" },
  ]} />;
}

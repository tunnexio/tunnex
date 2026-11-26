import type { ReactNode } from "react";
import { Link } from "react-router-dom";
import { Card, Loading } from "./ui";
import { askText, useOrgAdmins } from "../lib/useOrgAdmins";
import { useOrg } from "../lib/useOrg";
import { NAV_PERMISSIONS, navAllows, useMyOrgRoles } from "../lib/navaccess";

/**
 * LS-UX-2: the one calm answer for a page someone reached by URL but cannot use. No codes, no alarm
 * colour, a named person to ask, and a way back. UX only: the API refuses on its own.
 */
export function AdminOnlyNotice({ page }: { page: string }) {
  const { org } = useOrg();
  const admins = useOrgAdmins(org?.id);
  return <section aria-label={`${page} is managed by organization admins`}><Card className="max-w-2xl space-y-3">
    <h1 className="text-base font-semibold text-ink-heading">{page} is managed by organization admins</h1>
    <p className="text-sm text-ink-secondary">Your account can't open this page. If you need something here, ask {askText(admins)}.</p>
    <Link className="text-brand text-sm" to="/dashboard">Go to your overview</Link>
  </Card></section>;
}

/** Renders the page only for people whose roles allow the destination; otherwise AdminOnlyNotice. */
export function AdminOnlyRoute({ to, page, children }: { to: string; page: string; children: ReactNode }) {
  const mine = useMyOrgRoles();
  if (!NAV_PERMISSIONS[to]) return <>{children}</>;
  if (mine.state === "loading") return <Loading label={`Loading ${page}…`} />;
  return navAllows(to, mine) ? <>{children}</> : <AdminOnlyNotice page={page} />;
}

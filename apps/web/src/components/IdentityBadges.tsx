import { useEffect, useState } from "react";
import { api, loadOne, type Loaded, type Member, type Meta } from "../lib/api";
import { useOrg } from "../lib/useOrg";
import { roleFromMembers } from "../lib/policyview";
import { useAuth } from "../lib/auth";
import { Badge } from "./ui";
import { Icon } from "./Icon";

// S14.4 — EDITION AND ROLE AS READ-ONLY BADGES.
//
// ⛔ THE WIREFRAME DREW THESE AS TOGGLES (FREE/ENTERPRISE and ADMIN/USER). They are DEMO CONTROLS, and the
// founder ruled them out: A USER CANNOT SWITCH THEIR OWN EDITION OR ROLE. Rendering a toggle would offer a
// privilege the product does not grant — and a control that looks interactive and is not is a worse lie than
// a missing control, because the user forms a plan around it.
//
// So these are <span>s carrying TEXT. Not buttons, not selects, not anything focusable.
//
// EDITION READS THROUGH THE ONE GATING SEAM — `/meta`'s `edition`, the same value that decides whether
// enterprise surfaces exist. Never a second source, so S12.1 rewrites one thing rather than hunting copies.
// ROLE reads the resolved role from the roster, which is where Users.tsx already gets it.

export function IdentityBadges({
  variant = "badges",
}: {
  variant?: "badges" | "inline" | "menu";
}) {
  const { org: currentOrg } = useOrg();
  const { state } = useAuth();
  const myId = state.status === "authed" ? state.user.id : "";
  const orgId = currentOrg?.id ?? "";
  const [identity, setIdentity] = useState<{
    edition: string | null;
    role: string | null;
    ready: boolean;
  }>({ edition: null, role: null, ready: false });

  useEffect(() => {
    let cancelled = false;
    if (!myId || !orgId) {
      setIdentity({ edition: null, role: null, ready: false });
      return () => {
        cancelled = true;
      };
    }

    setIdentity({ edition: null, role: null, ready: false });
    void (async () => {
      // ⭐ The org-list fetch is gone (S12.5) — and this badge is the reason the seam matters visibly:
      // it renders YOUR ROLE, which is per-organization. Reading it from index zero meant an owner of the
      // second org saw the role they hold in the first one, on every screen.
      const [meta, mem] = await Promise.all([
        loadOne(() => api.GET("/api/v1/meta")) as Promise<Loaded<Meta>>,
        loadOne(() =>
          api.GET("/api/v1/organizations/{orgId}/members", {
            params: { path: { orgId } },
          }),
        ) as Promise<Loaded<Member[]>>,
      ]);
      if (cancelled) return;
      const resolved = roleFromMembers(mem, myId);
      setIdentity({
        edition: meta.ok ? meta.data.edition : null,
        role: !resolved.failed && resolved.role ? resolved.role : null,
        ready: true,
      });
    })();
    return () => {
      cancelled = true;
    };
  }, [myId, orgId]);

  const { edition, role, ready } = identity;

  // ABSENT UNTIL KNOWN, same rule as the nav counts. A badge reading "free" because /meta failed would
  // misstate what the org has paid for — and unlike a count, nobody would think to doubt it.
  if (variant === "menu") {
    const planValue = ready ? edition ?? "Unavailable" : "Loading…";
    const roleValue = ready ? role ?? "Unavailable" : "Loading…";
    return (
      <div className="space-y-0.5">
        <div className="flex min-h-9 items-center gap-2 rounded-lg px-2.5 text-xs text-slate-300">
          <Icon name="shield" size={15} className="text-slate-400" />
          <span>Plan</span>
          <span className="ml-auto capitalize text-slate-400">{planValue}</span>
        </div>
        <div className="flex min-h-9 items-center gap-2 rounded-lg px-2.5 text-xs text-slate-300">
          <Icon name="user" size={15} className="text-slate-400" />
          <span>Role</span>
          <span className="ml-auto capitalize text-slate-400">{roleValue}</span>
        </div>
      </div>
    );
  }

  if (variant === "inline") {
    const values = [edition, role].filter((value): value is string => Boolean(value));
    if (values.length === 0) return null;
    return (
      <span className="flex min-w-0 items-center gap-1.5 text-[10px] font-medium uppercase tracking-[0.12em] text-slate-400">
        {values.map((value, index) => (
          <span key={value} className="contents">
            {index > 0 && <span aria-hidden="true" className="text-slate-600">·</span>}
            <span className="truncate">{value}</span>
          </span>
        ))}
      </span>
    );
  }

  return (
    <span className="flex items-center gap-2">
      {edition && <Badge tone="neutral">{edition}</Badge>}
      {role && <Badge tone="neutral">{role}</Badge>}
    </span>
  );
}

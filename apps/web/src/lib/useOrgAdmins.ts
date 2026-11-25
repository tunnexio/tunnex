import { useEffect, useState } from "react";
import { api } from "./api";
import { personLabel } from "./personLabel";

// SA-UX-2 S4: name whom to ask. Members already hold member:list and can read the member list (names, emails,
// roles); this reads that same endpoint and keeps only owners and admins. No new data is exposed. When the list
// cannot be read, callers fall back to the generic "an organization owner or admin".
export function useOrgAdmins(orgId: string | undefined, enabled = true): string[] {
  const [admins, setAdmins] = useState<string[]>([]);
  useEffect(() => {
    if (!orgId || !enabled) return;
    let live = true;
    void api.GET("/api/v1/organizations/{orgId}/members", { params: { path: { orgId } } }).then(result => {
      if (!live || !result.data) return;
      const people = result.data.filter(m => m.status === "active" && [m.role, ...(m.roles ?? [])].some(r => r === "owner" || r === "admin"));
      people.sort((a, b) => Number([b.role, ...(b.roles ?? [])].includes("owner")) - Number([a.role, ...(a.roles ?? [])].includes("owner")));
      setAdmins(people.slice(0, 3).map(m => personLabel(m)));
    }).catch(() => {});
    return () => { live = false; };
  }, [orgId, enabled]);
  return admins;
}

/** "Ask Alice (a@x) or Bob (b@x)" or the generic phrase. */
export function askText(admins: string[], generic = "an organization owner or admin"): string {
  if (!admins.length) return generic;
  if (admins.length === 1) return admins[0];
  return `${admins.slice(0, -1).join(", ")} or ${admins[admins.length - 1]}`;
}

import "../users-inventory.css";
import { useEffect, useId, useMemo, useState } from "react";
import type { Device, Member, Role } from "../lib/api";
import { canManageMembership, HUMAN_ROLES } from "../lib/rbac";
import { deviceCountFor, deviceCountLabel, rosterShape } from "../lib/usersview";
import AppAccessEmptyState from "./AppAccessEmptyState";
import AppAccessPagination from "./AppAccessPagination";
import AppAccessRowMenu from "./AppAccessRowMenu";
import { Button, Input } from "./ui";

export type UsersInventoryProps = {
  members: Member[];
  devices: Device[] | null;
  actorId: string;
  actorRole: Role | undefined;
  emailVerified: boolean;
  busy: boolean;
  view: "users" | "roles";
  onInspect: (userId: string, stage?: "overview" | "roles") => void;
  onRequestAction: (action: "deactivate" | "reactivate" | "reset", targets: Member[]) => void;
  ownerCount: number;
};

type AccountAction = "deactivate" | "reactivate" | "reset";
type MemberFilter = "all" | "active" | "deactivated";
type SortKey = "person" | "roles" | "state" | "devices";

const accountActionLabel: Record<AccountAction, string> = {
  deactivate: "Deactivate",
  reactivate: "Reactivate",
  reset: "Reset 2FA",
};

/** The page owns roster reads, confirmations, role editing and account mutations. */
export default function UsersInventory({ members, devices, actorId, actorRole, emailVerified, busy, view, onInspect, onRequestAction, ownerCount }: UsersInventoryProps) {
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState<MemberFilter>("all");
  const [sort, setSort] = useState<{ key: SortKey; descending: boolean } | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const actorScope = `${actorId}/${actorRole ?? ""}/${emailVerified}`;
  const [selection, setSelection] = useState<{ scope: string; ids: Set<string> }>(() => ({ scope: actorScope, ids: new Set() }));
  const selectedIds = selection.scope === actorScope ? selection.ids : new Set<string>();
  const reasonPrefix = useId();
  const { showDeviceCount } = rosterShape({ role: actorRole, isEnterprise: false });
  const roles = (member: Member) => member.roles ?? [member.role];
  const deviceCount = (member: Member) => deviceCountFor({ role: actorRole, devices, userId: member.user_id });
  const canEditRoles = (member: Member) => emailVerified && canManageMembership(actorRole, member.role, "") && HUMAN_ROLES.some(role => canManageMembership(actorRole, member.role, role));
  const hasRowActions = members.some(canEditRoles);
  // Role editing includes self. Account selection retains the separate non-self gate.
  const canSelect = members.some(member => emailVerified && member.user_id !== actorId && canManageMembership(actorRole, member.role, ""));
  const counts = {
    all: members.length,
    active: members.filter(member => member.status === "active").length,
    deactivated: members.filter(member => member.status === "deactivated").length,
  };

  const filteredMembers = useMemo(() => {
    const terms = query.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return members.filter(member => {
      if (filter !== "all" && member.status !== filter) return false;
      const count = deviceCountFor({ role: actorRole, devices, userId: member.user_id });
      const text = [member.name, member.email, ...(member.roles ?? [member.role]), member.status, member.email_verified ? "" : "email unverified", member.user_id === actorId ? "you" : "", showDeviceCount ? deviceCountLabel(count) : ""].join(" ").toLowerCase();
      return terms.every(term => text.includes(term));
    });
  }, [members, devices, query, filter, actorRole, actorId, showDeviceCount]);
  const orderedMembers = useMemo(() => {
    if (!sort) return filteredMembers;
    const sortValue = (member: Member) => {
      if (sort.key === "person") return `${member.name ?? ""} ${member.email}`;
      if (sort.key === "roles") return (member.roles ?? [member.role]).join(" + ");
      if (sort.key === "state") return `${member.status} ${member.email_verified ? "" : "email unverified"}`;
      const count = deviceCountFor({ role: actorRole, devices, userId: member.user_id });
      return count.kind === "count" ? String(count.n) : deviceCountLabel(count);
    };
    return [...filteredMembers].sort((a, b) => sortValue(a).localeCompare(sortValue(b), undefined, { numeric: true, sensitivity: "base" }) * (sort.descending ? -1 : 1));
  }, [filteredMembers, sort, actorRole, devices]);
  const lastPage = Math.max(1, Math.ceil(orderedMembers.length / pageSize));
  const currentPage = Math.min(page, lastPage);
  const pageMembers = orderedMembers.slice((currentPage - 1) * pageSize, currentPage * pageSize);
  const selectedMembers = canSelect ? members.filter(member => selectedIds.has(member.user_id)) : [];
  const pageSelected = pageMembers.length > 0 && pageMembers.every(member => selectedIds.has(member.user_id));
  const outsidePageCount = selectedMembers.filter(member => !pageMembers.some(visible => visible.user_id === member.user_id)).length;

  useEffect(() => { setPage(previous => Math.min(previous, lastPage)); }, [lastPage]);
  useEffect(() => {
    setSelection(previous => {
      if (previous.scope !== actorScope) return { scope: actorScope, ids: new Set() };
      const ids = new Set([...previous.ids].filter(id => members.some(member => member.user_id === id)));
      return previous.ids.size === ids.size ? previous : { scope: actorScope, ids };
    });
  }, [members, actorScope]);

  const unavailable = (member: Member, action: AccountAction) => {
    if (busy) return "Wait for the current member operation.";
    if (!emailVerified) return "Verify your email before managing members.";
    if (action === "deactivate" && member.user_id === actorId) return "You cannot deactivate your own account.";
    if (action === "reset" && member.user_id === actorId) return "Reset your own 2FA from your account settings.";
    if (!canManageMembership(actorRole, member.role, "")) return "You cannot manage this member's role.";
    if (action === "deactivate") {
      if (member.status !== "active") return "Already deactivated.";
      if (member.role === "owner" && ownerCount <= 1) return "An organization must always have at least one owner.";
    }
    if (action === "reactivate" && member.status === "active") return "Already active.";
    return null;
  };
  const requestAction = (action: AccountAction, targets: Member[]) => {
    if (busy || !emailVerified || (action === "reset" && targets.length !== 1)) return;
    // Resolve targets from the current roster before handing them to the page's confirmation.
    const eligible = targets.map(target => members.find(member => member.user_id === target.user_id)).filter((member): member is Member => !!member && !unavailable(member, action));
    if (eligible.length) onRequestAction(action, eligible);
  };
  const updateSelection = (update: (ids: Set<string>) => Set<string>) => setSelection(previous => ({ scope: actorScope, ids: update(previous.scope === actorScope ? previous.ids : new Set()) }));
  const clearFilters = () => { setQuery(""); setFilter("all"); setPage(1); };
  const sortColumn = (key: SortKey) => { setSort(previous => ({ key, descending: previous?.key === key ? !previous.descending : false })); setPage(1); };
  const columnHeader = (key: SortKey, label: string) => <th key={key} data-column={key} scope="col" aria-sort={sort?.key === key ? sort.descending ? "descending" : "ascending" : "none"}><button type="button" onClick={() => sortColumn(key)}>{label}{sort?.key === key && <span aria-hidden="true">{sort.descending ? " ↓" : " ↑"}</span>}</button></th>;

  return <section className="users-roster-inventory" data-view={view} aria-label={view === "roles" ? "Role assignments" : "User inventory"}>
    <div className="ur-inventory-toolbar">
      <Input type="search" aria-label="Filter Members" placeholder="Search people, email or roles…" value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} />
      <nav className="ur-filter-tabs" aria-label="Member status filters">{([ ["all", "All"], ["active", "Active"], ["deactivated", "Deactivated"] ] as Array<[MemberFilter, string]>).map(([key, label]) => <button key={key} type="button" aria-pressed={filter === key} onClick={() => { setFilter(key); setPage(1); }}>{label} <span>({counts[key]})</span></button>)}</nav>
      <span className="ur-result-count">{query.trim() ? `${filteredMembers.length} matching` : `${filteredMembers.length} ${filteredMembers.length === 1 ? "person" : "people"}`}</span>
    </div>

    {selectedMembers.length > 0 && <div className="ur-selection" role="group" aria-label="Selected member actions">
      <div className="ur-selection-summary"><strong>{selectedMembers.length} selected</strong>{outsidePageCount > 0 && <span>{outsidePageCount} outside this page</span>}<Button size="sm" variant="ghost" disabled={busy} onClick={() => updateSelection(() => new Set())}>Clear</Button>{pageSelected && filteredMembers.length > pageMembers.length && <Button size="sm" variant="ghost" disabled={busy} onClick={() => updateSelection(() => new Set(filteredMembers.map(member => member.user_id)))}>Select all {filteredMembers.length} matching</Button>}</div>
      <div className="ur-selection-actions">{(["deactivate", "reactivate", "reset"] as const).map(action => {
        const eligible = selectedMembers.filter(member => !unavailable(member, action));
        const singleRequired = action === "reset" && selectedMembers.length !== 1;
        const reason = singleRequired ? "Select one person to reset 2FA." : selectedMembers.map(member => unavailable(member, action)).find(Boolean);
        const partial = !singleRequired && eligible.length > 0 && eligible.length < selectedMembers.length;
        const reasonId = `${reasonPrefix}-${action}-reason`;
        return <div key={action}>{partial && <span>{eligible.length} of {selectedMembers.length}</span>}<Button size="sm" variant="ghost" disabled={busy || eligible.length === 0 || singleRequired} title={reason ?? undefined} aria-describedby={reason ? reasonId : undefined} onClick={() => requestAction(action, eligible)}>{accountActionLabel[action]}</Button>{reason && <span id={reasonId} className="sr-only">{partial ? `${eligible.length} of ${selectedMembers.length} selected members are eligible. ` : ""}{reason}</span>}</div>;
      })}</div>
    </div>}

    {pageMembers.length > 0 ? <div className="ur-table-scroll"><table className="ur-members-table" data-devices={showDeviceCount || undefined}><caption className="sr-only">Members</caption><thead><tr>
      {canSelect && <th className="ur-select"><input type="checkbox" aria-label={`Select all ${pageMembers.length} on this page`} disabled={busy} checked={pageSelected} ref={element => { if (element) element.indeterminate = !pageSelected && pageMembers.some(member => selectedIds.has(member.user_id)); }} onChange={event => { const checked = event.target.checked; updateSelection(previous => { const next = new Set(previous); pageMembers.forEach(member => { if (checked) next.add(member.user_id); else next.delete(member.user_id); }); return next; }); }} /></th>}
      {columnHeader("person", "Member")}{columnHeader("roles", "Roles")}{columnHeader("state", "State")}{showDeviceCount && columnHeader("devices", "Devices")}{hasRowActions && <th className="ur-actions"><span className="sr-only">Actions</span></th>}
    </tr></thead><tbody>{pageMembers.map(member => {
      const primary = member.name?.trim() || member.email;
      const count = deviceCount(member);
      return <tr key={member.user_id} data-selected={canSelect && selectedIds.has(member.user_id) || undefined}>
        {canSelect && <td className="ur-select"><input type="checkbox" aria-label={`Select ${member.email}`} disabled={busy} checked={selectedIds.has(member.user_id)} onChange={event => { const checked = event.target.checked; updateSelection(previous => { const next = new Set(previous); if (checked) next.add(member.user_id); else next.delete(member.user_id); return next; }); }} /></td>}
        <td data-column="person"><div className="ur-person"><button type="button" className="ur-person-name" disabled={busy} onClick={() => onInspect(member.user_id, view === "roles" ? "roles" : "overview")}>{primary}</button>{member.user_id === actorId && <span className="ur-self">(you)</span>}</div>{primary !== member.email && <span className="ur-email">{member.email}</span>}</td>
        <td data-column="roles"><span className="ur-roles">{roles(member).join(" + ")}</span></td>
        <td data-column="state"><span className="ur-member-state" data-state={member.status === "active" && !member.email_verified ? "unverified" : member.status}>{member.status === "deactivated" ? "Deactivated" : !member.email_verified ? "Email unverified" : "Active"}</span>{member.status === "deactivated" && !member.email_verified && <span className="ur-unverified">Email unverified</span>}</td>
        {showDeviceCount && <td data-column="devices"><span className={count.kind === "count" ? "ur-device-count" : "ur-device-unknown"} aria-label={count.kind === "count" ? deviceCountLabel(count) : undefined}>{count.kind === "count" ? count.n : deviceCountLabel(count)}</span></td>}
        {hasRowActions && <td className="ur-actions">{canEditRoles(member) && <AppAccessRowMenu label={`User actions for ${member.email}`} actions={[
          { key: "roles", label: "Edit roles", disabledReason: busy ? "Wait for the current member operation." : null, onSelect: () => { if (!busy && canEditRoles(member)) onInspect(member.user_id, "roles"); } },
          ...(member.user_id === actorId ? [] : ([member.status === "active" ? "deactivate" : "reactivate", "reset"] as AccountAction[]).map(action => ({ key: action, label: accountActionLabel[action], danger: action === "deactivate" || action === "reset", disabledReason: unavailable(member, action), onSelect: () => requestAction(action, [member]) }))),
        ]} />}</td>}
      </tr>;
    })}</tbody></table></div> : <AppAccessEmptyState icon={null} title={query.trim() ? "No people match this search." : filter === "active" ? "No active accounts." : filter === "deactivated" ? "No deactivated accounts." : "No members yet."} description={query.trim() || filter !== "all" ? "Try another search or view all accounts." : "People who join your organization will appear here."} action={query.trim() || filter !== "all" ? <Button size="sm" variant="ghost" onClick={clearFilters}>Clear filters</Button> : undefined} />}
    <AppAccessPagination page={currentPage} pageSize={pageSize} count={pageMembers.length} hasNext={currentPage < lastPage} maxOffset={null} busy={busy} previousLabel="Previous members page" nextLabel="Next members page" onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} />
  </section>;
}

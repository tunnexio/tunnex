import { useEffect, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input, Loading, Select } from "./ui";
type Subject = components["schemas"]["AppAccessGrantSubjects"]["items"][number];
export default function AppAccessSubjectPicker({ orgId, appId, label, usersOnly = false, value, onChange }: { orgId: string; appId: string; label: string; usersOnly?: boolean; value: Subject | null; onChange: (subject: Subject | null) => void }) {
  const [search, setSearch] = useState(""); const [kind, setKind] = useState<"user" | "group">("user"); const [page, setPage] = useState(0);
  const [items, setItems] = useState<Subject[] | null>(null); const [error, setError] = useState(""); const [reload, setReload] = useState(0);
  useEffect(() => {
    let cancelled = false; setItems(null); setError("");
    const timeout = window.setTimeout(() => { void api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/grant-subjects", { params: { path: { orgId, appId }, query: { kind, search, limit: 20, offset: page * 20 } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load eligible users and groups."));
      else setItems(result.data.items);
    }).catch(() => { if (!cancelled) setError("Could not reach eligible users and groups."); }); }, 150);
    return () => { cancelled = true; window.clearTimeout(timeout); };
  }, [orgId, appId, search, kind, page, reload]);
  const options = value && !items?.some(item => item.id === value.id && item.kind === value.kind) ? [value, ...(items ?? [])] : items ?? [];
  return <div className="space-y-3">{!usersOnly && <Field label="Subject type"><Select value={kind} onChange={event => { setKind(event.target.value as typeof kind); setPage(0); onChange(null); }}><option value="user">User</option><option value="group">Group</option></Select></Field>}<Field label={`Search ${usersOnly || kind === "user" ? "users" : "groups"}`}><Input maxLength={100} value={search} onChange={event => { setSearch(event.target.value); setPage(0); }} /></Field><Field label={label}><Select value={value ? `${value.kind}:${value.id}` : ""} onChange={event => onChange(options.find(item => `${item.kind}:${item.id}` === event.target.value) ?? null)}><option value="">Select {usersOnly ? "a user" : "a subject"}</option>{options.map(item => <option key={`${item.kind}:${item.id}`} value={`${item.kind}:${item.id}`}>{item.name || item.email || item.id}{item.email && item.name ? ` · ${item.email}` : ""}</option>)}</Select></Field>{error ? <div><ErrorText>{error}</ErrorText><Button type="button" variant="ghost" onClick={() => setReload(value => value + 1)}>Retry subjects</Button></div> : !items ? <Loading label="Loading eligible subjects…" /> : <div className="flex items-center gap-3"><Button type="button" size="sm" variant="ghost" disabled={page === 0} onClick={() => setPage(value => value - 1)}>Previous subjects</Button><span className="text-xs">Page {page + 1}</span><Button type="button" size="sm" variant="ghost" disabled={items.length < 20 || page >= 500} onClick={() => setPage(value => value + 1)}>More subjects</Button></div>}</div>;
}

import { useState, type ReactNode } from "react";
import { Button, Input } from "./ui";

/** Bounded lists keep network details usable as the inventory grows. */
export function NetworkDetailList<T>({ label, items, searchText, renderItem }: { label: string; items: T[]; searchText: (item: T) => string; renderItem: (item: T) => ReactNode }) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(0);
  const filtered = items.filter(item => searchText(item).toLowerCase().includes(query.trim().toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / 5));
  const current = Math.min(page, pages - 1);
  return <div className="network-detail-list">
    {(items.length > 5 || query) && <Input aria-label={`Search ${label}`} placeholder={`Search ${label.toLowerCase()}…`} value={query} onChange={event => { setQuery(event.target.value); setPage(0); }} />}
    {filtered.length ? <ul aria-label={label}>{filtered.slice(current * 5, current * 5 + 5).map(renderItem)}</ul> : <p className="py-4 text-xs text-ink-secondary">No matches. Clear the search to see all items.</p>}
    {filtered.length > 5 && <div className="network-detail-pagination"><span>{current * 5 + 1}–{Math.min(current * 5 + 5, filtered.length)} of {filtered.length}</span><div><Button size="sm" variant="ghost" disabled={current === 0} onClick={() => setPage(current - 1)} aria-label={`Previous ${label.toLowerCase()}`}>Previous</Button><Button size="sm" variant="ghost" disabled={current + 1 === pages} onClick={() => setPage(current + 1)} aria-label={`Next ${label.toLowerCase()}`}>Next</Button></div></div>}
  </div>;
}

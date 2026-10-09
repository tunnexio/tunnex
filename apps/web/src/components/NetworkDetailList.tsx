import { useState, type ReactNode } from "react";
import { Input } from "./ui";
import AppAccessPagination from "./AppAccessPagination";

/** Bounded lists keep network details usable as the inventory grows. */
export function NetworkDetailList<T>({ label, items, searchText, renderItem }: { label: string; items: T[]; searchText: (item: T) => string; renderItem: (item: T) => ReactNode }) {
  const [query, setQuery] = useState("");
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(20);
  const filtered = items.filter(item => searchText(item).toLowerCase().includes(query.trim().toLowerCase()));
  const pages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const current = Math.min(page, pages);
  const visible = filtered.slice((current - 1) * pageSize, current * pageSize);
  return <div className="network-detail-list">
    {(items.length > 10 || query) && <Input aria-label={`Search ${label}`} placeholder={`Search ${label.toLowerCase()}…`} value={query} onChange={event => { setQuery(event.target.value); setPage(1); }} />}
    {filtered.length ? <ul aria-label={label}>{visible.map(renderItem)}</ul> : <p className="py-4 text-xs text-ink-secondary">No matches. Clear the search to see all items.</p>}
    <AppAccessPagination maxOffset={null} page={current} pageSize={pageSize} count={visible.length} hasNext={current < pages} onPageChange={setPage} onPageSizeChange={size => { setPageSize(size); setPage(1); }} previousLabel={`Previous ${label.toLowerCase()}`} nextLabel={`Next ${label.toLowerCase()}`} />
  </div>;
}

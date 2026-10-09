import { Button, Select } from "./ui";
import { Icon } from "./Icon";

export const appAccessPageSizes = [10, 20, 50] as const;
export function appAccessPageSize(value: string | null) {
  const parsed = Number(value);
  return appAccessPageSizes.includes(parsed as typeof appAccessPageSizes[number]) ? parsed : 20;
}

export default function AppAccessPagination({ page, pageSize, count, hasNext, busy = false, maxOffset = 10000, firstItem, onPageChange, onPageSizeChange, previousLabel = "Previous page", nextLabel = "Next page" }: {
  page: number; pageSize: number; count: number; hasNext: boolean; busy?: boolean;
  /** Preserve bounded API pagination by default; loaded local arrays can opt out. */
  maxOffset?: number | null;
  /** Cursor pages can be short; use the actual count of preceding cached rows. */
  firstItem?: number;
  onPageChange: (page: number) => void; onPageSizeChange: (size: number) => void;
  previousLabel?: string; nextLabel?: string;
}) {
  const hasOtherPages = page > 1 || hasNext;
  if (!hasOtherPages && count <= appAccessPageSizes[0]) return null;
  const first = firstItem ?? (page - 1) * pageSize + 1;
  const maxPage = maxOffset === null ? Infinity : Math.floor(maxOffset / pageSize) + 1;
  return <nav className="aa-pagination" aria-label="Table pagination">
    <span className="aa-pagination-count">{count ? `${first}–${first + count - 1} shown` : "0 results"}</span>
    <div className="aa-pagination-controls">
      <span>Rows per page</span><Select aria-label="Rows per page" width="auto" value={String(pageSize)} disabled={busy} onChange={event => onPageSizeChange(Number(event.target.value))}>{appAccessPageSizes.map(size => <option key={size} value={size}>{size}</option>)}</Select>
      {hasOtherPages && <><span className="aa-pagination-page">Page {page}</span>
        <Button variant="ghost" aria-label={previousLabel} title={previousLabel} disabled={busy || page <= 1} onClick={() => onPageChange(page - 1)}><Icon name="chevron-right" size={16} className="aa-pagination-previous" /></Button>
        <Button variant="ghost" aria-label={nextLabel} title={nextLabel} disabled={busy || !hasNext || page >= maxPage} onClick={() => onPageChange(page + 1)}><Icon name="chevron-right" size={16} /></Button>
      </>}
    </div>
  </nav>;
}

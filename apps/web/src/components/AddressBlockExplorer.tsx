import { useState } from "react";
import type { BlockMap } from "../lib/routedrangesview";
import "../address-block-explorer.css";
const ip = (n: number) =>
  [24, 16, 8, 0].map((shift) => (n >>> shift) & 255).join(".");
const states = {
  approved: "Routed",
  pending: "Pending approval",
  pool: "Device pool",
  vip: "Cluster VIP",
};
export function AddressBlockExplorer({
  map,
  complete,
}: {
  map: BlockMap;
  complete: boolean;
}) {
  const groupSize = 16;
  const [group, setGroup] = useState(() =>
    Math.floor((map.lit[0]?.index ?? 0) / groupSize),
  );
  const [cell, setCell] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const currentGroup = Math.min(
    group,
    Math.ceil(map.block.cells / groupSize) - 1,
  );
  const chosen =
    cell === null ? undefined : map.lit.find((c) => c.index === cell);
  const cidr = (index: number) =>
    `${ip(map.block.base + index * 2 ** (32 - map.block.cellPrefix))}/${map.block.cellPrefix}`;
  const items = chosen?.allocs ?? [];
  const summary = `${map.counts.approved} routed · ${map.counts.pending} pending · ${map.counts.pool} pool · ${map.counts.vip} cluster VIP`;
  return (
    <div
      className="address-explorer"
      role="group"
      aria-label={`${map.block.label} address space: ${summary}, ${(map.utilised * 100).toFixed(1)}% of /${map.block.prefix} routed`}
    >
      <div className="address-explorer-heading">
        <strong>{map.block.label}</strong>
        <span>{(map.claimed * 100).toFixed(1)}% allocated</span>
      </div>
      <p className="address-explorer-summary">{summary}</p>
      <p className="address-group-label">
        Block groups · /{map.block.cellPrefix}
      </p>
      <div className="address-overview" aria-label="Address groups">
        {Array.from(
          { length: Math.ceil(map.block.cells / groupSize) },
          (_, index) => {
            const occupied = map.lit.filter(
              (c) => Math.floor(c.index / groupSize) === index,
            ).length;
            return (
              <button
                key={index}
                data-occupied={occupied > 0}
                aria-label={`Explore ${cidr(index * groupSize)} through ${cidr(Math.min((index + 1) * groupSize - 1, map.block.cells - 1))}, ${occupied} occupied blocks`}
                aria-pressed={currentGroup === index}
                onClick={() => {
                  setGroup(index);
                  setCell(null);
                  setPage(0);
                }}
              >
                <span>
                  {index * groupSize}–
                  {Math.min((index + 1) * groupSize - 1, map.block.cells - 1)}
                </span>
                <i style={{ width: `${(occupied / groupSize) * 100}%` }} />
                <small>
                  {occupied
                    ? `${occupied} occupied`
                    : complete
                      ? "Empty"
                      : "Not verified"}
                </small>
              </button>
            );
          },
        )}
      </div>
      <div className="address-zoom-heading">
        <span>
          {cidr(currentGroup * groupSize)} —{" "}
          {cidr(
            Math.min((currentGroup + 1) * groupSize - 1, map.block.cells - 1),
          )}
        </span>
        <small>Select a block to inspect</small>
      </div>
      <div className="address-zoom">
        {Array.from(
          {
            length: Math.min(
              groupSize,
              map.block.cells - currentGroup * groupSize,
            ),
          },
          (_, offset) => {
            const index = currentGroup * groupSize + offset;
            const data = map.lit.find((c) => c.index === index);
            return (
              <button
                key={index}
                aria-pressed={cell === index}
                aria-label={`${cidr(index)}, ${data ? `${data.allocs.length} allocations` : complete ? "No recorded allocation" : "Not verified"}`}
                data-occupied={!!data}
                onClick={() => {
                  setCell(index);
                  setPage(0);
                }}
              >
                <strong>{cidr(index)}</strong>
                <small>
                  {data
                    ? `${data.allocs.length} allocation${data.allocs.length === 1 ? "" : "s"}`
                    : complete
                      ? "Empty"
                      : "Not verified"}
                </small>
                <span className="address-state-dots" aria-hidden="true">
                  {Array.from(new Set(data?.allocs.map((a) => a.kind))).map(
                    (kind) => (
                      <i key={kind} data-kind={kind} />
                    ),
                  )}
                </span>
              </button>
            );
          },
        )}
      </div>
      {cell !== null && (
        <section
          className="address-cell-details"
          aria-label={`Allocations in ${cidr(cell)}`}
        >
          <h4>{cidr(cell)}</h4>
          {!items.length ? (
            <p>
              {complete
                ? "No recorded allocation in this block. Availability is validated again when creating a route."
                : "Allocation data is incomplete. This block is not confirmed free."}
            </p>
          ) : (
            <>
              <ul>
                {items.slice(page * 8, page * 8 + 8).map((a, index) => (
                  <li key={`${a.cidr}:${a.kind}:${index}`}>
                    <span>
                      <strong>{a.cidr}</strong>
                      <small>{a.label}</small>
                    </span>
                    <span data-kind={a.kind}>{states[a.kind]}</span>
                  </li>
                ))}
              </ul>
              {items.length > 8 && (
                <div className="address-pages">
                  <button
                    disabled={page === 0}
                    onClick={() => setPage(page - 1)}
                  >
                    Previous
                  </button>
                  <span>
                    {page * 8 + 1}–{Math.min(page * 8 + 8, items.length)} of{" "}
                    {items.length}
                  </span>
                  <button
                    disabled={(page + 1) * 8 >= items.length}
                    onClick={() => setPage(page + 1)}
                  >
                    Next
                  </button>
                </div>
              )}
            </>
          )}
        </section>
      )}
    </div>
  );
}

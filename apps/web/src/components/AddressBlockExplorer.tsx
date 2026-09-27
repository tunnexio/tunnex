import { useRef, useState } from "react";
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
  const [cell, setCell] = useState<number | null>(null);
  const [page, setPage] = useState(0);
  const [focus, setFocus] = useState(0);
  const [hover, setHover] = useState<number | null>(null);
  const tiles = useRef<Array<HTMLButtonElement | null>>([]);
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
      <p className="sr-only">{summary}</p>
      <div className="address-map-caption"><span>Each tile = /{map.block.cellPrefix} · colored tiles contain allocations</span><span>{hover !== null ? cidr(hover) : "Select a tile"}</span></div>
      <div className="address-tiles" aria-label="Address blocks">
        {Array.from({length:map.block.cells},(_, index)=>{
          const data=map.lit.find(c=>c.index===index);
          const kinds=Array.from(new Set(data?.allocs.map(a=>a.kind)));
          const label=`${cidr(index)}, ${data ? `${data.allocs.length} allocations` : complete ? "No recorded allocation" : "Not verified"}`;
          return <button key={index} ref={el=>{tiles.current[index]=el;}} type="button" tabIndex={focus===index ? 0 : -1}
            aria-label={label} title={label} aria-pressed={cell===index} data-kind={kinds.length>1 ? "mixed" : kinds[0] ?? "empty"}
            onMouseEnter={()=>setHover(index)} onMouseLeave={()=>setHover(null)} onFocus={()=>{setFocus(index);setHover(index);}}
            onClick={()=>{setCell(index);setPage(0);}}
            onKeyDown={event=>{
              const columns=window.matchMedia("(max-width:600px)").matches ? 16 : 32;
              const offset=event.key==="ArrowRight" ? 1 : event.key==="ArrowLeft" ? -1 : event.key==="ArrowDown" ? columns : event.key==="ArrowUp" ? -columns : 0;
              if(offset || event.key==="Home" || event.key==="End") {
                event.preventDefault();
                const next=event.key==="Home" ? 0 : event.key==="End" ? map.block.cells-1 : Math.max(0,Math.min(map.block.cells-1,index+offset));
                tiles.current[next]?.focus();
              }
            }}><span className="sr-only">{label}</span></button>;
        })}
      </div>
      <div className="address-map-legend">{[["approved","Published"],["pending","Pending"],["pool","Device pool"],["vip","Kubernetes"],["mixed","Mixed"],["empty",complete ? "Unallocated" : "Unverified"]].map(([kind,label])=><span key={kind}><i data-kind={kind}/>{label}</span>)}</div>
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

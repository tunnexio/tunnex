import { RoutingPath } from "./RoutingPath";
import {Fragment,useMemo,useState} from "react";
import {Link} from "react-router-dom";
import type {Allocation,RangeRow,SubnetFetch} from "../lib/routedrangesview";
import type {DNSForward,Site} from "../lib/api";
import "../routing-explorer.css";
const labels={approved:"Published",pending:"Pending approval",pool:"Device pool",vip:"Cluster VIP"};
export function RoutingExplorer({allocations,rows,sites,fanOut,complete,initialFilter="all"}:{allocations:Allocation[];rows:RangeRow[];sites:Site[];fanOut:SubnetFetch[]|null;forwards:DNSForward[];complete:boolean;initialFilter?:string}) {
 const [page,setPage]=useState(0); const [query,setQuery]=useState("");const [filter,setFilter]=useState(initialFilter);const [selected,setSelected]=useState("");
 const entries=useMemo(()=>allocations.map((allocation,index)=>{
  const attribution=rows.find(row=>row.range===allocation.cidr)?.attribution;
  const siteId=allocation.kind==="approved" && attribution?.kind==="site" ? attribution.siteId : allocation.kind==="pending" ? fanOut?.find(f=>f.ok && f.subnets.some(s=>s.cidr===allocation.cidr && s.status==="pending"))?.siteId : undefined;
  const owner=siteId ? sites.find(s=>s.id===siteId)?.name || allocation.label : allocation.kind==="pool" || allocation.kind==="vip" ? "Reserved address space" : "Network not identified";
  return {...allocation,siteId,owner,key:`${allocation.kind}:${allocation.cidr}:${index}`};
 }),[allocations,rows,sites,fanOut]);
 const visible=entries.filter(entry=>(filter==="all"||entry.kind===filter)&&`${entry.cidr} ${entry.owner} ${entry.label}`.toLowerCase().includes(query.toLowerCase().trim()));
 const currentPage=Math.min(page,Math.max(0,Math.ceil(visible.length/12)-1));
 const paged=visible.slice(currentPage*12,currentPage*12+12);
 const groups=Array.from(new Set(paged.map(entry=>entry.owner)));
 const active=visible.find(entry=>entry.key===selected);
 const pendingCount=entries.filter(entry=>entry.kind==="pending").length;
 const details = active && <aside className="routing-inspector" aria-label="Range details"><button className="routing-detail-close" aria-label="Close range details" onClick={()=>setSelected("")}>×</button>
    <RoutingPath key={active.key} kind={active.kind} destination={active.siteId ? active.owner : "Network not identified"} range={active.cidr} />
    <details className="route-more"><summary>Details & next steps</summary><dl><dt>Owner</dt><dd>{active.owner}</dd><dt>Routing</dt><dd>{active.kind==="approved" ? "Published to split-tunnel devices" : active.kind==="pending" ? "Withheld until approved" : "Reserved allocation; not a published route by itself"}</dd></dl>
    <div className="routing-context"><strong>{active.kind==="pending" ? "Before you approve" : active.kind==="approved" ? "If the destination cannot be reached" : "Why this is reserved"}</strong><p>{active.kind==="pending" ? "Confirm that this range belongs to the intended network and does not overlap another location. Approval publishes it to devices; access policies still control access." : active.kind==="approved" ? "This route is advertised, but reachability is not tested here. Check the site's gateway status, then the access policy for the device or user." : active.kind==="pool" ? "These addresses are assigned to devices. Keep them separate from the ranges used by your networks." : "These addresses are reserved for Kubernetes services. Avoid assigning them to another network."}</p></div></details>
    {active.siteId && <Link to={`/sites?site=${encodeURIComponent(active.siteId)}${active.kind==="pending" ? "&section=approvals":""}`}>{active.kind==="pending" ? "Review approvals":"Open site"} →</Link>}
    {!active.siteId && active.kind==="approved" && <small className="routing-owner-note">Network ownership unavailable</small>}
    {active.kind==="pool" && <Link to="/devices">View devices →</Link>}{active.kind==="vip" && <Link to="/kubernetes">View Kubernetes →</Link>}
  </aside>;
 return <div className="routing-explorer">
  {pendingCount > 0 && filter!=="pending" && <button className="routing-attention" onClick={()=>{setFilter("pending");setQuery("");setPage(0);setSelected("");}}><span><strong>{pendingCount} {pendingCount===1 ? "range needs" : "ranges need"} approval</strong></span><span>Review <span aria-hidden="true">→</span></span></button>}

  <div className="routing-explorer-tools"><input aria-label="Search routing graph" placeholder="Find a range or site…" value={query} onChange={e=>{setQuery(e.target.value);setPage(0);}} /><select aria-label="Filter routing graph" value={filter} onChange={e=>{setFilter(e.target.value);setPage(0);}}><option value="all">All allocations</option>{Object.entries(labels).map(([kind,label])=><option key={kind} value={kind}>{label}</option>)}</select><span>{visible.length} of {entries.length}</span></div>
  {!complete && <p className="text-warn text-sm">Some allocation data is unavailable or still loading. This view may be incomplete.</p>}
  <div className="routing-explorer-layout"><div className="routing-explorer-canvas" role="group" aria-label="Routing graph">
   {!visible.length && <p className="text-ink-secondary">{entries.length ? "No matching ranges. Try another search or filter." : "No allocations available yet."}</p>}
   {groups.map(group=><section className="routing-branch" key={group} aria-label={group}><div className="routing-owner"><span>{group}</span><small>{visible.filter(e=>e.owner===group).length} {visible.filter(e=>e.owner===group).length===1 ? "range" : "ranges"}</small></div><div className="routing-branch-ranges">{paged.filter(e=>e.owner===group).map(entry=><Fragment key={entry.key}><button aria-pressed={active?.key===entry.key} onClick={()=>setSelected(entry.key)} className="routing-range-node" data-kind={entry.kind}><span><strong>{entry.cidr}</strong><small>{labels[entry.kind]}</small></span><span aria-hidden="true">→</span></button>{active?.key===entry.key && details}</Fragment>)}</div></section>)}
  </div></div>
  {visible.length > 12 && <div className="routing-pages"><span>{currentPage*12+1}–{Math.min(currentPage*12+12,visible.length)} of {visible.length}</span><div><button disabled={currentPage===0} onClick={()=>setPage(currentPage-1)}>Previous</button><button disabled={(currentPage+1)*12>=visible.length} onClick={()=>setPage(currentPage+1)}>Next</button></div></div>}

 </div>;
}

import {useMemo,useState} from "react";
import {Link} from "react-router-dom";
import type {Allocation,RangeRow,SubnetFetch} from "../lib/routedrangesview";
import type {DNSForward,Site} from "../lib/api";
import "../routing-explorer.css";
const labels={approved:"Routed",pending:"Pending approval",pool:"Device pool",vip:"Cluster VIP"};
export function RoutingExplorer({allocations,rows,sites,fanOut,forwards,complete}:{allocations:Allocation[];rows:RangeRow[];sites:Site[];fanOut:SubnetFetch[]|null;forwards:DNSForward[];complete:boolean}) {
 const [query,setQuery]=useState("");const [filter,setFilter]=useState("all");const [selected,setSelected]=useState("");
 const entries=useMemo(()=>allocations.map((allocation,index)=>{
  const attribution=rows.find(row=>row.range===allocation.cidr)?.attribution;
  const siteId=allocation.kind==="approved" && attribution?.kind==="site" ? attribution.siteId : allocation.kind==="pending" ? fanOut?.find(f=>f.ok && f.subnets.some(s=>s.cidr===allocation.cidr && s.status==="pending"))?.siteId : undefined;
  const owner=siteId ? sites.find(s=>s.id===siteId)?.name || allocation.label : allocation.kind==="pool" || allocation.kind==="vip" ? "Reserved address space" : "Unattributed ranges";
  return {...allocation,siteId,owner,key:`${allocation.kind}:${allocation.cidr}:${index}`};
 }),[allocations,rows,sites,fanOut]);
 const visible=entries.filter(entry=>(filter==="all"||entry.kind===filter)&&`${entry.cidr} ${entry.owner} ${entry.label}`.toLowerCase().includes(query.toLowerCase().trim()));
 const groups=Array.from(new Set(visible.map(entry=>entry.owner)));
 const active=visible.find(entry=>entry.key===selected);
 return <div className="routing-explorer">
  <div className="routing-explorer-tools"><input aria-label="Search routing graph" placeholder="Find a range or site…" value={query} onChange={e=>setQuery(e.target.value)} /><select aria-label="Filter routing graph" value={filter} onChange={e=>setFilter(e.target.value)}><option value="all">All allocations</option>{Object.entries(labels).map(([kind,label])=><option key={kind} value={kind}>{label}</option>)}</select><span>{visible.length} of {entries.length}</span></div>
  {!complete && <p className="text-warn text-sm">Some allocation data is unavailable or still loading. This view may be incomplete.</p>}
  <div className="routing-explorer-layout"><div className="routing-explorer-canvas" role="group" aria-label="Routing graph">
   {!visible.length && <p className="text-ink-secondary">{entries.length ? "No matching ranges. Try another search or filter." : "No allocations available yet."}</p>}
   {groups.map(group=><section className="routing-branch" key={group} aria-label={group}><div className="routing-owner"><span>{group}</span><small>{visible.filter(e=>e.owner===group).length} allocations</small></div><div className="routing-branch-ranges">{visible.filter(e=>e.owner===group).map(entry=><button key={entry.key} aria-pressed={active?.key===entry.key} onClick={()=>setSelected(entry.key)} className="routing-range-node" data-kind={entry.kind}><span><strong>{entry.cidr}</strong><small>{labels[entry.kind]}</small></span><span aria-hidden="true">→</span></button>)}</div></section>)}
  </div><aside className="routing-inspector" aria-label="Range details">{active ? <>
    <span className="routing-inspector-label">Selected range</span><h3>{active.cidr}</h3><p data-kind={active.kind}>{labels[active.kind]}</p>
    <dl><dt>Owner</dt><dd>{active.owner}</dd><dt>Routing</dt><dd>{active.kind==="approved" ? "Published to split-tunnel devices" : active.kind==="pending" ? "Withheld until approved" : "Reserved allocation; not a published route by itself"}</dd></dl>
    {active.siteId && <Link to={`/sites?site=${encodeURIComponent(active.siteId)}${active.kind==="pending" ? "&section=approvals":""}`}>{active.kind==="pending" ? "Review approvals":"Open site"} →</Link>}
    {!active.siteId && active.kind==="approved" && <p className="text-sm text-ink-secondary">{active.label}. The routing endpoint publishes this range even when its site cannot be identified.</p>}
    {active.kind==="pool" && <Link to="/devices">View devices →</Link>}{active.kind==="vip" && <Link to="/kubernetes">View Kubernetes →</Link>}
  </> : <><span className="routing-inspector-label">Inspect your network</span><h3>Select a range</h3><p>See its owner, routing state, and next action here.</p></>}
  <div className="routing-inspector-note">Connections show ownership, not live traffic. {forwards.length} DNS forwards are listed below.</div></aside></div>
 </div>;
}

import { useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import type { Member, UserGroup } from "../lib/api";
import { Badge, Button, DataTable, Field, Input, Modal, Select } from "./ui";
import AppAccessRowMenu from "./AppAccessRowMenu";
import AppAccessEmptyState from "./AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "./AppAccessPagination";
import { Icon } from "./Icon";
import { ResourceSummary } from "./ResourceSummary";
type Grant=components["schemas"]["ServerAccessGrant"];
type Server=components["schemas"]["ServerAccessServer"];
type InputGrant=components["schemas"]["ServerAccessGrantInput"];
export function ServerAccountGrants({grants,servers,members,groups,disabled,onRevoke,onRenew,onRenewDismiss,verification}:{grants:Grant[];servers:Server[];members:Member[];groups:UserGroup[];disabled:boolean;onRevoke:(id:string)=>void;onRenew:(body:InputGrant,done:()=>void)=>Promise<void>;onRenewDismiss?:()=>void;verification?:React.ReactNode}){
 const [renew,setRenew]=useState<Grant>();const [hours,setHours]=useState(1);
 const [search,setSearch]=useState("");const [status,setStatus]=useState("all");const [page,setPage]=useState(1);const [pageSize,setPageSize]=useState(20);
 const now=Date.now();
 // Keep the latest enabled grant for each account and recipient before filtering or pagination.
 const latest=new Map<string,Grant>();
 for(const grant of grants){if(!grant.enabled||Date.parse(grant.starts_at)>now||!servers.some(server=>server.id===grant.server_id))continue;const key=JSON.stringify([grant.server_id,grant.account,grant.user_id,grant.group_id]);const previous=latest.get(key);if(!previous||Date.parse(grant.expires_at)>Date.parse(previous.expires_at))latest.set(key,grant)}
 const subject=(grant:Grant)=>grant.user_id?members.find(member=>member.user_id===grant.user_id)?.email??grant.user_id:groups.find(group=>group.id===grant.group_id)?.name??grant.group_id??"Unavailable recipient";
 const serverName=(grant:Grant)=>servers.find(server=>server.id===grant.server_id)?.name??"Removed server";
 const rows=[...latest.values()].sort((a,b)=>Number(Date.parse(a.expires_at)<=now)-Number(Date.parse(b.expires_at)<=now)).filter(grant=>(status==="all"||status==="expired"&&Date.parse(grant.expires_at)<=now||status==="active"&&Date.parse(grant.expires_at)>now)&&[serverName(grant),grant.account,subject(grant)].join(" ").toLowerCase().includes(search.trim().toLowerCase()));
 const current=Math.min(page,Math.max(1,Math.ceil(rows.length/pageSize)));const visible=rows.slice((current-1)*pageSize,current*pageSize);
 const clear=()=>{setSearch("");setStatus("all");setPage(1)};
 const closeRenew=()=>{if(disabled)return;setRenew(undefined);onRenewDismiss?.()};
 return <section className="sa-grants" aria-label="Account access">
  <div className="sa-list-heading"><h2>Account grants</h2></div>
  <div className="sa-list-toolbar"><Input aria-label="Search account grants" placeholder="Search account access…" value={search} onChange={event=>{setSearch(event.target.value);setPage(1)}}/><Select aria-label="Account grant status" width="auto" value={status} onChange={event=>{setStatus(event.target.value);setPage(1)}}><option value="all">All access</option><option value="active">Active</option><option value="expired">Expired</option></Select></div>
  {!rows.length?<AppAccessEmptyState icon="users" title={search||status!=="all"?"No matching grants":"No active or expired grants"} description={search||status!=="all"?"Try another search or clear the filters.":"Grant account access from a server's Access step."} action={search||status!=="all"?<Button variant="ghost" onClick={clear}>Clear access filters</Button>:<Link className="text-brand" to="/browser-access/terminal">View servers</Link>}/>:<div className="sa-table sa-grants-table"><DataTable caption="Account grants" rows={visible} rowKey={grant=>grant.id} rowLabel={subject} pageSize={0} filterable={false} failed={false} empty={null} columns={[
   {key:"server",header:"Server",cell:grant=><div className="sa-grant-identity"><p>{serverName(grant)}</p><span>{grant.account}</span></div>},
   {key:"subject",header:"User or group",cell:grant=><div className="sa-grant-subject"><p>{subject(grant)}</p><span>{grant.user_id?"Person":"Group"}</span></div>},
   {key:"status",header:"Status",cell:grant=><Badge tone={Date.parse(grant.expires_at)<=now?"warn":"ok"}>{Date.parse(grant.expires_at)<=now?"Expired":"Active"}</Badge>},
   {key:"expires",header:"Expires",cell:grant=><time dateTime={grant.expires_at}>{new Date(grant.expires_at).toLocaleString()}</time>},
   {key:"actions",header:"Actions",cell:grant=><AppAccessRowMenu label={`Grant actions for ${subject(grant)} · ${grant.account} on ${serverName(grant)}`} actions={[Date.parse(grant.expires_at)<=now?{key:"extend",label:"Extend access",icon:<Icon name="clock-3" size={16}/>,disabledReason:disabled?"Wait for the current action to finish.":null,onSelect:()=>{setHours(1);setRenew(grant)}}:{key:"revoke",label:"Revoke access",danger:true,icon:<Icon name="ban" size={16}/>,disabledReason:disabled?"Wait for the current action to finish.":null,onSelect:()=>onRevoke(grant.id)}]}/>}
  ]}/></div>}
  <AppAccessPagination page={current} pageSize={pageSize} count={visible.length} hasNext={current*pageSize<rows.length} busy={disabled} onPageChange={setPage} onPageSizeChange={size=>{setPageSize(appAccessPageSize(String(size)));setPage(1)}} previousLabel="Previous account grants" nextLabel="Next account grants"/>
  {renew&&<Modal title="Extend access" placement="right" showClose onDismiss={closeRenew}><form className="sa-grant-form" onSubmit={event=>{event.preventDefault();if(disabled||!Number.isFinite(hours)||hours<1||hours>168)return;void onRenew({server_id:renew.server_id,account:renew.account,...(renew.user_id?{user_id:renew.user_id}:{group_id:renew.group_id!}),starts_at:new Date().toISOString(),expires_at:new Date(Date.now()+hours*3600000).toISOString()},()=>setRenew(undefined))}}><ResourceSummary title="Access context"><dl className="sa-dialog-summary tnx-resource-facts"><div><dt>Server</dt><dd>{serverName(renew)}</dd></div><div><dt>Account</dt><dd>{renew.account}</dd></div><div className="tnx-resource-fact-wide"><dt>Recipient</dt><dd>{subject(renew)}</dd></div></dl></ResourceSummary><Field label="Extend duration (hours)"><Input autoFocus required type="number" min={1} max={168} value={hours} onChange={event=>setHours(Number(event.target.value))}/></Field><div className="sa-form-actions"><Button type="button" variant="ghost" disabled={disabled} onClick={closeRenew}>Cancel</Button><Button type="submit" disabled={disabled||!Number.isFinite(hours)||hours<1||hours>168}>Confirm extension</Button></div></form>{verification}</Modal>}
 </section>
}

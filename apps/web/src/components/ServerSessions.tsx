import { useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import type { Member } from "../lib/api";
import { Badge, Button, DataTable, Input, Modal, Select, RefreshButton } from "./ui";
import AppAccessRowMenu, { type AppAccessRowMenuAction } from "./AppAccessRowMenu";
import AppAccessEmptyState from "./AppAccessEmptyState";
import AppAccessPagination, { appAccessPageSize } from "./AppAccessPagination";
import { ResourceSummary } from "./ResourceSummary";
import { Icon } from "./Icon";
type Session=components["schemas"]["ServerAccessSession"];
type Server=components["schemas"]["ServerAccessServer"];
const live=(session:Session)=>["pending","connecting","connected"].includes(session.status);
export function ServerSessions({sessions,servers,members,disabled,onRefresh,onEnd,onReplay,importControl}:{sessions:Session[];servers:Server[];members:Member[];disabled:boolean;onRefresh:()=>void;onEnd:(id:string)=>void;onReplay:(id:string)=>void;importControl:React.ReactNode}){
 const [filter,setFilter]=useState("sessions");const [page,setPage]=useState(1);const [pageSize,setPageSize]=useState(20);const [search,setSearch]=useState("");const [details,setDetails]=useState<Session>();
 const serverName=(session:Session)=>servers.find(server=>server.id===session.server_id)?.name??"Removed server";
 const userName=(session:Session)=>members.find(member=>member.user_id===session.user_id)?.email??session.user_id.slice(0,8);
 const rows=sessions.filter(session=>(filter==="checks"?session.kind==="check":(session.kind==="terminal"||session.kind==="editor")&&(filter==="active"?live(session):filter==="ended"?!live(session):true))&&[session.id,serverName(session),userName(session),session.account].join(" ").toLowerCase().includes(search.trim().toLowerCase()));
 const current=Math.min(page,Math.max(1,Math.ceil(rows.length/pageSize)));const visible=rows.slice((current-1)*pageSize,current*pageSize);
 const actions=(session:Session):AppAccessRowMenuAction[]=>[
  ...(session.kind==="terminal"&&session.recording_enabled?[{key:"replay",label:"Replay",icon:<Icon name="terminal" size={16}/>,onSelect:()=>onReplay(session.id)}]:[]),
  ...(live(session)?[{key:"end",label:"End session",danger:true,icon:<Icon name="ban" size={16}/>,disabledReason:disabled?"Wait for the current action to finish.":null,onSelect:()=>onEnd(session.id)}]:[]),
  {key:"events",label:"Session events",icon:<Icon name="scroll-text" size={16}/>,href:`/audit?target_type=server_access&target_id=${session.id}`},
  ...(session.reason?[{key:"details",label:"Details",icon:<Icon name="circle-alert" size={16}/>,onSelect:()=>setDetails(session)}]:[])
 ];
 return <section className="sa-sessions" aria-label="Server sessions">
  <div className="sa-list-heading"><h3>Server sessions</h3><RefreshButton label="Refresh sessions" disabled={disabled} onClick={onRefresh} /></div>
  <div className="sa-list-toolbar"><Input aria-label="Search sessions" placeholder="Search sessions…" value={search} onChange={event=>{setSearch(event.target.value);setPage(1)}}/><Select aria-label="Session view" width="auto" value={filter} onChange={event=>{setFilter(event.target.value);setPage(1)}}><option value="sessions">All sessions</option><option value="active">Active sessions</option><option value="ended">Ended sessions</option><option value="checks">Connection checks</option></Select><details className="sa-import"><summary>Import recording</summary><div>{importControl}</div></details></div>
  {!rows.length?<AppAccessEmptyState icon={filter==="checks"?"shield-check":"terminal"} title={search?"No matching sessions":filter==="checks"?"No connection checks":filter==="active"?"No active sessions":filter==="ended"?"No ended sessions":"No server sessions"} description={search?"Try another search.":filter==="checks"?"Checks appear after you test a server account.":"Connect to a server account to start a session."} action={search?<Button variant="ghost" onClick={()=>{setSearch("");setPage(1)}}>Clear session search</Button>:<Link className="text-brand" to="/browser-access/terminal">View servers</Link>}/>:<div className="sa-table sa-session-table"><DataTable caption="Server sessions" rows={visible} rowKey={session=>session.id} rowLabel={session=>`${serverName(session)} · ${session.account}`} pageSize={0} filterable={false} failed={false} empty={null} columns={[
   {key:"server",header:"Server",cell:session=><div className="sa-session-identity"><p title={session.server_id}>{serverName(session)}</p><span>{session.account} · <span title={session.id}>{session.id.slice(0,8)}</span></span>{session.kind==="editor"&&<span>Developer · Recording off</span>}</div>},
   {key:"user",header:"User",cell:session=><span title={session.user_id}>{userName(session)}</span>},
   {key:"status",header:"Status",cell:session=><Badge tone={session.status==="connected"||session.status==="passed"?"ok":session.status==="failed"?"warn":undefined}>{session.status.charAt(0).toUpperCase()+session.status.slice(1)}</Badge>},
   {key:"expires",header:"Expires",cell:session=><time dateTime={session.expires_at}>{new Date(session.expires_at).toLocaleString()}</time>},
   {key:"actions",header:"Actions",cell:session=><AppAccessRowMenu label={`Session actions for ${session.id.slice(0,8)}`} actions={actions(session)}/>}
  ]}/></div>}
  <AppAccessPagination page={current} pageSize={pageSize} count={visible.length} hasNext={current*pageSize<rows.length} busy={disabled} onPageChange={setPage} onPageSizeChange={size=>{setPageSize(appAccessPageSize(String(size)));setPage(1)}} previousLabel="Previous sessions" nextLabel="Next sessions"/>
  {details&&<Modal title="Session details" placement="right" showClose onDismiss={()=>setDetails(undefined)}><ResourceSummary title="Session information"><dl className="sa-dialog-summary tnx-resource-facts"><div><dt>Server</dt><dd>{serverName(details)}</dd></div><div><dt>Account</dt><dd>{details.account}</dd></div><div><dt>Status</dt><dd>{details.status}</dd></div><div className="tnx-resource-fact-wide"><dt>Reason</dt><dd>{details.reason.replace(/_/g," ")}</dd></div><div className="tnx-resource-fact-wide"><dt>Session</dt><dd className="font-mono">{details.id}</dd></div></dl></ResourceSummary></Modal>}
 </section>
}

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
import { sessionReasonText } from "../lib/serverAccessReasons";
import { personLabel } from "../lib/personLabel";
type Session=components["schemas"]["ServerAccessSession"];
type Server=components["schemas"]["ServerAccessServer"];
const live=(session:Session)=>["pending","connecting","connected"].includes(session.status);
const replayable=(session:Session)=>session.kind==="terminal"&&session.recording_enabled;

/** SA-UX-2 R1: what the recording state of a session is, in words. */
export function recordingLabel(session:Session):string{
 if(session.kind==="check")return "Not applicable";
 if(session.kind==="editor")return "Developer · Recording off";
 return session.recording_enabled?"Recorded":"Not recorded";
}
const statusLabel=(status:string)=>({pending:"Starting",connecting:"Connecting",connected:"Connected",ended:"Ended",passed:"Passed",failed:"Failed"} as Record<string,string>)[status]??"Unknown";

/** Human duration such as "12 min" or "1 h 5 min". */
export function sessionDuration(session:Session):string{
 if(!session.created_at||!session.ended_at)return "";
 const seconds=Math.max(0,Math.round((Date.parse(session.ended_at)-Date.parse(session.created_at))/1000));
 if(seconds<60)return `${seconds} s`;
 const minutes=Math.round(seconds/60);
 return minutes<60?`${minutes} min`:`${Math.floor(minutes/60)} h ${minutes%60} min`;
}
const auditHref=(session:Session)=>`/audit?target_type=server_access&target_id=${session.id}`;

export function ServerSessions({sessions,servers,members,disabled,onRefresh,onEnd,onReplay,importControl}:{sessions:Session[];servers:Server[];members:Member[];disabled:boolean;onRefresh:()=>void;onEnd:(id:string)=>void;onReplay:(id:string)=>void;importControl:React.ReactNode}){
 const [filter,setFilter]=useState("sessions");const [page,setPage]=useState(1);const [pageSize,setPageSize]=useState(20);const [search,setSearch]=useState("");const [details,setDetails]=useState<Session>();
 const serverName=(session:Session)=>servers.find(server=>server.id===session.server_id)?.name??"Removed server";
 const userName=(session:Session)=>personLabel(members.find(member=>member.user_id===session.user_id),`Former member (${session.user_id.slice(0,8)})`);
 const rows=sessions.filter(session=>(filter==="checks"?session.kind==="check":(session.kind==="terminal"||session.kind==="editor")&&(filter==="active"?live(session):filter==="ended"?!live(session):true))&&[session.id,serverName(session),userName(session),session.account].join(" ").toLowerCase().includes(search.trim().toLowerCase()));
 const current=Math.min(page,Math.max(1,Math.ceil(rows.length/pageSize)));const visible=rows.slice((current-1)*pageSize,current*pageSize);
 const actions=(session:Session):AppAccessRowMenuAction[]=>[
  {key:"details",label:"Details",icon:<Icon name="circle-alert" size={16}/>,onSelect:()=>setDetails(session)},
  ...(replayable(session)?[{key:"replay",label:"Replay",icon:<Icon name="terminal" size={16}/>,onSelect:()=>onReplay(session.id)}]:[]),
  ...(live(session)?[{key:"end",label:"End session",danger:true,icon:<Icon name="ban" size={16}/>,disabledReason:disabled?"Wait for the current action to finish.":null,onSelect:()=>onEnd(session.id)}]:[]),
  {key:"events",label:"Audit events for this session",icon:<Icon name="scroll-text" size={16}/>,href:auditHref(session)},
 ];
 return <section className="sa-sessions" aria-label="Server sessions">
  <div className="sa-list-heading"><h3>Server sessions</h3><RefreshButton label="Refresh sessions" disabled={disabled} onClick={onRefresh} /></div>
  <div className="sa-list-toolbar"><Input aria-label="Search sessions" placeholder="Search sessions…" value={search} onChange={event=>{setSearch(event.target.value);setPage(1)}}/><Select aria-label="Session view" width="auto" value={filter} onChange={event=>{setFilter(event.target.value);setPage(1)}}><option value="sessions">All sessions</option><option value="active">Active sessions</option><option value="ended">Ended sessions</option><option value="checks">Connection checks</option></Select><details className="sa-import"><summary>Import recording</summary><div>{importControl}</div></details></div>
  {!rows.length?<AppAccessEmptyState icon={filter==="checks"?"shield-check":"terminal"} title={search?"No matching sessions":filter==="checks"?"No connection checks":filter==="active"?"No active sessions":filter==="ended"?"No ended sessions":"No server sessions"} description={search?"Try another search.":filter==="checks"?"Checks appear after you test a server account.":"Connect to a server account to start a session."} action={search?<Button variant="ghost" onClick={()=>{setSearch("");setPage(1)}}>Clear session search</Button>:<Link className="text-brand" to="/browser-access/terminal">View servers</Link>}/>:<div className="sa-table sa-session-table"><DataTable caption="Server sessions" rows={visible} rowKey={session=>session.id} rowLabel={session=>`${serverName(session)} · ${session.account}`} pageSize={0} filterable={false} failed={false} empty={null} columns={[
   {key:"server",header:"Server",cell:session=><div className="sa-session-identity"><p title={session.server_id}>{serverName(session)}</p><span>{session.account} · <span title={session.id}>{session.id.slice(0,8)}</span></span></div>},
   {key:"user",header:"User",cell:session=><span title={session.user_id}>{userName(session)}</span>},
   {key:"status",header:"Status",cell:session=><Badge tone={session.status==="connected"||session.status==="passed"?"ok":session.status==="failed"?"warn":undefined}>{statusLabel(session.status)}</Badge>},
   {key:"recording",header:"Recording",cell:session=><span>{recordingLabel(session)}</span>},
   {key:"started",header:"Started",cell:session=>session.created_at?<time dateTime={session.created_at}>{new Date(session.created_at).toLocaleString()}</time>:<span>Not reported</span>},
   {key:"time",header:"Duration or expiry",cell:session=>live(session)?<span>Expires <time dateTime={session.expires_at}>{new Date(session.expires_at).toLocaleString()}</time></span>:<span>{sessionDuration(session)||"Ended"}</span>},
   {key:"actions",header:"Actions",cell:session=><div className="flex items-center gap-2">{replayable(session)&&<Button variant="ghost" onClick={()=>onReplay(session.id)}>Replay</Button>}<AppAccessRowMenu label={`Session actions for ${session.id.slice(0,8)}`} actions={actions(session)}/></div>}
  ]}/></div>}
  <AppAccessPagination page={current} pageSize={pageSize} count={visible.length} hasNext={current*pageSize<rows.length} busy={disabled} onPageChange={setPage} onPageSizeChange={size=>{setPageSize(appAccessPageSize(String(size)));setPage(1)}} previousLabel="Previous sessions" nextLabel="Next sessions"/>
  {details&&<Modal title="Session details" placement="right" showClose onDismiss={()=>setDetails(undefined)}><ResourceSummary title="Session information"><dl className="sa-dialog-summary tnx-resource-facts"><div><dt>Server</dt><dd>{serverName(details)}</dd></div><div><dt>Account</dt><dd>{details.account}</dd></div><div><dt>User</dt><dd>{userName(details)}</dd></div><div><dt>Status</dt><dd>{statusLabel(details.status)}</dd></div>{details.created_at&&<div><dt>Started</dt><dd>{new Date(details.created_at).toLocaleString()}</dd></div>}{details.ended_at&&<div><dt>Ended</dt><dd>{new Date(details.ended_at).toLocaleString()} ({sessionDuration(details)})</dd></div>}<div><dt>Recording</dt><dd>{recordingLabel(details)}</dd></div>{details.reason&&<div className="tnx-resource-fact-wide"><dt>Reason</dt><dd>{sessionReasonText(details.reason)}</dd></div>}<div className="tnx-resource-fact-wide"><dt>Session</dt><dd className="font-mono">{details.id}</dd></div></dl>
   <div className="mt-3 flex flex-wrap gap-3">{replayable(details)&&<Button onClick={()=>{const id=details.id;setDetails(undefined);onReplay(id)}}>Replay recording</Button>}<Link className="text-brand" to={auditHref(details)}>Audit events for this session</Link></div></ResourceSummary></Modal>}
 </section>
}

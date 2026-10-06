import { useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import type { Member } from "../lib/api";
import { Badge, Button, Card, DataTable, Field, Select } from "./ui";
type Session=components["schemas"]["ServerAccessSession"];
type Server=components["schemas"]["ServerAccessServer"];
const live=(s:Session)=>["pending","connecting","connected"].includes(s.status);
export function ServerSessions({sessions,servers,members,disabled,onRefresh,onEnd,onReplay,importControl}:{sessions:Session[];servers:Server[];members:Member[];disabled:boolean;onRefresh:()=>void;onEnd:(id:string)=>void;onReplay:(id:string)=>void;importControl:React.ReactNode}){
 const [filter,setFilter]=useState("sessions");const [page,setPage]=useState(1);
 const rows=sessions.filter(s=>filter==="checks"?s.kind==="check":(s.kind==="terminal"||s.kind==="editor")&&(filter==="active"?live(s):filter==="ended"?!live(s):true));
 const pages=Math.max(1,Math.ceil(rows.length/20));const current=Math.min(page,pages);
 return <Card className="space-y-4"><div className="app-access-panel-header"><div><h3 className="text-lg font-semibold">Server sessions</h3><p className="text-sm text-ink-secondary">Review sessions and recordings, or end active access.</p></div><Button variant="ghost" disabled={disabled} onClick={onRefresh}>Refresh sessions</Button></div><div className="flex flex-wrap items-start justify-between gap-3"><Field label="Session view"><Select value={filter} onChange={e=>{setFilter(e.target.value);setPage(1)}}><option value="sessions">All sessions</option><option value="active">Active sessions</option><option value="ended">Ended sessions</option><option value="checks">Connection checks</option></Select></Field><details className="text-sm"><summary className="cursor-pointer text-ink-secondary">Import recording</summary><div className="mt-3 max-w-xl space-y-3">{importControl}</div></details></div><div className="app-access-inventory-table"><DataTable caption="Server sessions" rows={rows.slice((current-1)*20,current*20)} rowKey={s=>s.id} filterable={false} failed={false} empty="No sessions in this view." columns={[
 {key:"session",header:"Session",cell:s=><span className="font-mono" title={s.id}>{s.id.slice(0,8)}</span>},
 {key:"server",header:"Server",cell:s=>servers.find(v=>v.id===s.server_id)?.name??<span title={s.server_id}>Removed server</span>},
 {key:"user",header:"User",cell:s=>members.find(m=>m.user_id===s.user_id)?.email??<span title={s.user_id}>{s.user_id.slice(0,8)}</span>},
 {key:"account",header:"Account",cell:s=><span>{s.account}{s.kind==="editor"&&<span className="block text-xs text-ink-secondary">Developer · Recording off</span>}</span>},
 {key:"status",header:"Status",cell:s=><Badge tone={s.status==="connected"||s.status==="passed"?"ok":s.status==="failed"?"warn":undefined}>{s.status.charAt(0).toUpperCase()+s.status.slice(1)}</Badge>},
 {key:"expires",header:"Expires",cell:s=><time dateTime={s.expires_at}>{new Date(s.expires_at).toLocaleString()}</time>},
 {key:"actions",header:"Actions",cell:s=><div className="flex flex-wrap items-center gap-3">{s.kind==="terminal"&&s.recording_enabled&&<Button variant="ghost" size="sm" onClick={()=>onReplay(s.id)}>Replay</Button>}{live(s)&&<Button variant="ghost" size="sm" disabled={disabled} onClick={()=>onEnd(s.id)}>End session</Button>}<Link className="text-brand text-sm" to={`/audit?target_type=server_access&target_id=${s.id}`}>Session events</Link>{s.reason&&<details className="text-sm"><summary className="cursor-pointer text-ink-secondary">Details</summary><p>{s.reason.replace(/_/g," ")}</p></details>}</div>}
 ]}/></div><div className="app-access-pagination flex flex-wrap items-center gap-3"><Button variant="ghost" disabled={disabled||current===1} onClick={()=>setPage(current-1)}>Previous sessions</Button><span>Page {current}</span><Button variant="ghost" disabled={disabled||current===pages} onClick={()=>setPage(current+1)}>Next sessions</Button></div></Card>
}

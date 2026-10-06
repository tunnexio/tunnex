import { useState } from "react";
import type { components } from "@tunnex/shared";
import type { Member, UserGroup } from "../lib/api";
import { Badge, Button, Card, DataTable, Field, Input } from "./ui";
type Grant=components["schemas"]["ServerAccessGrant"];
type Server=components["schemas"]["ServerAccessServer"];
type InputGrant=components["schemas"]["ServerAccessGrantInput"];
export function ServerAccountGrants({grants,servers,members,groups,disabled,onRevoke,onRenew,verification}:{grants:Grant[];servers:Server[];members:Member[];groups:UserGroup[];disabled:boolean;onRevoke:(id:string)=>void;onRenew:(body:InputGrant,done:()=>void)=>Promise<void>;verification?:React.ReactNode}){
 const [renew,setRenew]=useState<Grant>();const [hours,setHours]=useState(1);
 const now=Date.now();
 // Keep the latest enabled grant for each account and recipient; renewal retains audit history.
 const latest=new Map<string,Grant>();
 for(const g of grants){if(!g.enabled||Date.parse(g.starts_at)>now||!servers.some(s=>s.id===g.server_id))continue;const key=JSON.stringify([g.server_id,g.account,g.user_id,g.group_id]);const previous=latest.get(key);if(!previous||Date.parse(g.expires_at)>Date.parse(previous.expires_at))latest.set(key,g)}
 const rows=[...latest.values()].sort((a,b)=>Number(Date.parse(a.expires_at)<=now)-Number(Date.parse(b.expires_at)<=now));
 const subject=(g:Grant)=>g.user_id?members.find(m=>m.user_id===g.user_id)?.email??g.user_id:groups.find(v=>v.id===g.group_id)?.name??g.group_id;
 return <Card className="space-y-3"><h2>Account grants</h2><p>Manage active and expired access.</p><DataTable caption="Account grants" rows={rows} rowKey={g=>g.id} filterable={false} failed={false} empty="No active or expired access." columns={[
 {key:"server",header:"Server",cell:g=>servers.find(s=>s.id===g.server_id)?.name},
 {key:"account",header:"Account",cell:g=>g.account},
 {key:"subject",header:"User or group",cell:subject},
 {key:"expires",header:"Expires",cell:g=><time dateTime={g.expires_at}>{new Date(g.expires_at).toLocaleString()}</time>},
 {key:"status",header:"Status",cell:g=><Badge tone={Date.parse(g.expires_at)<=now?"warn":"ok"}>{Date.parse(g.expires_at)<=now?"Expired":"Active"}</Badge>},
 {key:"actions",header:"Actions",cell:g=>Date.parse(g.expires_at)<=now?<Button variant="ghost" disabled={disabled} onClick={()=>{setHours(1);setRenew(g)}}>Extend access</Button>:<Button variant="ghost" disabled={disabled} onClick={()=>onRevoke(g.id)}>Revoke access</Button>}
 ]}/>{renew&&<form className="space-y-3 rounded-xl border border-white/10 p-4" onSubmit={e=>{e.preventDefault();if(!Number.isFinite(hours)||hours<1||hours>168)return;void onRenew({server_id:renew.server_id,account:renew.account,...(renew.user_id?{user_id:renew.user_id}:{group_id:renew.group_id!}),starts_at:new Date().toISOString(),expires_at:new Date(Date.now()+hours*3600000).toISOString()},()=>setRenew(undefined))}}><h3>Extend access · {renew.account}</h3><p>{servers.find(s=>s.id===renew.server_id)?.name} · {subject(renew)}</p><Field label="Extend duration (hours)"><Input autoFocus required type="number" min={1} max={168} value={hours} onChange={e=>setHours(Number(e.target.value))}/></Field><div className="flex gap-2"><Button type="submit" disabled={disabled}>Confirm extension</Button><Button type="button" variant="ghost" disabled={disabled} onClick={()=>setRenew(undefined)}>Cancel</Button></div></form>}{renew&&verification}</Card>
}

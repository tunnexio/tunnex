import { useEffect, useState } from "react";
import { useSearchParams } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { AuthLayout } from "../components/AuthLayout";
import { Button, ErrorText } from "../components/ui";
import { InlineTerminalMfa } from "../components/InlineTerminalMfa";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { editorCallback } from "../lib/editorAccess";
export default function EditorAuth(){
 const [params]=useSearchParams();const [workspace,setWorkspace]=useState<components["schemas"]["ServerAccessWorkspace"]>();const [error,setError]=useState("");const [busy,setBusy]=useState(false);const [mfa,setMfa]=useState(false);
 const org=params.get("org")??"",serverId=params.get("server")??"",account=params.get("account")??"",publicKey=params.get("public_key")??"",challenge=params.get("code_challenge")??"",state=params.get("state")??"";
 const callback=editorCallback(params.get("redirect_uri")??"");const valid=!!callback&&/^[A-Za-z0-9_-]{43}$/.test(state)&&/^[A-Za-z0-9_-]{43}$/.test(challenge)&&publicKey.length<=4096;
 useEffect(()=>{if(!valid)return;let live=true;void api.GET("/api/v1/organizations/{orgId}/server-access",{params:{path:{orgId:org}}}).then(r=>{if(!live)return;if(r.data)setWorkspace(r.data);else setError(apiErrorMessage(r.error,"Could not load editor access."))}).catch(()=>{if(live)setError("Could not reach the control plane.")});return()=>{live=false}},[org,valid]);
 const server=workspace?.servers.find(s=>s.id===serverId&&s.accounts.includes(account));
 async function approve(){if(busy||!callback||!valid)return;setBusy(true);setError("");try{const r=await api.POST("/api/v1/organizations/{orgId}/server-access/sessions/editor",{params:{path:{orgId:org}},body:{server_id:serverId,account,public_key:publicKey,code_challenge:challenge}});if(!r.data||r.error){if(apiErrorCode(r.error)==="mfa_required"){setMfa(true);return};setError(apiErrorMessage(r.error,"Editor access was refused."));return}callback.searchParams.set("code",r.data.code);callback.searchParams.set("state",state);window.location.assign(callback.toString());}catch{setError("Could not reach the control plane.")}finally{setBusy(false)}}
 return <AuthLayout><div className="space-y-4"><h1 className="text-xl font-semibold">Connect with local VS Code</h1>{!valid?<ErrorText>Invalid editor request. Run the Tunnex command again.</ErrorText>:<><p>{server?.name??"Loading server…"} · {account}</p><p className="text-sm text-ink-secondary">Tunnex CLI · Recording off</p><p className="text-xs text-ink-secondary">Approve the local CLI at {callback!.host}. Access ends when your grant or session expires.</p><ErrorText>{error}</ErrorText><Button disabled={busy||!server?.developer_access_enabled||!server.enabled||!server.ready_accounts.includes(account)} onClick={()=>void approve()}>{busy?"Approving…":"Approve editor access"}</Button>{server&&!server.developer_access_enabled&&<ErrorText>Ask your admin to enable local VS Code access (CLI) for this server.</ErrorText>}{mfa&&<InlineTerminalMfa action={`Open ${server?.name??"server"} in VS Code`} freshnessSeconds={workspace?.mfa_freshness_seconds} onCancel={()=>setMfa(false)} onVerified={async()=>{setMfa(false);await approve()}}/>}</>}</div></AuthLayout>
}

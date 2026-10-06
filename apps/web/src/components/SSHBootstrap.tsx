import { useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { bootstrapBundle, parseBootstrapResult, type BootstrapResult } from "../lib/sshBootstrap";
import { Button, ErrorText, Field, Input } from "./ui";
type Server = components["schemas"]["ServerAccessServer"];
export function SSHBootstrap({orgId,server,disabled,onSave}:{orgId:string;server:Server;disabled:boolean;onSave:(accounts:string[],fingerprint:string)=>Promise<void>}) {
 const [busy,setBusy]=useState(false);const [error,setError]=useState("");const [result,setResult]=useState<BootstrapResult>();const [pasted,setPasted]=useState("");const [selected,setSelected]=useState(server.accounts.join(","));
 const file=`tunnex-ssh-bootstrap-${server.id}.py`;
 async function download(){setBusy(true);setError("");try{
  const trust=await api.GET("/api/v1/organizations/{orgId}/server-access/trust",{params:{path:{orgId}}});
  if(!trust.data)throw new Error(apiErrorMessage(trust.error,"Could not load the public SSH CA."));
  const response=await fetch("/tunnex-browser-ssh.py",{credentials:"same-origin"});if(!response.ok)throw new Error("Could not load the SSH helper.");
  const source=await bootstrapBundle(await response.text(),trust.data.public_key,orgId,server,trust.data.ca_fingerprint??"");
  const url=URL.createObjectURL(new Blob([source],{type:"text/x-python;charset=utf-8"}));const link=document.createElement("a");link.href=url;link.download=file;link.click();setTimeout(()=>URL.revokeObjectURL(url),1000);
 }catch(e){setError(e instanceof Error?e.message:"Could not create bootstrap bundle.")}finally{setBusy(false)}}
 return <details className="rounded border border-white/10 p-4 space-y-3"><summary className="cursor-pointer font-semibold">Quick SSH bootstrap</summary>
 <p>Configure eligible Linux login users in one run. Public CA trust and this server identity are included. Root, system and non-login users are excluded. No Tunnex member receives access until an administrator grants it.</p>
 <Button disabled={disabled||busy} onClick={()=>void download()}>Download server bootstrap</Button>
 <ol className="list-decimal pl-5 space-y-2"><li>Review the downloaded bundle and copy it to this machine over your trusted management SSH connection.</li><li>Run on the target machine for all eligible existing login users:</li></ol>
 <pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{`sudo python3 ${file} bootstrap --all-login-users`}</pre>
 <Field label="Selected Linux users (alternative)"><Input value={selected} onChange={e=>setSelected(e.target.value)} placeholder="ubuntu,deploy"/></Field>
 {/^[a-z_][a-z0-9_-]{0,31}(,[a-z_][a-z0-9_-]{0,31})*$/.test(selected)&&<pre className="overflow-x-auto whitespace-pre-wrap break-all text-xs">{`sudo python3 ${file} bootstrap --accounts '${selected}'`}</pre>}
 <p>The helper reuses existing CA and host keys when this server is already configured. Later, run <code>sudo tunnex-browser-ssh sync-accounts --all-login-users</code> or <code>sudo tunnex-browser-ssh sync-accounts --accounts ubuntu,deploy</code>. Sync adds accounts and preserves existing configuration. Up to 16 accounts per server are supported.</p>
 <p>Paste the JSON printed between BEGIN/END TUNNEX SSH RESULT below, or copy /etc/tunnex-browser-ssh/setup-result.json back over the same trusted SSH connection and import it. Verify the fingerprint against the target output before saving. Saving changes requires new account checks; then enable the server and grant access.</p>
 <Field label="Import SSH bootstrap result"><input type="file" accept=".json,application/json" disabled={disabled||busy} onChange={async e=>{const file=e.currentTarget.files?.[0];setResult(undefined);setError("");if(!file)return;try{if(file.size>65536)throw new Error("Bootstrap result is too large.");setResult(parseBootstrapResult(await file.text(),orgId,server))}catch(err){setError(err instanceof Error?err.message:"Invalid bootstrap result.")}}}/></Field>
 <Field label="Paste SSH bootstrap result"><textarea className="w-full rounded border border-white/10 bg-transparent p-3 font-mono text-xs" rows={4} maxLength={65536} value={pasted} onChange={e=>setPasted(e.target.value)} placeholder="Paste the result JSON printed on the target"/></Field><Button variant="ghost" disabled={disabled||busy||!pasted.trim()} onClick={()=>{setResult(undefined);setError("");try{setResult(parseBootstrapResult(pasted,orgId,server))}catch(e){setError(e instanceof Error?e.message:"Invalid bootstrap result.")}}}>Review pasted result</Button>
 {result&&<div className="space-y-2"><p>Discovered/configured accounts: <strong>{result.accounts.join(", ")}</strong></p><p className="break-all">Host fingerprint: <code>{result.host_fingerprint}</code></p><p>This saves server configuration. It does not create access grants.</p><Button disabled={disabled||busy} onClick={async()=>{setBusy(true);try{await onSave(result.accounts,result.host_fingerprint)}finally{setBusy(false)}}}>Save verified accounts and fingerprint</Button></div>}
 <ErrorText>{error}</ErrorText></details>;
}

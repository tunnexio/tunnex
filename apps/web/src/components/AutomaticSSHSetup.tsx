import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { InlineTerminalMfa } from "./InlineTerminalMfa";
import { MfaSettings } from "./MfaSettings";
import { FirewallHelp } from "./FirewallHelp";
import { useOptionalAuth } from "../lib/auth";
import type { Node } from "../lib/api";
import { Badge, Button, ErrorText, Field, Input, SettingRow, Switch } from "./ui";
type Server=components["schemas"]["ServerAccessServer"];
type Job=components["schemas"]["ServerAccessEnrollment"];
const terminalStates=new Set(["succeeded","failed","cancelled","expired"]);
export function AutomaticSSHSetup({orgId,server,gateway,disabled,onComplete,onMfa,mfaFreshnessSeconds=900}:{orgId:string;server:Server;gateway?:Node;disabled:boolean;onComplete:()=>void;onMfa:()=>void;mfaFreshnessSeconds?:number}){
 // SA-UX-2 item 3: a confirmed factor is reported as a recovery-code count (even 0).
 const auth=useOptionalAuth();const [mfaEnrolledNow,setMfaEnrolledNow]=useState(false);
 // Unknown (no signed-in user in context) is not treated as missing; the server still enforces MFA.
 const mfaEnrolled=mfaEnrolledNow||auth?.state.status!=="authed"||typeof auth.state.user.recovery_codes_remaining==="number";const [mfaSetupOpen,setMfaSetupOpen]=useState(false);
 const gatewayName=gateway?.name??"selected for this server";
 const [account,setAccount]=useState("ubuntu"),[port,setPort]=useState(22),[fingerprint,setFingerprint]=useState("");
 const [all,setAll]=useState(true),[accounts,setAccounts]=useState(server.accounts.join(","));
 const [job,setJob]=useState<Job>(),[busy,setBusy]=useState(false),[error,setError]=useState("");const command=useRef<HTMLTextAreaElement>(null);const completed=useRef<string>();
 const [needsMfa,setNeedsMfa]=useState(false);const retry=useRef<()=>Promise<void>>();
 const syncing=server.accounts.length>0;
 const path={orgId,serverId:server.id};
 function failure(value:unknown,fallback:string,retryAction?:()=>Promise<void>){if((value as {error?:{code?:string}})?.error?.code==="mfa_required"){setError("");retry.current=retryAction;setNeedsMfa(true);onMfa()}else setError(apiErrorMessage(value,fallback))}
 useEffect(()=>{if(!job||terminalStates.has(job.state))return;let live=true;const timer=setInterval(()=>{void api.GET("/api/v1/organizations/{orgId}/server-access/enrollments/{enrollmentId}",{params:{path:{orgId,enrollmentId:job.id}}}).then(r=>{if(!live)return;if(r.data){setJob(r.data);if(r.data.state==="succeeded"&&completed.current!==r.data.id){completed.current=r.data.id;onComplete()}}else failure(r.error,"Could not refresh setup status.")}).catch(()=>{if(live)setError("Could not reach the control plane; setup status is unconfirmed.")})},2000);return()=>{live=false;clearInterval(timer)}},[job?.id,job?.state,orgId,onComplete]);
 useEffect(()=>{let live=true;void api.GET("/api/v1/organizations/{orgId}/server-access/servers/{serverId}/enrollment",{params:{path:{orgId,serverId:server.id}}}).then(r=>{if(!live)return;if(r.data)setJob(r.data);else if(r.response.status!==404)failure(r.error,"Could not load the existing setup job.")}).catch(()=>{if(live)setError("Could not load setup status.")});return()=>{live=false}},[orgId,server.id]);
 const active=job&&!terminalStates.has(job.state);
 async function prepare(){setBusy(true);setError("");try{const r=await api.POST("/api/v1/organizations/{orgId}/server-access/servers/{serverId}/enrollment",{params:{path},body:{management_account:account,management_port:port,...(fingerprint.trim()?{management_fingerprint:fingerprint.trim()}:{}),accounts:all?[]:accounts.split(",").map(a=>a.trim()).filter(Boolean)}});if(r.data)setJob(r.data);else failure(r.error,"Could not prepare automatic setup.",prepare)}catch{setError("Could not reach the control plane.")}finally{setBusy(false)}}
 async function action(cancel=false){if(!job)return;setBusy(true);setError("");try{const opts={params:{path:{orgId,enrollmentId:job.id}}};const r=cancel?await api.DELETE("/api/v1/organizations/{orgId}/server-access/enrollments/{enrollmentId}",opts):await api.POST("/api/v1/organizations/{orgId}/server-access/enrollments/{enrollmentId}",opts);if(r.data)setJob(r.data);else failure(r.error,"Setup action was not confirmed.",()=>action(cancel))}catch{setError("Could not reach the control plane.")}finally{setBusy(false)}}

 const validTrust=/^SHA256:[A-Za-z0-9+/]{43}$/.test(fingerprint.trim());
 const blocked=disabled?"Wait for the current action to finish.":server.enabled&&!syncing?"Disable this server before initial SSH setup.":!account.trim()?"Enter a management SSH account.":fingerprint.trim()&&!validTrust?"The independently verified fingerprint must look like SHA256:… (43 characters), or leave it empty.":!mfaEnrolled?"Set up two-factor verification first (above).":!all&&!accounts.trim()?"Choose at least one Linux account.":"";
 const stage=!active?0:job?.state==="awaiting_authorization"?1:job?.state==="queued"||job?.state==="running"?2:0;
 const statusLabel=job?.state==="succeeded"?"Last run complete":job?.state==="awaiting_authorization"?"Authorization needed":job?.state==="running"||job?.state==="queued"?"In progress":job?.state==="preparing"?"Preparing":job?.state==="failed"?"Failed":job?.state==="expired"?"Expired":"Cancelled";
 return <section className="rounded-xl border border-white/10 p-4 sm:p-5 space-y-5" aria-label="Automatic gateway SSH setup">
 <div className="app-access-panel-header"><div><h3>{syncing?"Sync Linux accounts":"Set up browser SSH"}</h3><p className="max-w-prose">{syncing?"Discover new Linux accounts without interrupting existing access.":"Connect the gateway securely and discover this server’s Linux accounts."}</p></div>
 {job&&<Badge tone={job.state==="succeeded"?"ok":job.state==="failed"?"danger":job.state==="expired"?"warn":"neutral"}>{statusLabel}</Badge>}</div>
 <ol aria-label="SSH setup steps" className="grid gap-2 sm:grid-cols-3 text-sm">
 {["Verify server","Authorize gateway",syncing?"Sync accounts":"Configure SSH"].map((label,i)=><li key={label} aria-current={active&&stage===i?"step":undefined} className={`flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 ${stage===i?"text-ink-heading":"text-ink-secondary"}`}><span aria-hidden="true" className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-white/5 text-xs">{i+1}</span>{label}</li>)}
 </ol>
 {!active&&<div className="space-y-4">
 <div className="rounded-lg border border-white/10 p-3 text-sm space-y-2" aria-label="Before you start"><p className="font-medium text-ink-heading">Before you start</p>
 <p><strong>Network:</strong> the gateway {gatewayName} must reach {server.private_ip} on TCP {port} (management SSH, for setup) and on TCP {server.ssh_port} (browser terminal, afterwards).</p>
 <FirewallHelp gatewayName={gatewayName} host={server.private_ip??"SERVER_IP"} port={server.ssh_port??2222} summary="Firewall examples"/>
 <p><strong>Two-factor verification:</strong> {mfaEnrolled?"you will confirm a code from your authenticator app when you prepare setup.":"setting up a server needs it, and your account has none yet. Set it up here first."}</p>
 {!mfaEnrolled&&<details className="tnx-inline-mfa-setup" onToggle={e=>setMfaSetupOpen(e.currentTarget.open)}><summary className="cursor-pointer">Set up two-factor verification</summary>{mfaSetupOpen&&<MfaSettings setupLabel="Set up two-factor" onEnrolled={()=>setMfaEnrolledNow(true)} signInReturnTo="/browser-access/terminal"/>}</details>}
 <p><strong>A way to run one command on the server</strong> as an administrator (sudo).</p>
 <RunCommandHelp ip={server.private_ip??"SERVER_IP"}/></div>
 <div className="grid gap-4 sm:grid-cols-[minmax(0,1fr)_160px]">
 <Field label="Management SSH account"><Input value={account} onChange={e=>setAccount(e.target.value)}/></Field>
 <Field label="Management SSH port"><Input type="number" min={1} max={65535} value={port} onChange={e=>setPort(Number(e.target.value))}/></Field></div>
 <p className="text-xs text-ink-secondary max-w-prose">Server identity is verified automatically: the one-time authorization command you run on the server records its SSH host key, and Tunnex accepts the gateway's connection only if it presented that key.</p>
 <details className="text-sm text-ink-secondary" open={!!fingerprint}><summary className="cursor-pointer text-ink-body">Advanced: verify the host key independently</summary><div className="mt-2 space-y-2"><Field label="Verified management SSH fingerprint (optional)"><Input placeholder="SHA256:…" value={fingerprint} aria-describedby="management-fingerprint-help" onChange={e=>setFingerprint(e.target.value)}/></Field>
 <p id="management-fingerprint-help" className="text-xs">{!fingerprint.trim()?"Optional. When set, Tunnex pins this host key instead of verifying it automatically. Use it if the server's SSH host key is not in the default location, or if you prefer an independent check.":validTrust?"Fingerprint format accepted. The gateway will accept only this host key.":"Paste only SHA256:… from a trusted session on this server."}</p>
 <p className="text-xs">Run on {server.private_ip} through a trusted session:</p><pre className="rounded-lg bg-white/5 p-3 overflow-x-auto text-xs">sudo ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256</pre></div></details>
 <SettingRow label="Discover all eligible login users" description="Find existing and newly created Linux login accounts. Keep this on to discover all users."><Switch label="Discover all eligible login users" checked={all} onChange={setAll}/></SettingRow>
 {!all&&<Field label="Selected existing Linux accounts"><Input value={accounts} onChange={e=>setAccounts(e.target.value)} placeholder="ubuntu,deploy"/></Field>}
 <div className="flex flex-wrap items-center gap-3"><Button disabled={!!blocked||busy} onClick={()=>void prepare()}>{busy?"Preparing…":syncing?"Sync accounts":"Prepare automatic setup"}</Button><p className="text-xs text-ink-secondary">{blocked||"Recent MFA and a new one-time authorization are required."}</p></div>
 </div>}
 {needsMfa&&<InlineTerminalMfa action={syncing?"Sync accounts":"Prepare SSH setup"} freshnessSeconds={mfaFreshnessSeconds} onCancel={()=>{setNeedsMfa(false);retry.current=undefined}} onVerified={async()=>{setNeedsMfa(false);const next=retry.current;retry.current=undefined;await next?.()}}/>}
 {job&&<div className="rounded-lg bg-white/5 p-4 space-y-3" role="status">
 <p className="text-sm font-medium text-ink-heading">{active?"Current run":"Latest result"} · {statusLabel}</p><p className="max-w-prose text-sm text-ink-secondary">{job.message}</p>
 {active&&<p className="text-xs text-ink-secondary">Authorization expires: {new Date(job.expires_at).toLocaleString()}</p>}
 {job.state==="awaiting_authorization"&&<><p className="text-sm">Run this command on <strong>{server.private_ip}</strong>, then return here to continue.</p><textarea ref={command} aria-label="One-time SSH authorization command" className="w-full rounded-lg border border-white/10 bg-transparent p-3 font-mono text-xs" readOnly rows={3} value={job.authorization_command} onFocus={e=>e.target.select()}/>
 <div className="flex flex-wrap gap-2"><Button variant="ghost" onClick={()=>{if(navigator.clipboard)void navigator.clipboard.writeText(job.authorization_command).catch(()=>{command.current?.focus();command.current?.select()});else{command.current?.focus();command.current?.select()}}}>Copy authorization command</Button><Button disabled={busy||disabled} onClick={()=>void action()}>{syncing?"Run account sync":"Configure automatically"}</Button></div>
 <p className="text-xs text-ink-secondary">Continue after the target confirms “Temporary gateway setup authorized”. Authorization is limited to this installer and is cleaned up after use.</p></>}
 {active&&<Button variant="ghost" disabled={busy} onClick={()=>void action(true)}>Cancel setup</Button>}
{job.state==="succeeded"&&<div className="rounded-lg border border-white/10 bg-white/5 p-3 text-sm space-y-2"><p><strong>Allow the browser terminal:</strong> the gateway {gatewayName} must reach {server.private_ip} on TCP {server.ssh_port}. If an account check says the server could not be reached, allow it in the server's firewall or cloud security rules, then run Check again.</p><FirewallHelp gatewayName={gatewayName} host={server.private_ip??"SERVER_IP"} port={server.ssh_port??2222} summary="Firewall examples"/></div>}
  {job.state==="succeeded"&&<p className="text-sm">{syncing?"Check any new account, then grant access under Access. Existing checked accounts stay available.":"Check the accounts below, enable the server, then grant access under Access."}</p>}
 </div>}
 <details className="text-xs text-ink-secondary"><summary className="cursor-pointer">Supported systems and account limits</summary><p className="mt-2 max-w-prose">Requires Linux, Python 3, OpenSSH and systemd. Root, system and non-login users are excluded. Maximum 16 accounts. Unsupported distributions and enforcing SELinux are refused. Discovery runs on request; it does not grant access or remove existing accounts.</p></details>
 <ErrorText>{error}</ErrorText></section>
}

// SA-UX-2 item 11: ways to run the one-time authorization command when the server has no direct SSH from you.
export function RunCommandHelp({ip}:{ip:string}){
 return <details className="text-sm text-ink-secondary"><summary className="cursor-pointer text-ink-body">Can't run commands on the server?</summary><div className="mt-2 space-y-2 max-w-prose">
 <p>Any channel you already trust works: the command must run on the server itself, as root (sudo). It is single use and expires in 15 minutes.</p>
 <p><strong>Through a jump host</strong> (for example a host or gateway VM you can SSH to that can reach the server):</p><pre className="overflow-x-auto rounded-lg bg-white/5 p-2 text-xs">{`ssh -J you@JUMP_HOST you@${ip}`}</pre>
 <p><strong>Google Cloud (no external IP):</strong> use IAP TCP forwarding. It needs a firewall rule allowing Google's IAP range to reach SSH:</p><pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-white/5 p-2 text-xs">{`gcloud compute firewall-rules create allow-iap-ssh --network=NETWORK --direction=INGRESS --action=ALLOW --rules=tcp:22 --source-ranges=35.235.240.0/20\ngcloud compute ssh VM_NAME --zone=ZONE --tunnel-through-iap`}</pre>
 <p><strong>AWS:</strong> use Systems Manager Session Manager (the instance needs the SSM agent and an instance profile with AmazonSSMManagedInstanceCore):</p><pre className="overflow-x-auto rounded-lg bg-white/5 p-2 text-xs">aws ssm start-session --target INSTANCE_ID</pre>
 <p><strong>Azure:</strong> use Azure Bastion, or Run Command (<code>az vm run-command invoke --command-id RunShellScript --scripts '…'</code>).</p>
 <p><strong>New VMs:</strong> you can paste the command into cloud-init / user data (<code>runcmd:</code>) only if the VM boots within the 15-minute window. User data is stored in the cloud provider's metadata, so prefer an interactive channel.</p>
 </div></details>
}

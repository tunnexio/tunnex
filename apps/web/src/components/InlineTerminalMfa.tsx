import { useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input } from "./ui";
import { MfaSettings } from "./MfaSettings";

export function InlineTerminalMfa({action, freshnessSeconds=900, onVerified, onCancel}:{action:string;freshnessSeconds?:number;onVerified:()=>void|Promise<void>;onCancel:()=>void}) {
 const [showSetup,setShowSetup]=useState(false);
 const [code,setCode]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
 async function verify(){if(busy||!code.trim())return;setBusy(true);setError("");
  try {const result=await api.POST("/api/v1/auth/mfa/step-up",{body:{code:code.trim()}});
   if(result.error||!result.data){setError(apiErrorMessage(result.error,"Verification was not confirmed. Try again."));return}
   setCode("");await onVerified();
  }catch{setError("Could not verify MFA. Check your connection and try again.")}finally{setBusy(false)}
 }
 return <section aria-label={`MFA for ${action}`} className="rounded-lg border border-white/10 bg-white/5 p-4 space-y-3">
  <div><h3 className="text-sm font-semibold">Verify MFA for Terminal</h3><p className="mt-1 text-sm text-ink-secondary">Verify to continue: {action}. This verification can be reused in this signed-in session for up to {Math.round(freshnessSeconds/60)} minutes, according to your organization policy.</p></div>
  <form className="space-y-3" onSubmit={e=>{e.preventDefault();void verify()}}>
   <Field label="Authenticator or recovery code"><Input required autoFocus autoComplete="one-time-code" value={code} onChange={e=>setCode(e.target.value)} disabled={busy}/></Field>
   <ErrorText>{error}</ErrorText>
   <div className="flex flex-wrap gap-2"><Button type="submit" disabled={busy||!code.trim()}>{busy?"Verifying…":"Verify and continue"}</Button><Button type="button" variant="ghost" disabled={busy} onClick={onCancel}>Cancel verification</Button></div>
  </form>
  <details className="text-xs text-ink-secondary" onToggle={e=>setShowSetup(e.currentTarget.open)}><summary className="cursor-pointer">Need to set up an authenticator?</summary>{showSetup&&<MfaSettings setupLabel="Set up MFA" onEnrolled={()=>void onVerified()} signInReturnTo="/browser-access/terminal"/>}</details>
 </section>;
}

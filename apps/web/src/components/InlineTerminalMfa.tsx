import { useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input } from "./ui";
import { MfaSettings } from "./MfaSettings";
import { Icon } from "./Icon";

export function InlineTerminalMfa({action, freshnessSeconds=900, onVerified, onCancel}:{action:string;freshnessSeconds?:number;onVerified:()=>void|Promise<void>;onCancel:()=>void}) {
 const [showSetup,setShowSetup]=useState(false);
 const [code,setCode]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
 async function verify(){if(busy||!code.trim())return;setBusy(true);setError("");
  try {const result=await api.POST("/api/v1/auth/mfa/step-up",{body:{code:code.trim()}});
   if(result.error||!result.data){setError(apiErrorMessage(result.error,"Verification was not confirmed. Try again."));return}
   setCode("");await onVerified();
  }catch{setError("Could not verify MFA. Check your connection and try again.")}finally{setBusy(false)}
 }
 return <section aria-label={`MFA for ${action}`} className="tnx-inline-mfa">
  <div className="tnx-inline-mfa-heading"><span className="tnx-inline-mfa-icon" aria-hidden="true"><Icon name="shield-check" size={18}/></span><div><h3>Verify your identity</h3><p className="tnx-inline-mfa-context">{action}</p></div></div>
  <p className="tnx-inline-mfa-policy">Verification is reused for up to {Math.round(freshnessSeconds/60)} minutes in this signed-in session.</p>
  <form className="tnx-inline-mfa-form" onSubmit={e=>{e.preventDefault();void verify()}}>
   <div className="tnx-inline-mfa-entry"><Field label="Authenticator or recovery code"><Input required autoFocus autoComplete="one-time-code" placeholder="Enter code" value={code} onChange={e=>setCode(e.target.value)} disabled={busy}/></Field><div className="tnx-inline-mfa-actions"><Button type="submit" disabled={busy||!code.trim()}>{busy?"Verifying…":"Verify and continue"}</Button><Button type="button" variant="ghost" aria-label="Cancel verification" disabled={busy} onClick={onCancel}>Cancel</Button></div></div>
   <ErrorText>{error}</ErrorText>
  </form>
  <details className="tnx-inline-mfa-setup" onToggle={e=>setShowSetup(e.currentTarget.open)}><summary>Authenticator setup</summary>{showSetup&&<MfaSettings setupLabel="Set up MFA" onEnrolled={()=>void onVerified()} signInReturnTo="/browser-access/terminal"/>}</details>
 </section>;
}

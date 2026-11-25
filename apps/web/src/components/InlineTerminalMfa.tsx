import { useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText, Field, Input } from "./ui";
import { MfaSettings } from "./MfaSettings";
import { useOptionalAuth } from "../lib/auth";
import { Icon } from "./Icon";

export function InlineTerminalMfa({action, freshnessSeconds=900, onVerified, onCancel}:{action:string;freshnessSeconds?:number;onVerified:()=>void|Promise<void>;onCancel:()=>void}) {
 // SA-UX-2 I1: without a confirmed factor, setup comes first and is open; known only when signed in.
 const auth0=useOptionalAuth();const missing=auth0?.state.status==="authed"&&typeof auth0.state.user.recovery_codes_remaining!=="number";
 const [showSetup,setShowSetup]=useState(missing);
 const here=typeof window==="undefined"?"/":window.location.pathname+window.location.search;
 // A confirmed factor is reported as a recovery-code count (even 0). Offer setup only when there is none or it is unknown.
 const auth=useOptionalAuth();const enrolled=auth?.state.status==="authed"&&typeof auth.state.user.recovery_codes_remaining==="number";
 const [code,setCode]=useState(""),[busy,setBusy]=useState(false),[error,setError]=useState("");
 async function verify(){if(busy||!code.trim())return;setBusy(true);setError("");
  try {const result=await api.POST("/api/v1/auth/mfa/step-up",{body:{code:code.trim()}});
   if(result.error||!result.data){setError(apiErrorMessage(result.error,"Verification was not confirmed. Try again."));return}
   setCode("");await onVerified();
  }catch{setError("Could not verify the code. Check your connection and try again.")}finally{setBusy(false)}
 }
 return <section aria-label={`MFA for ${action}`} className="tnx-inline-mfa">
  <div className="tnx-inline-mfa-heading"><span className="tnx-inline-mfa-icon" aria-hidden="true"><Icon name="shield-check" size={18}/></span><div><h3>Verify your identity</h3><p className="tnx-inline-mfa-context">{action}</p></div></div>
  {missing&&<p role="note" className="tnx-inline-mfa-policy">Your account has no authenticator app yet. Set one up below, then enter its code.</p>}<p className="tnx-inline-mfa-policy">Two-factor verification is reused for up to {Math.round(freshnessSeconds/60)} minutes in this signed-in session.</p>
  <form className="tnx-inline-mfa-form" onSubmit={e=>{e.preventDefault();void verify()}}>
   <div className="tnx-inline-mfa-entry"><Field label="Authenticator or recovery code"><Input required autoFocus autoComplete="one-time-code" placeholder="Enter code" value={code} onChange={e=>setCode(e.target.value)} disabled={busy}/></Field><div className="tnx-inline-mfa-actions"><Button type="submit" disabled={busy||!code.trim()}>{busy?"Verifying…":"Verify and continue"}</Button><Button type="button" variant="ghost" aria-label="Cancel verification" disabled={busy} onClick={onCancel}>Cancel</Button></div></div>
   <ErrorText>{error}</ErrorText>
  </form>
  {!enrolled&&<details className="tnx-inline-mfa-setup" open={showSetup} onToggle={e=>setShowSetup(e.currentTarget.open)}><summary>Set up an authenticator app</summary>{showSetup&&<MfaSettings setupLabel="Set up two-factor" onEnrolled={()=>void onVerified()} signInReturnTo={here}/>}</details>}
 </section>;
}

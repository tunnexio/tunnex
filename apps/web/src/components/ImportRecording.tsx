import { useEffect, useRef, useState } from "react";
import { api, apiErrorMessage } from "../lib/api";
import { Button, ErrorText } from "./ui";
import { encodeRecordingPackage, MAX_RECORDING_FILE_BYTES, parseRecordingImport, type ImportedRecording } from "../lib/recordingImport";
export function ImportRecording({orgId,onImport,onReset}: {orgId:string;onImport:(value:ImportedRecording)=>void;onReset?:()=>void}) {
 const input=useRef<HTMLInputElement>(null);const request=useRef(0);
 const [error,setError]=useState("");const [busy,setBusy]=useState(false);const [pending,setPending]=useState<File>();
 useEffect(()=>()=>{request.current++},[]);
 async function load(file:File,decrypt=false){const token=++request.current;onReset?.();setError("");setBusy(true);try{
  if(file.size>MAX_RECORDING_FILE_BYTES)throw new Error("Recording file exceeds the 32 MiB limit.");
  const name=file.name.slice(0,255);
  if(file.name.toLowerCase().endsWith(".tunnex-recording")){
   if(!decrypt){if(token===request.current)setPending(file);return}
   const encoded=encodeRecordingPackage(new Uint8Array(await file.arrayBuffer()));
   if(token!==request.current)return;
   const result=await api.POST("/api/v1/organizations/{orgId}/server-access/recording-import",{params:{path:{orgId}},body:{package:encoded}});
   if(token!==request.current)return;
   if(result.error||!result.data)throw new Error(apiErrorMessage(result.error,"Package import was denied or could not be decrypted."));
   const recording=parseRecordingImport(JSON.stringify(result.data));setPending(undefined);onImport({recording,name,source:"encrypted-package"});
  }else if(file.name.toLowerCase().endsWith(".json")){
   const recording=parseRecordingImport(await file.text());if(token===request.current){setPending(undefined);onImport({recording,name,source:"json"})}
  }else throw new Error("Choose a Manual download .json or a complete encrypted .tunnex-recording package. Raw chunks and manifests are unsupported.");
 }catch(e){if(token===request.current){setPending(undefined);setError(e instanceof Error?e.message:"Could not read this recording file.")}}finally{if(token===request.current)setBusy(false)}}
 return <div className="space-y-2"><Button variant="ghost" disabled={busy} onClick={()=>input.current?.click()}>{busy?"Reading recording…":"Import recording"}</Button><input ref={input} className="sr-only" type="file" accept=".json,.tunnex-recording,application/json" aria-label="Import recording file" disabled={busy} onChange={e=>{const file=e.target.files?.[0];e.target.value="";if(file)void load(file)}}/><p className="text-sm">Manual download JSON stays in this browser. Encrypted .tunnex-recording packages require explicit upload to this control plane for authorized decryption with the original installation key. Raw chunks and manifests are unsupported. Imports do not restore sessions, grants or trusted audit identity.</p>{pending&&<div className="space-y-2"><p role="note">{pending.name} will be uploaded to this organization's control plane only when you choose Decrypt package for replay. Current account access is checked; closing the replay clears its browser snapshot.</p><div className="flex gap-3"><Button disabled={busy} onClick={()=>void load(pending,true)}>Decrypt package for replay</Button><Button variant="ghost" disabled={busy} onClick={()=>{request.current++;setPending(undefined);onReset?.()}}>Cancel package import</Button></div></div>}<ErrorText>{error}</ErrorText></div>;
}

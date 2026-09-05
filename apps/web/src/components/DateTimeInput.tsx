import {useEffect, useRef, useState, type InputHTMLAttributes} from "react";
import "../date-time-input.css";
const pad=(n:number)=>String(n).padStart(2,"0");
const localDate=(d:Date)=>`${d.getFullYear()}-${pad(d.getMonth()+1)}-${pad(d.getDate())}`;

/** Keeps the native form value and validation, with an in-page calendar editor. */
export function DateTimeInput(props:InputHTMLAttributes<HTMLInputElement>) {
 const root=useRef<HTMLDivElement>(null);
 const input=useRef<HTMLInputElement>(null);
 const trigger=useRef<HTMLButtonElement>(null);
 const panel=useRef<HTMLDivElement>(null);
 const [open,setOpen]=useState(false);
 const [draft,setDraft]=useState("");
 const [month,setMonth]=useState(()=>new Date());
 useEffect(()=>{if(open){panel.current?.scrollIntoView?.({block:"nearest"}); panel.current?.querySelector<HTMLButtonElement>("button")?.focus({preventScroll:true});}},[open]);
 useEffect(()=>{
   const dismiss=(event:PointerEvent)=>{if(!root.current?.contains(event.target as Node))setOpen(false);};
   const opened=(event:Event)=>{if((event as CustomEvent).detail!==input.current)setOpen(false);};
   document.addEventListener("pointerdown",dismiss);
   document.addEventListener("tnx-date-open",opened);
   return ()=>{document.removeEventListener("pointerdown",dismiss);document.removeEventListener("tnx-date-open",opened);};
 },[]);
 const withTime=props.type==="datetime-local";
 const date=draft.slice(0,10);
 const time=draft.slice(11,16)||"09:00";
 const year=month.getFullYear(), m=month.getMonth();
 const first=new Date(year,m,1).getDay();
 const days=new Date(year,m+1,0).getDate();
 const min=String(props.min??""),max=String(props.max??"");
 const valid=!!date && (!min || draft>=min) && (!max || draft<=max);
 function close(){setOpen(false);trigger.current?.focus();}
 function commit(value:string){
  const node=input.current;if(!node)return;
  Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,"value")?.set?.call(node,value);
  node.dispatchEvent(new Event("input",{bubbles:true}));
  close();
 }
 function choose(day:string){setDraft(day+(withTime?`T${time}`:""));}
 function showPicker(){
   if(props.disabled || props.readOnly)return;
   document.dispatchEvent(new CustomEvent("tnx-date-open",{detail:input.current}));
   const value=input.current?.value||"";setDraft(value);setMonth(value?new Date(`${value.slice(0,10)}T12:00`):new Date());setOpen(true);
 }
 const [uncontrolledValue,setUncontrolledValue]=useState(String(props.defaultValue??""));
 const empty=String(props.value??uncontrolledValue)==="";
 return <div ref={root} className="tnx-date-field">
  <div className="tnx-date-control" data-empty={empty}><input {...props} ref={input} onChange={event=>{setUncontrolledValue(event.target.value);props.onChange?.(event);}} onClick={event=>{props.onClick?.(event);if(!event.defaultPrevented)showPicker();}}/>
  {empty&&<span className="tnx-date-placeholder" aria-hidden="true">{withTime ? "Choose date & time" : "Choose a date"}</span>}
  <button ref={trigger} type="button" disabled={props.disabled||props.readOnly} aria-label="Choose date and time" aria-expanded={open} onClick={()=>{if(open)close();else showPicker();}}><svg aria-hidden="true" width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5"><rect x="3" y="5" width="18" height="16" rx="3"/><path d="M7 3v4m10-4v4M3 11h18"/></svg></button></div>
  {open&&<div ref={panel} className="tnx-date-picker" role="group" aria-label="Date and time picker" onKeyDown={e=>{if(e.key==="Escape"){e.preventDefault();e.stopPropagation();close();}}}>
   <header><button type="button" aria-label="Previous month" onClick={()=>setMonth(new Date(year,m-1,1))}>‹</button><strong>{month.toLocaleDateString(undefined,{month:"long",year:"numeric"})}</strong><button type="button" aria-label="Next month" onClick={()=>setMonth(new Date(year,m+1,1))}>›</button></header>
   <div className="tnx-calendar-week" aria-hidden="true">{["Su","Mo","Tu","We","Th","Fr","Sa"].map(d=><span key={d}>{d}</span>)}</div>
   <div className="tnx-calendar-days">{Array.from({length:first},(_,i)=><span key={`blank-${i}`}/>)}{Array.from({length:days},(_,i)=>{
    const day=`${year}-${pad(m+1)}-${pad(i+1)}`;
    return <button type="button" key={day} aria-label={day} aria-pressed={date===day} disabled={!!((min&&day<min.slice(0,10))||(max&&day>max.slice(0,10)))} onClick={()=>choose(day)}>{i+1}</button>;
   })}</div>
   {withTime&&<div className="tnx-calendar-time"><span>Time <small>Local · 24-hour</small></span><select aria-label="Hour" value={time.slice(0,2)} onChange={e=>setDraft(`${date||localDate(new Date())}T${e.target.value}:${time.slice(3,5)}`)}>{Array.from({length:24},(_,i)=><option key={i}>{pad(i)}</option>)}</select><span>:</span><select aria-label="Minute" value={time.slice(3,5)} onChange={e=>setDraft(`${date||localDate(new Date())}T${time.slice(0,2)}:${e.target.value}`)}>{Array.from({length:60},(_,i)=><option key={i}>{pad(i)}</option>)}</select></div>}
   <footer><button type="button" disabled={props.required} onClick={()=>commit("")}>Clear</button><button type="button" onClick={close}>Cancel</button><button type="button" disabled={!valid} onClick={()=>commit(draft)}>Apply</button></footer>
  </div>}
 </div>;
}

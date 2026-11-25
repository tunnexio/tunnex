import { useState, type FormEvent } from "react";
import { Button, Field, Input, Select } from "./ui";

// SA-UX-2 R4: people choose sizes in KB/MB/GB; the API keeps bytes.
const units = { KB: 1024, MB: 1024 * 1024, GB: 1024 * 1024 * 1024 } as const;
type Unit = keyof typeof units;
export function toUnit(bytes: number, allowed: Unit[]): { value: number; unit: Unit } {
  for (const unit of [...allowed].reverse()) if (bytes >= units[unit] && bytes % units[unit] === 0) return { value: bytes / units[unit], unit };
  return { value: Math.round(bytes / units[allowed[0]]), unit: allowed[0] };
}
export const toBytes = (value: number, unit: Unit) => Math.round(value * units[unit]);
const SESSION = { min: 64 * 1024, max: 16 * 1024 * 1024 }, ORG = { min: 64 * 1024, max: 1024 * 1024 * 1024 };
const show = (bytes: number) => { const v = toUnit(bytes, ["KB", "MB", "GB"]); return `${v.value} ${v.unit}`; };

function SizeField({ label, value, unit, units: allowed, onValue, onUnit }: { label: string; value: number; unit: Unit; units: Unit[]; onValue: (v: number) => void; onUnit: (u: Unit) => void }) {
  return <Field label={label}><span className="flex gap-2"><Input aria-label={label} type="number" min={1} step="any" required value={value} onChange={e => onValue(Number(e.target.value))} /><Select aria-label={`${label} unit`} width="auto" value={unit} onChange={e => onUnit(e.target.value as Unit)}>{allowed.map(u => <option key={u} value={u}>{u}</option>)}</Select></span></Field>;
}

export function RecordingPolicyForm({days,sessionBytes,orgBytes,mfaSeconds,disabled,onSave}:{mfaSeconds:number;days:number;sessionBytes:number;orgBytes:number;disabled:boolean;onSave:(v:{mfa_freshness_seconds:number;recording_retention_days:number;recording_max_session_bytes:number;recording_max_org_bytes:number})=>Promise<void>}) {
  const [freshness, setFreshness] = useState(mfaSeconds);
  const [retention, setRetention] = useState(days);
  const initialSession = toUnit(sessionBytes, ["KB", "MB"]), initialOrg = toUnit(orgBytes, ["MB", "GB"]);
  const [session, setSession] = useState(initialSession.value), [sessionUnit, setSessionUnit] = useState<Unit>(initialSession.unit);
  const [org, setOrg] = useState(initialOrg.value), [orgUnit, setOrgUnit] = useState<Unit>(initialOrg.unit);
  const sessionValue = toBytes(session, sessionUnit), orgValue = toBytes(org, orgUnit);
  const problem = !(sessionValue >= SESSION.min && sessionValue <= SESSION.max) ? `Per-session limit must be between ${show(SESSION.min)} and ${show(SESSION.max)}.`
    : !(orgValue >= ORG.min && orgValue <= ORG.max) ? `Organization limit must be between ${show(ORG.min)} and ${show(ORG.max)}.`
    : orgValue < sessionValue ? "The organization limit must be at least the per-session limit." : "";
  function submit(e: FormEvent) { e.preventDefault(); if (problem) return; void onSave({ mfa_freshness_seconds: freshness, recording_retention_days: retention, recording_max_session_bytes: sessionValue, recording_max_org_bytes: orgValue }); }
  return <form onSubmit={submit} className="space-y-5">
    <fieldset className="space-y-2"><legend className="font-medium">Two-factor reuse</legend>
      <Field label="Reuse two-factor verification for (minutes)"><Input type="number" min={1} max={15} step="any" required value={freshness / 60} onChange={e => setFreshness(Math.round(Number(e.target.value) * 60))} /></Field>
      <p className="text-xs text-ink-secondary">After someone verifies, connecting again within this window does not ask for a new code. 1 to 15 minutes.</p>
    </fieldset>
    <fieldset className="space-y-3"><legend className="font-medium">Recordings</legend>
      <div className="grid gap-3 sm:grid-cols-3">
        <Field label="Keep recordings for (days)"><Input type="number" min={1} max={3650} required value={retention} onChange={e => setRetention(Number(e.target.value))} /></Field>
        <SizeField label="Limit per session" value={session} unit={sessionUnit} units={["KB", "MB"]} onValue={setSession} onUnit={setSessionUnit} />
        <SizeField label="Limit for the organization" value={org} unit={orgUnit} units={["MB", "GB"]} onValue={setOrg} onUnit={setOrgUnit} />
      </div>
      <ul className="list-disc pl-5 text-xs text-ink-secondary space-y-1">
        <li>A recorded session that reaches its limit is closed, and its reason says the recording limit was reached. While the organization total is at its limit, recorded sessions cannot start.</li>
        <li>After the retention period the recording content is deleted (after a verified S3 archive when automatic archiving is on). The session record and its audit events stay.</li>
        <li>Changes apply to new sessions.</li>
      </ul>
    </fieldset>
    {problem && <p role="alert" className="text-sm text-danger">{problem}</p>}
    <Button type="submit" disabled={disabled || !!problem}>Save policy</Button>
  </form>;
}

import { useState } from "react";
import { Button, ErrorText, Field, Select } from "./ui";

// "You have no grant" without a dead end (SA-UX-2 item 4, App Access AA-4). Callers who may create grants can grant
// themselves through the ordinary grant endpoint (same validation, limits and audit); others are told whom to ask.
// Shared presentation only; each product passes its own grant call.
export function SelfGrant({ what, canGrant, askWho, maxHours, onGrant, onDismiss }: {
  what: string; canGrant: boolean; askWho: string; maxHours: number;
  onGrant: (hours: number) => Promise<string | undefined>; onDismiss?: () => void;
}) {
  const [hours, setHours] = useState(1), [busy, setBusy] = useState(false), [error, setError] = useState("");
  const choices = [1, 4, 8, 24, 72, 168].filter(value => value <= maxHours);
  if (!canGrant) return <div role="alert" className="space-y-2 rounded-lg border border-white/10 p-3 text-sm">
    <p className="text-ink-heading">You do not have access to {what} yet.</p>
    <p className="text-ink-secondary">Ask {askWho} to grant you access.</p>
    {onDismiss && <Button variant="ghost" onClick={onDismiss}>Dismiss</Button>}
  </div>;
  return <form role="alert" aria-label="Grant myself access" className="space-y-3 rounded-lg border border-white/10 p-3 text-sm" onSubmit={async event => {
    event.preventDefault(); if (busy) return; setBusy(true); setError("");
    try { const failure = await onGrant(hours); if (failure) setError(failure); } finally { setBusy(false); }
  }}>
    <p className="text-ink-heading">You do not have access to {what} yet.</p>
    <p className="text-ink-secondary">You can manage access here, so you can grant yourself time-limited access. The grant is recorded in the audit log like any other.</p>
    <Field label="Duration"><Select value={String(hours)} onChange={event => setHours(Number(event.target.value))}>{choices.map(value => <option key={value} value={value}>{value < 24 ? `${value} hour${value === 1 ? "" : "s"}` : `${value / 24} day${value === 24 ? "" : "s"}`}</option>)}</Select></Field>
    <div className="flex flex-wrap gap-2"><Button type="submit" disabled={busy}>{busy ? "Granting…" : "Grant myself access"}</Button>{onDismiss && <Button variant="ghost" type="button" disabled={busy} onClick={onDismiss}>Not now</Button>}</div>
    <ErrorText>{error}</ErrorText>
  </form>;
}

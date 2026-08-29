import { useState } from "react";
import { Button, Field, Input } from "./ui";

export type AgentProfileStatus = "pending" | "active" | "suspended" | "revoked";

export type AgentProfileEditorValue = {
	environment: string;
	runtime: string;
	labels: Record<string, string>;
};

type CurrentProfile = AgentProfileEditorValue & { status: AgentProfileStatus };

type Props = {
	value: CurrentProfile;
	canManageLifecycle: boolean;
	onSaveMetadata: (value: AgentProfileEditorValue) => void;
	onLifecycleChange: (status: "active" | "suspended") => void;
  disabled?: boolean;
};

function parseLabels(raw: string): Record<string, string> | null {
  try {
    const parsed: unknown = JSON.parse(raw);
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
    for (const [key, value] of Object.entries(parsed)) {
      if (!key.trim() || typeof value !== "string") return null;
    }
    return parsed as Record<string, string>;
  } catch {
    return null;
  }
}

/** F01 metadata editor. Owner, identity and telemetry are intentionally absent: they are read-only facts. */
export function AgentProfileEditor({ value, canManageLifecycle, onSaveMetadata, onLifecycleChange, disabled = false }: Props) {
  const [draft, setDraft] = useState(value);
  const [labels, setLabels] = useState(JSON.stringify(value.labels, null, 2));
  const [labelError, setLabelError] = useState<string | null>(null);
  const lifecycleDisabled = disabled || !canManageLifecycle;
  const lifecycleAction = value.status === "active" ? "suspend" : value.status === "suspended" ? "resume" : null;

  function submit(event: React.FormEvent) {
    event.preventDefault();
    const parsed = parseLabels(labels);
    if (!parsed) {
      setLabelError("Labels must be a JSON object with non-empty keys and string values.");
      return;
    }
    setLabelError(null);
	 onSaveMetadata({ environment: draft.environment, runtime: draft.runtime, labels: parsed });
  }

  return (
    <form className="grid gap-3" onSubmit={submit} aria-label="Agent metadata">
      <div className="grid gap-3 sm:grid-cols-2">
        <Field label="Environment"><Input value={draft.environment} disabled={disabled} onChange={(e) => setDraft({ ...draft, environment: e.target.value })} /></Field>
        <Field label="Runtime"><Input value={draft.runtime} disabled={disabled} onChange={(e) => setDraft({ ...draft, runtime: e.target.value })} /></Field>
      </div>
      <Field label="Labels (JSON)">
        <textarea aria-describedby={labelError ? "agent-label-error" : undefined} className="min-h-20 w-full rounded-md border border-white/10 bg-ink-900 px-3 py-2 font-mono text-xs text-white focus-visible:border-white/25 focus-visible:outline-none focus-visible:ring-1 focus-visible:ring-inset focus-visible:ring-white/35" value={labels} disabled={disabled} onChange={(e) => { setLabels(e.target.value); setLabelError(null); }} />
      </Field>
      {labelError && <p id="agent-label-error" role="alert" className="text-xs text-danger">{labelError}</p>}
      <p className="text-xs text-ink-tertiary">Lifecycle: <span className="text-ink-body">{value.status}</span></p>
      {value.status === "pending" && <p className="text-xs text-ink-secondary">Awaiting approval; this editor cannot bypass device approval.</p>}
      {value.status === "revoked" && <p className="text-xs text-ink-secondary">Revoked is terminal; enrol a new agent instead.</p>}
      {lifecycleAction && canManageLifecycle && (
            <Button size="sm" variant="ghost" type="button" disabled={lifecycleDisabled} onClick={() => onLifecycleChange(lifecycleAction === "suspend" ? "suspended" : "active")}>
          {lifecycleAction === "suspend" ? "Suspend agent" : "Resume agent"}
        </Button>
      )}
      <Button size="sm" className="w-fit" type="submit" disabled={disabled}>Save metadata</Button>
    </form>
  );
}

import { useState } from "react";

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
    <form className="grid gap-3 rounded-lg border border-line bg-ink-900/40 p-3" onSubmit={submit} aria-label="Agent metadata">
      <label className="grid gap-1 text-xs text-ink-secondary">
        Environment
        <input className="rounded border border-line bg-ink-800 px-2 py-1 text-white" value={draft.environment} disabled={disabled} onChange={(e) => setDraft({ ...draft, environment: e.target.value })} />
      </label>
      <label className="grid gap-1 text-xs text-ink-secondary">
        Runtime
        <input className="rounded border border-line bg-ink-800 px-2 py-1 text-white" value={draft.runtime} disabled={disabled} onChange={(e) => setDraft({ ...draft, runtime: e.target.value })} />
      </label>
      <label className="grid gap-1 text-xs text-ink-secondary">
        Labels (JSON)
        <textarea aria-describedby={labelError ? "agent-label-error" : undefined} className="min-h-20 rounded border border-line bg-ink-800 px-2 py-1 font-mono text-xs text-white" value={labels} disabled={disabled} onChange={(e) => { setLabels(e.target.value); setLabelError(null); }} />
      </label>
      {labelError && <p id="agent-label-error" role="alert" className="text-xs text-danger">{labelError}</p>}
      <p className="text-xs text-ink-secondary">Lifecycle: {value.status}</p>
      {value.status === "pending" && <p className="text-xs text-ink-secondary">Awaiting approval; this editor cannot bypass device approval.</p>}
      {value.status === "revoked" && <p className="text-xs text-ink-secondary">Revoked is terminal; enrol a new agent instead.</p>}
      {lifecycleAction && canManageLifecycle && (
						<button type="button" className="w-fit rounded border border-line px-3 py-1 text-xs text-white disabled:opacity-50" disabled={lifecycleDisabled} onClick={() => onLifecycleChange(lifecycleAction === "suspend" ? "suspended" : "active")}>
          {lifecycleAction === "suspend" ? "Suspend agent" : "Resume agent"}
        </button>
      )}
      <button className="w-fit rounded bg-accent px-3 py-1 text-xs text-white disabled:opacity-50" type="submit" disabled={disabled}>Save metadata</button>
    </form>
  );
}

import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api, apiErrorMessage, loadOne, type HealthCheck } from "../lib/api";
import { Button, DataTable, ErrorText, Field, Input, Loading, Modal, Select, RefreshButton } from "./ui";
import { LoadRetry } from "./LoadRetry";
import AppAccessRowMenu from "./AppAccessRowMenu";
import { POSTURE_HONESTY_LINE, buildOsVersionParam, checkModeOf, osVersionCoverage, osVersionMins, wouldFailCopy, type CheckMode } from "../lib/postureview";
import "../devices-policy-workspace.css";

type Props = { orgId: string; canManage: boolean; renderNavigation?: (actions: ReactNode) => ReactNode };
type CheckKind = HealthCheck["kind"];
type Editor = { kind: CheckKind; mode: CheckMode; macos: string; windows: string; generation: number };
const checkRows: { kind: CheckKind; name: string }[] = [
  { kind: "disk_encryption", name: "Disk encryption" },
  { kind: "os_version", name: "Minimum OS version" },
];

export function PostureChecksSection(props: Props) {
  return <PostureWorkspace key={`${props.orgId}:${props.canManage}`} {...props} />;
}

function PostureWorkspace({ orgId, canManage, renderNavigation }: Props) {
  const [checks, setChecks] = useState<HealthCheck[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saveNote, setSaveNote] = useState<string | null>(null);
  const [saved, setSaved] = useState<string | null>(null);
  const [editor, setEditor] = useState<Editor | null>(null);
  const alive = useRef(true), request = useRef(0), locked = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; request.current++; }; }, []);

  const load = useCallback(async () => {
    const sequence = ++request.current;
    setChecks(null); setLoadError(null);
    const result = await loadOne(() => api.GET("/api/v1/organizations/{orgId}/health-checks", { params: { path: { orgId } } }));
    if (!alive.current || sequence !== request.current) return false;
    if (!result.ok) { setLoadError(result.error); return false; }
    if (!Array.isArray(result.data) || !result.data.every((check) => check && typeof check === "object" && (check.kind === "disk_encryption" || check.kind === "os_version") && (check.mode === "warn" || check.mode === "require")) || new Set(result.data.map((check) => check.kind)).size !== result.data.length) {
      setLoadError("The saved posture response was not valid. Refresh checks to reload it.");
      return false;
    }
    setChecks(result.data as HealthCheck[]);
    return true;
  }, [orgId]);
  useEffect(() => { void load(); }, [load]);

  function edit(kind: CheckKind) {
    if (!canManage || busy || !checks || loadError) return;
    const mins = osVersionMins(checks.find((check) => check.kind === kind));
    setErr(null);
    setEditor({ kind, mode: checkModeOf(checks, kind), macos: mins.macos, windows: mins.windows, generation: request.current });
  }
  function updateEditor(patch: Partial<Pick<Editor, "mode" | "macos" | "windows">>) {
    if (busy) return;
    setErr(null); setEditor((current) => current ? { ...current, ...patch } : current);
  }
  async function saveCheck() {
    if (!canManage || locked.current || !alive.current || !editor || !checks || loadError || editor.generation !== request.current) return;
    const draft = editor;
    const param = draft.kind === "os_version" && draft.mode !== "off" ? buildOsVersionParam({ macos: draft.macos, windows: draft.windows }) : undefined;
    if (draft.kind === "os_version" && draft.mode !== "off" && !param) {
      setErr("Set a minimum version for at least one platform, or turn the check off.");
      return;
    }
    locked.current = true; setBusy(true); setErr(null); setSaveNote(null); setSaved(null);
    try {
      let note: string | null = null;
      if (draft.mode === "off") {
        const { error } = await api.DELETE("/api/v1/organizations/{orgId}/health-checks/{checkKind}", { params: { path: { orgId, checkKind: draft.kind } } });
        if (!alive.current) return;
        if (error) { setErr(apiErrorMessage(error, "Could not turn the check off.")); return; }
      } else {
        const { data, error } = await api.PUT("/api/v1/organizations/{orgId}/health-checks/{checkKind}", {
          params: { path: { orgId, checkKind: draft.kind } },
          body: { mode: draft.mode, param: (param ?? undefined) as Record<string, never> | undefined },
        });
        if (!alive.current) return;
        if (error) { setErr(apiErrorMessage(error, "Could not save the check.")); return; }
        note = wouldFailCopy(draft.mode, (data as HealthCheck | undefined)?.would_fail_count);
      }
      setSaveNote(note);
      // The inventory represents the authoritative readback, never the local draft.
      const refreshed = await load();
      if (!alive.current) return;
      setEditor(null);
      if (refreshed) setSaved(`${checkRows.find((row) => row.kind === draft.kind)?.name} saved.`);
      else setErr("The change was accepted, but saved checks could not be reloaded. Refresh checks before making another change.");
    } catch {
      if (!alive.current) return;
      setEditor(null);
      setErr("The save was not confirmed. Refresh checks to review the current policy before retrying.");
      await load();
    } finally { locked.current = false; if (alive.current) setBusy(false); }
  }

  const refresh = <RefreshButton label="Refresh checks" disabled={busy} onClick={() => { setEditor(null); setErr(null); setSaved(null); setSaveNote(null); void load(); }} />;
  const editorName = checkRows.find((row) => row.kind === editor?.kind)?.name;
  const coverage = editor && editor.mode !== "off" ? osVersionCoverage({ macos: editor.macos, windows: editor.windows }) : [];
  return <>
    {renderNavigation?.(refresh)}
    <div className={`devices-policy-content${canManage ? "" : " devices-policy-readonly"}`}>
      {!renderNavigation && <div className="devices-policy-toolbar"><span className="devices-policy-copy">Saved device checks</span>{refresh}</div>}
      {!editor && <ErrorText>{err}</ErrorText>}
      {saved && <p role="status" className="devices-policy-notice">{saved}</p>}
      {saveNote && <p role="status" className="devices-policy-impact">{saveNote}</p>}
      {loadError ? <LoadRetry error={loadError} onRetry={() => { setEditor(null); void load(); }} /> : checks == null ? <Loading label="Loading saved posture checks…" /> : <>
        <DataTable variant="flat" caption="Posture checks" rows={checkRows} rowKey={(row) => row.kind} rowLabel={(row) => row.name} failed={false} filterable={false} pageSize={0} empty="No checks available." columns={[
          { key: "check", header: "Check", cell: (row) => <div className="devices-policy-cell">{canManage ? <button className="devices-policy-name" onClick={() => edit(row.kind)}>{row.name}</button> : <span>{row.name}</span>}<small>{row.kind === "disk_encryption" ? "Device-reported FileVault or BitLocker" : "macOS and Windows version floors"}</small></div> },
          { key: "mode", header: "Saved mode", cell: (row) => modeLabel(checkModeOf(checks, row.kind)) },
          { key: "coverage", header: "Coverage", cell: (row) => checkModeOf(checks, row.kind) === "off" ? <span className="devices-policy-copy">Check is off</span> : row.kind === "disk_encryption" ? <span className="devices-policy-copy">macOS and Windows · reported encryption</span> : <ul className="devices-policy-coverage">{osVersionCoverage(osVersionMins(checks.find((check) => check.kind === row.kind))).map((item) => <li key={item.platform} data-unconstrained={!item.covered || undefined}>{item.label}</li>)}</ul> },
          ...(canManage ? [{ key: "actions", header: "Actions", cell: (row: typeof checkRows[number]) => <AppAccessRowMenu label={`Actions for ${row.name}`} actions={[{ key: "edit", label: "Edit check", disabledReason: busy ? "Wait for the current save." : undefined, onSelect: () => edit(row.kind) }]} /> }] : []),
        ]} />
        <details className="devices-policy-help"><summary>About posture signals</summary><p>{POSTURE_HONESTY_LINE}</p><p>Missing device facts do not block access. A skipped check is not proof of compliance. Non-reporting platforms are unaffected.</p></details>
      </>}
    </div>
    {editor && <Modal title={editorName ?? "Posture check"} placement="right" size="enrollment" showClose onDismiss={() => !busy && setEditor(null)} actions={<><Button variant="ghost" disabled={busy} onClick={() => setEditor(null)}>Cancel</Button><Button disabled={busy || checks == null || !!loadError || editor.generation !== request.current} onClick={() => void saveCheck()}>{busy ? "Saving…" : "Save check"}</Button></>}>
      <div className="devices-policy-editor">
        <ErrorText>{err}</ErrorText>
        <Field label="Mode"><Select width="full" aria-label="Mode" value={editor.mode} disabled={busy} onChange={(event) => updateEditor({ mode: event.target.value as CheckMode })}><option value="off">Off</option><option value="warn">Warn</option><option value="require">Require</option></Select></Field>
        <p>{editor.mode === "off" ? "Off removes this check from the policy." : editor.mode === "warn" ? "Warn records a reported failure while access continues." : "Require blocks devices that report a failed check. Unknown or unreported facts do not block."}</p>
        {editor.kind === "disk_encryption" && <p>Uses FileVault on macOS or BitLocker on Windows, as reported by the device.</p>}
        {editor.kind === "os_version" && editor.mode !== "off" && <>
          <div className="devices-policy-version-inputs"><Field label="macOS minimum"><Input aria-label="macOS minimum" value={editor.macos} disabled={busy} onChange={(event) => updateEditor({ macos: event.target.value })} placeholder="e.g. 14.0" /></Field><Field label="Windows minimum"><Input aria-label="Windows minimum" value={editor.windows} disabled={busy} onChange={(event) => updateEditor({ windows: event.target.value })} placeholder="e.g. 10.0.22631" /></Field></div>
          <ul className="devices-policy-coverage" aria-label="Draft platform coverage">{coverage.map((item) => <li key={item.platform} data-unconstrained={!item.covered || undefined}>{item.label}</li>)}</ul>
          <p>Windows 11 uses <code>10.0</code> build numbers. Run <code>winver</code> to check the floor.</p>
          <details className="devices-policy-help"><summary>Windows build numbers</summary><p>Windows 11 reports as <code>10.0.22000</code>, not <code>11.0</code>. Enter its build number, such as <code>10.0.22631</code> for 23H2. Run <code>winver</code> on a device to check.</p></details>
        </>}
        <details className="devices-policy-help"><summary>About posture signals</summary><p>{POSTURE_HONESTY_LINE}</p><p>Missing device facts do not block access. A skipped check is not proof of compliance. Non-reporting platforms are unaffected.</p></details>
      </div>
    </Modal>}
  </>;
}

function modeLabel(mode: CheckMode) { return mode === "off" ? "Off" : mode === "warn" ? "Warn" : "Require"; }

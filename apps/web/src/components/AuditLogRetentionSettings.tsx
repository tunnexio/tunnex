import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";

import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { relativeAge } from "../lib/format";
import {
  Button,
  ErrorText,
  Field,
  Input,
  Loading,
  Modal,
  Select,
  SettingRow,
  SettingValue,
} from "./ui";

export const AUDIT_RETENTION_DAYS_MIN = 1;
export const AUDIT_RETENTION_DAYS_MAX = 3650;
export const AUDIT_CLEANUP_INTERVAL_MINUTES_MIN = 5;
export const AUDIT_CLEANUP_INTERVAL_MINUTES_MAX = 1440;

export type AuditLogRetentionResource =
  components["schemas"]["AuditLogRetention"];
type AuditLogRetentionRun = components["schemas"]["AuditLogRetentionRun"];
type Notice = { text: string; tone: "success" | "danger" };
type RetentionMode = "forever" | "bounded";
type PruneRequestState = {
  key: string;
  inFlight: boolean;
  outcomeUnknown: boolean;
  error: string | null;
};

const RETENTION_PATH =
  "/api/v1/organizations/{orgId}/audit-log-retention";
const PRUNE_PATH =
  "/api/v1/organizations/{orgId}/audit-log-retention/actions/prune";

async function getRetention(orgId: string) {
  return api.GET(RETENTION_PATH, { params: { path: { orgId } } });
}

async function putRetention(
  orgId: string,
  resource: AuditLogRetentionResource,
  retentionDays: number | null,
  cleanupIntervalMinutes: number,
) {
  return api.PUT(RETENTION_PATH, {
    params: { path: { orgId } },
    body: {
      retention_days: retentionDays,
      cleanup_interval_minutes: cleanupIntervalMinutes,
      expected_revision: resource.revision,
    },
  });
}

async function pruneRetention(orgId: string, idempotencyKey: string) {
  return api.POST(PRUNE_PATH, {
    params: { path: { orgId } },
    body: { idempotency_key: idempotencyKey },
  });
}

function integerInRange(
  input: string,
  minimum: number,
  maximum: number,
): number | null {
  if (!/^\d+$/.test(input.trim())) return null;
  const value = Number(input);
  return Number.isSafeInteger(value) && value >= minimum && value <= maximum
    ? value
    : null;
}

function formatInterval(minutes: number): string {
  if (minutes % 1440 === 0) {
    const days = minutes / 1440;
    return `${days} ${days === 1 ? "day" : "days"}`;
  }
  if (minutes % 60 === 0) {
    const hours = minutes / 60;
    return `${hours} ${hours === 1 ? "hour" : "hours"}`;
  }
  return `${minutes} minutes`;
}

function dateLabel(iso: string): string {
  const parsed = new Date(iso);
  return Number.isNaN(parsed.getTime()) ? iso : parsed.toLocaleString();
}

function newIdempotencyKey(): string {
  if (typeof globalThis.crypto?.randomUUID === "function") {
    return globalThis.crypto.randomUUID();
  }
  return `web-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function runSummary(run: AuditLogRetentionRun | null | undefined) {
  if (!run) return { text: "Not run yet", tone: "muted" as const };
  if (run.status === "running") {
    return {
      text: `Running · started ${relativeAge(run.started_at)}`,
      tone: "warn" as const,
    };
  }
  if (run.status === "failed") {
    const code = run.error_code ? ` · ${run.error_code}` : "";
    return {
      text: `Failed${code} · ${run.deleted_rows.toLocaleString()} rows deleted before failure`,
      tone: "danger" as const,
    };
  }
  const pending = run.more_pending ? " · more eligible expired rows remain" : "";
  return {
    text: `${run.deleted_rows.toLocaleString()} rows deleted in ${run.batches.toLocaleString()} ${run.batches === 1 ? "batch" : "batches"}${pending}`,
    tone: run.more_pending ? ("warn" as const) : ("muted" as const),
  };
}

export function AuditLogRetentionSettings({
  orgId,
  canEdit,
}: {
  orgId: string;
  canEdit: boolean;
}) {
  const [resource, setResource] =
    useState<AuditLogRetentionResource | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [mode, setMode] = useState<RetentionMode>("forever");
  const [retentionDays, setRetentionDays] = useState("365");
  const [cleanupInterval, setCleanupInterval] = useState("60");
  const [editorOpen, setEditorOpen] = useState(false);
  const [confirmSave, setConfirmSave] = useState(false);
  const [saveBusy, setSaveBusy] = useState(false);
  const [saveError, setSaveError] = useState<string | null>(null);
  const [saveConflict, setSaveConflict] = useState(false);
  const [notice, setNotice] = useState<Notice | null>(null);
  const [confirmPrune, setConfirmPrune] = useState(false);
  const [pruneBusy, setPruneBusy] = useState(false);
  const [pruneError, setPruneError] = useState<string | null>(null);
  const [pruneOutcomeUnknown, setPruneOutcomeUnknown] = useState(false);
  const loadRequest = useRef(0);
  const activeOrgId = useRef(orgId);
  activeOrgId.current = orgId;
  const pruneRequests = useRef(new Map<string, PruneRequestState>());
  const retentionDaysErrorId = useId();
  const cleanupIntervalErrorId = useId();

  function showPruneRequest(next: PruneRequestState | undefined) {
    setPruneBusy(next?.inFlight ?? false);
    setPruneError(next?.error ?? null);
    setPruneOutcomeUnknown(next?.outcomeUnknown ?? false);
  }

  function storePruneRequest(targetOrgId: string, next: PruneRequestState) {
    pruneRequests.current.set(targetOrgId, next);
    if (activeOrgId.current === targetOrgId) showPruneRequest(next);
  }

  function clearPruneRequest(targetOrgId: string) {
    pruneRequests.current.delete(targetOrgId);
    if (activeOrgId.current === targetOrgId) showPruneRequest(undefined);
  }

  const applyResource = useCallback((next: AuditLogRetentionResource) => {
    setResource(next);
    setMode(next.retention_days == null ? "forever" : "bounded");
    setRetentionDays(String(next.retention_days ?? 365));
    setCleanupInterval(String(next.cleanup_interval_minutes));
  }, []);

  const load = useCallback(async () => {
    const request = ++loadRequest.current;
    setEditorOpen(false);
    setConfirmSave(false);
    setLoading(true);
    setLoadError(null);
    setResource(null);
    setSaveError(null);
    setSaveConflict(false);
    setNotice(null);
    try {
      const result = await getRetention(orgId);
      if (request !== loadRequest.current) return;
      if (result.error || !result.data) {
        setLoadError(
          apiErrorMessage(
            result.error,
            "Could not load the audit-log retention policy.",
          ),
        );
        return;
      }
      applyResource(result.data);
    } catch {
      if (request === loadRequest.current) setLoadError("Could not reach the API.");
    } finally {
      if (request === loadRequest.current) setLoading(false);
    }
  }, [applyResource, orgId]);

  useEffect(() => {
    setEditorOpen(false);
    setConfirmSave(false);
    setSaveBusy(false);
    setConfirmPrune(false);
    showPruneRequest(pruneRequests.current.get(orgId));
    void load();
    return () => {
      loadRequest.current += 1;
    };
  }, [load]);

  const parsedDays = integerInRange(
    retentionDays,
    AUDIT_RETENTION_DAYS_MIN,
    AUDIT_RETENTION_DAYS_MAX,
  );
  const parsedInterval = integerInRange(
    cleanupInterval,
    AUDIT_CLEANUP_INTERVAL_MINUTES_MIN,
    AUDIT_CLEANUP_INTERVAL_MINUTES_MAX,
  );
  const retentionDaysError =
    mode === "bounded" && parsedDays === null
      ? `Retention must be a whole number from ${AUDIT_RETENTION_DAYS_MIN} to ${AUDIT_RETENTION_DAYS_MAX} days.`
      : null;
  const cleanupIntervalError =
    parsedInterval === null
      ? `Cleanup interval must be a whole number from ${AUDIT_CLEANUP_INTERVAL_MINUTES_MIN} to ${AUDIT_CLEANUP_INTERVAL_MINUTES_MAX} minutes.`
      : null;
  const draftError = retentionDaysError ?? cleanupIntervalError;
  const selectedDays = mode === "forever" ? null : parsedDays;
  const changed =
    resource !== null &&
    (selectedDays !== resource.retention_days ||
      parsedInterval !== resource.cleanup_interval_minutes);
  const destructiveSave =
    resource !== null &&
    mode === "bounded" &&
    parsedDays !== null &&
    (resource.retention_days == null || parsedDays < resource.retention_days);

  function resetDraft() {
    if (resource) applyResource(resource);
    setSaveError(null);
    setSaveConflict(false);
    setConfirmSave(false);
  }

  function openEditor() {
    resetDraft();
    setEditorOpen(true);
  }

  function dismissEditor() {
    if (saveBusy) return;
    resetDraft();
    setEditorOpen(false);
  }

  function requestSave() {
    if (!resource || draftError || !changed) return;
    if (destructiveSave) {
      setSaveError(null);
      setSaveConflict(false);
      setConfirmSave(true);
      return;
    }
    void save();
  }

  async function save() {
    if (!resource || parsedInterval === null || (mode === "bounded" && parsedDays === null)) {
      return;
    }
    const requestedOrgId = orgId;
    setSaveBusy(true);
    setSaveError(null);
    setSaveConflict(false);
    setNotice(null);
    try {
      const result = await putRetention(
        requestedOrgId,
        resource,
        mode === "forever" ? null : parsedDays,
        parsedInterval,
      );
      if (activeOrgId.current !== requestedOrgId) return;
      if (result.error || !result.data) {
        const conflict =
          apiErrorCode(result.error) === "audit_log_retention_revision_conflict";
        setSaveConflict(conflict);
        setSaveError(
          conflict
            ? "This retention policy changed after it was loaded. Reload the current policy before trying again."
            : apiErrorMessage(
                result.error,
                "Could not save the audit-log retention policy.",
              ),
        );
        return;
      }
      applyResource(result.data);
      setNotice({ text: "Audit-log retention policy saved.", tone: "success" });
      setConfirmSave(false);
      setEditorOpen(false);
    } catch {
      if (activeOrgId.current === requestedOrgId) {
        setSaveError("Could not reach the API. The retention policy was not confirmed.");
      }
    } finally {
      if (activeOrgId.current === requestedOrgId) setSaveBusy(false);
    }
  }

  function openPruneConfirmation() {
    if (!resource || resource.retention_days == null) return;
    const existing = pruneRequests.current.get(orgId);
    const next =
      existing ?? {
        key: newIdempotencyKey(),
        inFlight: false,
        outcomeUnknown: false,
        error: null,
      };
    storePruneRequest(orgId, next);
    setConfirmPrune(true);
  }

  function dismissPrune() {
    if (pruneBusy) return;
    setConfirmPrune(false);
    const request = pruneRequests.current.get(orgId);
    if (!request?.outcomeUnknown) {
      clearPruneRequest(orgId);
    }
  }

  function startNewPruneRequest() {
    if (pruneBusy) return;
    storePruneRequest(orgId, {
      key: newIdempotencyKey(),
      inFlight: false,
      outcomeUnknown: false,
      error: null,
    });
  }

  async function runPrune() {
    const requestedOrgId = orgId;
    const existing = pruneRequests.current.get(requestedOrgId);
    if (existing?.inFlight) return;
    const idempotencyKey = existing?.key ?? newIdempotencyKey();
    storePruneRequest(requestedOrgId, {
      key: idempotencyKey,
      inFlight: true,
      outcomeUnknown: false,
      error: null,
    });
    setNotice(null);
    try {
      const result = await pruneRetention(requestedOrgId, idempotencyKey);
      if (result.error || !result.data) {
        storePruneRequest(requestedOrgId, {
          key: idempotencyKey,
          inFlight: false,
          outcomeUnknown: true,
          error: apiErrorMessage(
            result.error,
            "Could not run audit-log pruning.",
          ),
        });
        return;
      }
      clearPruneRequest(requestedOrgId);
      if (activeOrgId.current !== requestedOrgId) return;
      applyResource(result.data.retention);
      const run = result.data.run;
      if (run.status === "failed") {
        const code = run.error_code ? ` (${run.error_code})` : "";
        setNotice({
          text: `Audit-log pruning failed${code} after deleting ${run.deleted_rows.toLocaleString()} ${run.deleted_rows === 1 ? "row" : "rows"}. Start a new manual prune to retry with a new request key.`,
          tone: "danger",
        });
      } else {
        setNotice({
          text:
            run.status === "running"
              ? "Audit-log pruning started. Refresh status to follow the run."
              : `Audit-log pruning completed. ${run.deleted_rows.toLocaleString()} rows deleted.`,
          tone: "success",
        });
      }
      setConfirmPrune(false);
    } catch {
      storePruneRequest(requestedOrgId, {
        key: idempotencyKey,
        inFlight: false,
        outcomeUnknown: true,
        error:
          "Could not reach the API. The pruning outcome is unknown; retry uses the same request key.",
      });
    }
  }

  if (loading || !resource) {
    return (
      <SettingRow
        label="Audit-log retention"
        description="Controls how long this organization keeps control-plane audit evidence."
      >
        {loadError ? (
          <div className="max-w-md text-left">
            <ErrorText>{loadError}</ErrorText>
            <Button className="mt-2" size="sm" variant="ghost" onClick={() => void load()}>
              Retry audit retention
            </Button>
          </div>
        ) : (
          <Loading size="inline" label="Loading audit-log retention policy…" />
        )}
      </SettingRow>
    );
  }

  const summary = runSummary(resource.last_run);
  const bounded = resource.retention_days != null;

  return (
    <>
      <SettingRow
        label="Audit-log retention"
        description="Forever preserves the existing append-only history. A bounded window makes older control-plane audit rows eligible for policy-bound deletion."
      >
        <div className="flex items-center gap-3">
          <SettingValue>
            {bounded
              ? `${resource.retention_days} days · every ${formatInterval(resource.cleanup_interval_minutes)}`
              : "Forever"}
          </SettingValue>
          <Button
            variant="ghost"
            disabled={!canEdit || saveBusy}
            onClick={openEditor}
          >
            Edit audit-log policy
          </Button>
        </div>
      </SettingRow>

      {editorOpen && (
        <Modal
          title={
            confirmSave && parsedDays !== null
              ? `Change audit-log retention to ${parsedDays} days?`
              : "Edit audit-log retention"
          }
          danger={confirmSave}
          onDismiss={dismissEditor}
          actions={
            confirmSave && parsedDays !== null ? (
              <>
                <Button
                  variant="ghost"
                  disabled={saveBusy}
                  onClick={() => {
                    setConfirmSave(false);
                    setSaveError(null);
                    setSaveConflict(false);
                  }}
                >
                  Back
                </Button>
                <Button
                  variant="danger"
                  disabled={saveBusy}
                  onClick={() => void save()}
                >
                  {saveBusy
                    ? "Saving…"
                    : `Save ${parsedDays}-day retention`}
                </Button>
              </>
            ) : (
              <>
                <Button
                  variant="ghost"
                  disabled={saveBusy}
                  onClick={dismissEditor}
                >
                  Cancel
                </Button>
                <Button
                  disabled={saveBusy || Boolean(draftError) || !changed}
                  onClick={requestSave}
                >
                  {saveBusy ? "Saving…" : "Save audit-log policy"}
                </Button>
              </>
            )
          }
        >
          {confirmSave && parsedDays !== null ? (
            <div className="space-y-3 text-sm text-ink-tertiary">
              <p>
                Saving this {parsedDays}-day window enables the server scheduler
                to permanently delete retention-eligible audit rows older than
                {` ${parsedDays} days`}.
              </p>
              <p>
                Protected provenance may outlive the window. Deleted audit
                evidence cannot be restored.
              </p>
              <ErrorText>{saveError}</ErrorText>
              {saveConflict && (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={saveBusy}
                  onClick={() => void load()}
                >
                  Reload audit-log policy
                </Button>
              )}
            </div>
          ) : (
            <div className="space-y-4">
              <Field label="Retention mode">
                <Select
                  value={mode}
                  disabled={saveBusy}
                  onChange={(event) => {
                    setMode(event.target.value as RetentionMode);
                    setSaveError(null);
                    setSaveConflict(false);
                  }}
                >
                  <option value="forever">Forever</option>
                  <option value="bounded">Bounded window</option>
                </Select>
              </Field>
              <div className="grid gap-3 sm:grid-cols-2">
                {mode === "bounded" && (
                  <div>
                    <Field label="Retention duration (days)">
                      <Input
                        type="number"
                        inputMode="numeric"
                        min={AUDIT_RETENTION_DAYS_MIN}
                        max={AUDIT_RETENTION_DAYS_MAX}
                        step={1}
                        value={retentionDays}
                        disabled={saveBusy}
                        aria-invalid={Boolean(retentionDaysError)}
                        aria-describedby={
                          retentionDaysError
                            ? retentionDaysErrorId
                            : undefined
                        }
                        onChange={(event) => {
                          setRetentionDays(event.target.value);
                          setSaveError(null);
                          setSaveConflict(false);
                        }}
                      />
                    </Field>
                    {retentionDaysError && (
                      <p
                        id={retentionDaysErrorId}
                        role="alert"
                        className="mt-1 text-xs text-danger"
                      >
                        {retentionDaysError}
                      </p>
                    )}
                  </div>
                )}
                <div>
                  <Field label="Cleanup interval (minutes)">
                    <Input
                      type="number"
                      inputMode="numeric"
                      min={AUDIT_CLEANUP_INTERVAL_MINUTES_MIN}
                      max={AUDIT_CLEANUP_INTERVAL_MINUTES_MAX}
                      step={1}
                      value={cleanupInterval}
                      disabled={saveBusy}
                      aria-invalid={Boolean(cleanupIntervalError)}
                      aria-describedby={
                        cleanupIntervalError
                          ? cleanupIntervalErrorId
                          : undefined
                      }
                      onChange={(event) => {
                        setCleanupInterval(event.target.value);
                        setSaveError(null);
                        setSaveConflict(false);
                      }}
                    />
                  </Field>
                  {cleanupIntervalError && (
                    <p
                      id={cleanupIntervalErrorId}
                      role="alert"
                      className="mt-1 text-xs text-danger"
                    >
                      {cleanupIntervalError}
                    </p>
                  )}
                </div>
              </div>
              <p className="text-xs text-ink-tertiary">
                Switching to a bounded window is irreversible for rows deleted
                after the policy takes effect. It never flushes current evidence
                immediately.
              </p>
              <ErrorText>{saveError}</ErrorText>
              {saveConflict && (
                <Button
                  size="sm"
                  variant="ghost"
                  disabled={saveBusy}
                  onClick={() => void load()}
                >
                  Reload audit-log policy
                </Button>
              )}
            </div>
          )}
        </Modal>
      )}

      <SettingRow
        label="Audit-log deletion boundary"
        description="Ordinary update, delete, and truncate operations remain blocked at the database. Only the saved age policy can authorize old rows in bounded transactions."
      >
        <SettingValue>{bounded ? `Older than ${resource.retention_days} days` : "No deletion"}</SettingValue>
      </SettingRow>

      <SettingRow
        label="Last audit-log pruning run"
        description={
          resource.last_run
            ? `${resource.last_run.trigger} run ${resource.last_run.completed_at ? `completed ${dateLabel(resource.last_run.completed_at)}` : `started ${dateLabel(resource.last_run.started_at)}`}.`
            : "No scheduled or manual audit-log pruning run has been recorded."
        }
      >
        <SettingValue tone={summary.tone}>{summary.text}</SettingValue>
      </SettingRow>

      <SettingRow
        label="Next audit-log pruning"
        description="The server scheduler uses the saved organization policy; browser state does not affect it."
      >
        <div className="flex items-center gap-2">
          <SettingValue>
            {!bounded
              ? "Disabled while retention is Forever"
              : resource.next_run_at
                ? dateLabel(resource.next_run_at)
                : "Not scheduled yet"}
          </SettingValue>
          <Button size="sm" variant="ghost" disabled={loading || pruneBusy} onClick={() => void load()}>
            Refresh audit status
          </Button>
        </div>
      </SettingRow>

      <SettingRow
        label="Run audit-log pruning now"
        description={
          bounded
            ? `Runs the saved ${resource.retention_days}-day policy in server-bounded batches of at most ${resource.batch_size.toLocaleString()} rows. No browser-selected cutoff is accepted.`
            : "Manual pruning is unavailable while audit logs are retained forever."
        }
      >
        <Button
          size="sm"
          variant="ghost"
          disabled={!canEdit || pruneBusy || !bounded}
          onClick={openPruneConfirmation}
        >
          Review audit-log prune
        </Button>
      </SettingRow>

      <SettingRow
        label="Control-plane audit evidence"
        description="Review the retained actor, action, target, and recorded metadata."
      >
        <Link className="text-sm font-medium text-accent-400 hover:underline" to="/audit">
          View Audit Log
        </Link>
      </SettingRow>

      {!canEdit && (
        <p role="status" className="py-3 text-xs text-ink-tertiary">
          Verify your email before changing retention or starting maintenance.
        </p>
      )}
      {notice && (
        <p
          role={notice.tone === "danger" ? "alert" : "status"}
          className={`py-3 text-xs ${notice.tone === "danger" ? "text-danger" : "text-accent-400"}`}
        >
          {notice.text}
        </p>
      )}

      {confirmPrune && resource.retention_days != null && (
        <Modal
          title="Run audit-log pruning now?"
          danger
          onDismiss={dismissPrune}
          actions={
            <>
              <Button variant="ghost" disabled={pruneBusy} onClick={dismissPrune}>
                Cancel
              </Button>
              {pruneOutcomeUnknown && (
                <Button
                  variant="ghost"
                  disabled={pruneBusy}
                  onClick={startNewPruneRequest}
                >
                  Start new audit prune request
                </Button>
              )}
              <Button variant="danger" disabled={pruneBusy} onClick={() => void runPrune()}>
                {pruneBusy ? "Pruning…" : pruneError ? "Retry audit-log pruning" : "Run audit-log policy prune"}
              </Button>
            </>
          }
        >
          <div className="space-y-3 text-sm text-ink-tertiary">
            <p>
              The server will permanently delete only this organization’s retention-eligible audit rows older than {resource.retention_days} days, in batches of at most {resource.batch_size.toLocaleString()} rows.
            </p>
            <p>Audit evidence pinned as durable operation provenance is protected and may outlive the window. There is no flush-all control and no caller-selected cutoff. Deleted audit evidence cannot be restored.</p>
            {pruneOutcomeUnknown && (
              <p role="status">
                Retrying reuses the previous request key so the server cannot start a duplicate run. Starting a new request explicitly abandons that protection.
              </p>
            )}
            <ErrorText>{pruneError}</ErrorText>
          </div>
        </Modal>
      )}
    </>
  );
}

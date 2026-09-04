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
  SettingRow,
  SettingValue,
} from "./ui";

export const RETENTION_DAYS_MIN = 1;
export const RETENTION_DAYS_MAX = 3650;
export const CLEANUP_INTERVAL_MINUTES_MIN = 5;
export const CLEANUP_INTERVAL_MINUTES_MAX = 1440;

type RetentionRun = components["schemas"]["AccessEventRetentionRun"];
type Notice = { text: string; tone: "success" | "danger" };
type PruneRequestState = {
  key: string;
  inFlight: boolean;
  outcomeUnknown: boolean;
  error: string | null;
};

export type AccessEventRetentionResource =
  components["schemas"]["AccessEventRetention"];

const RETENTION_PATH =
  "/api/v1/organizations/{orgId}/access-event-retention";
const PRUNE_PATH =
  "/api/v1/organizations/{orgId}/access-event-retention/actions/prune";

async function getRetention(orgId: string) {
  return api.GET(
    RETENTION_PATH,
    { params: { path: { orgId } } },
  );
}

async function putRetention(
  orgId: string,
  resource: AccessEventRetentionResource,
  retentionDays: number,
  cleanupIntervalMinutes: number,
) {
  return api.PUT(
    RETENTION_PATH,
    {
      params: { path: { orgId } },
      body: {
        retention_days: retentionDays,
        cleanup_interval_minutes: cleanupIntervalMinutes,
        expected_revision: resource.revision,
      },
    },
  );
}

async function pruneRetention(
  orgId: string,
  idempotencyKey: string,
) {
  return api.POST(
    PRUNE_PATH,
    {
      params: { path: { orgId } },
      body: { idempotency_key: idempotencyKey },
    },
  );
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

function runSummary(run: RetentionRun | null | undefined) {
  if (!run) {
    return { text: "Not run yet", tone: "muted" as const };
  }
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
  const pending = run.more_pending ? " · more eligible rows remain" : "";
  return {
    text: `${run.deleted_rows.toLocaleString()} rows deleted in ${run.batches.toLocaleString()} ${run.batches === 1 ? "batch" : "batches"}${pending}`,
    tone: run.more_pending ? ("warn" as const) : ("muted" as const),
  };
}

function isRevisionConflict(error: unknown): boolean {
  return apiErrorCode(error) === "access_event_retention_revision_conflict";
}

export function AccessEventRetentionSettings({
  orgId,
  canEdit,
}: {
  orgId: string;
  canEdit: boolean;
}) {
  const [resource, setResource] =
    useState<AccessEventRetentionResource | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [retentionDays, setRetentionDays] = useState("");
  const [cleanupInterval, setCleanupInterval] = useState("");
  const [editorOpen, setEditorOpen] = useState(false);
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

  const applyResource = useCallback((next: AccessEventRetentionResource) => {
    setResource(next);
    setRetentionDays(String(next.retention_days));
    setCleanupInterval(String(next.cleanup_interval_minutes));
  }, []);

  const load = useCallback(async () => {
    const request = ++loadRequest.current;
    setEditorOpen(false);
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
            "Could not load the access-event retention policy.",
          ),
        );
        return;
      }
      applyResource(result.data);
    } catch {
      if (request === loadRequest.current) {
        setLoadError("Could not reach the API.");
      }
    } finally {
      if (request === loadRequest.current) setLoading(false);
    }
  }, [applyResource, orgId]);

  useEffect(() => {
    setEditorOpen(false);
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
    RETENTION_DAYS_MIN,
    RETENTION_DAYS_MAX,
  );
  const parsedInterval = integerInRange(
    cleanupInterval,
    CLEANUP_INTERVAL_MINUTES_MIN,
    CLEANUP_INTERVAL_MINUTES_MAX,
  );
  const retentionDaysError =
    parsedDays === null
      ? `Retention must be a whole number from ${RETENTION_DAYS_MIN} to ${RETENTION_DAYS_MAX} days.`
      : null;
  const cleanupIntervalError =
    parsedInterval === null
      ? `Cleanup interval must be a whole number from ${CLEANUP_INTERVAL_MINUTES_MIN} to ${CLEANUP_INTERVAL_MINUTES_MAX} minutes.`
      : null;
  const draftError = retentionDaysError ?? cleanupIntervalError;
  const changed =
    resource !== null &&
    (parsedDays !== resource.retention_days ||
      parsedInterval !== resource.cleanup_interval_minutes);

  function resetDraft() {
    if (resource) applyResource(resource);
    setSaveError(null);
    setSaveConflict(false);
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

  async function save() {
    if (!resource || parsedDays === null || parsedInterval === null) return;
    const requestedOrgId = orgId;
    setSaveBusy(true);
    setSaveError(null);
    setSaveConflict(false);
    setNotice(null);
    try {
      const result = await putRetention(
        requestedOrgId,
        resource,
        parsedDays,
        parsedInterval,
      );
      if (activeOrgId.current !== requestedOrgId) return;
      if (result.error || !result.data) {
        const conflict = isRevisionConflict(result.error);
        setSaveConflict(conflict);
        setSaveError(
          conflict
            ? "This retention policy changed after it was loaded. Reload the current policy before trying again."
            : apiErrorMessage(
                result.error,
                "Could not save the access-event retention policy.",
              ),
        );
        return;
      }
      applyResource(result.data);
      setNotice({
        text: "Access-event retention policy saved.",
        tone: "success",
      });
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
            "Could not run access-event pruning.",
          ),
        });
        return;
      }
      clearPruneRequest(requestedOrgId);
      if (activeOrgId.current !== requestedOrgId) return;
      applyResource(result.data.retention);
      const lastRun = result.data.run;
      if (lastRun.status === "failed") {
        const code = lastRun.error_code ? ` (${lastRun.error_code})` : "";
        setNotice({
          text: `Access-event pruning failed${code} after deleting ${lastRun.deleted_rows.toLocaleString()} ${lastRun.deleted_rows === 1 ? "row" : "rows"}. Start a new manual prune to retry with a new request key.`,
          tone: "danger",
        });
      } else {
        setNotice({
          text:
            lastRun.status === "running"
              ? "Access-event pruning started. Refresh status to follow the run."
              : `Access-event pruning completed. ${lastRun.deleted_rows.toLocaleString()} rows deleted.`,
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
        label="Access-event retention"
        description="Controls the organization’s queryable access-event window and scheduled pruning cadence."
      >
        {loadError ? (
          <div className="max-w-md text-left">
            <ErrorText>{loadError}</ErrorText>
            <Button className="mt-2" size="sm" variant="ghost" onClick={() => void load()}>
              Retry
            </Button>
          </div>
        ) : (
          <Loading size="inline" label="Loading retention policy…" />
        )}
      </SettingRow>
    );
  }

  const summary = runSummary(resource.last_run);

  return (
    <>
      <SettingRow
        label="Access-event retention"
        description="Events older than this ingest-time window become eligible for pruning. The row target is an independent bounded-cleanup threshold."
      >
        <div className="flex items-center gap-3">
          <SettingValue>
            {resource.retention_days} days · every {formatInterval(resource.cleanup_interval_minutes)}
          </SettingValue>
          <Button
            variant="ghost"
            disabled={!canEdit || saveBusy}
            onClick={openEditor}
          >
            Edit policy
          </Button>
        </div>
      </SettingRow>

      {editorOpen && (
        <Modal
          title="Edit access-event retention"
          onDismiss={dismissEditor}
          actions={
            <>
              <Button variant="ghost" disabled={saveBusy} onClick={dismissEditor}>
                Cancel
              </Button>
              <Button
                disabled={saveBusy || Boolean(draftError) || !changed}
                onClick={() => void save()}
              >
                {saveBusy ? "Saving…" : "Save retention policy"}
              </Button>
            </>
          }
        >
          <div className="space-y-4">
            <div className="grid gap-3 sm:grid-cols-2">
              <div>
                <Field label="Retention duration (days)">
                  <Input
                    type="number"
                    inputMode="numeric"
                    min={RETENTION_DAYS_MIN}
                    max={RETENTION_DAYS_MAX}
                    step={1}
                    value={retentionDays}
                    disabled={saveBusy}
                    aria-invalid={Boolean(retentionDaysError)}
                    aria-describedby={
                      retentionDaysError ? retentionDaysErrorId : undefined
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
              <div>
                <Field label="Cleanup interval (minutes)">
                  <Input
                    type="number"
                    inputMode="numeric"
                    min={CLEANUP_INTERVAL_MINUTES_MIN}
                    max={CLEANUP_INTERVAL_MINUTES_MAX}
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
              Shortening retention does not flush the table immediately. It makes older rows eligible for the next scheduled or manual policy-bound prune.
            </p>
            <ErrorText>{saveError}</ErrorText>
            {saveConflict && (
              <Button size="sm" variant="ghost" disabled={saveBusy} onClick={() => void load()}>
                Reload current policy
              </Button>
            )}
          </div>
        </Modal>
      )}

      <SettingRow
        label="Database pruning target"
        description="Pruning also works toward retaining this many newest access events for the organization, even when they are inside the age window. Counts can temporarily exceed the target between bounded runs."
      >
        <SettingValue>{resource.row_cap.toLocaleString()} rows</SettingValue>
      </SettingRow>

      <SettingRow
        label="Last pruning run"
        description={
          resource.last_run
            ? `${resource.last_run.trigger} run ${resource.last_run.completed_at ? `completed ${dateLabel(resource.last_run.completed_at)}` : `started ${dateLabel(resource.last_run.started_at)}`}.`
            : "No scheduled or manual pruning run has been recorded for this organization."
        }
      >
        <SettingValue tone={summary.tone}>{summary.text}</SettingValue>
      </SettingRow>

      <SettingRow
        label="Next scheduled pruning"
        description="The scheduler uses the saved organization policy; changing browser tabs does not affect it."
      >
        <div className="flex items-center gap-2">
          <SettingValue>
            {resource.next_run_at ? dateLabel(resource.next_run_at) : "Not scheduled yet"}
          </SettingValue>
          <Button size="sm" variant="ghost" disabled={loading || pruneBusy} onClick={() => void load()}>
            Refresh status
          </Button>
        </div>
      </SettingRow>

      <SettingRow
        label="Run pruning now"
        description={`Runs the saved ${resource.retention_days}-day and ${resource.row_cap.toLocaleString()}-row policy in server-bounded batches. There is no flush-all or browser-selected cutoff.`}
      >
        <Button size="sm" variant="ghost" disabled={!canEdit || pruneBusy} onClick={openPruneConfirmation}>
          Review manual prune
        </Button>
      </SettingRow>

      <SettingRow
        label="Access-event evidence"
        description="Review the retained allow, deny, termination, and integrity-gap records."
      >
        <Link className="text-sm font-medium text-accent-400 hover:underline" to="/access-events">
          View Access Events
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

      {confirmPrune && (
        <Modal
          title="Run access-event pruning now?"
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
                  Start new prune request
                </Button>
              )}
              <Button variant="danger" disabled={pruneBusy} onClick={() => void runPrune()}>
                {pruneBusy ? "Pruning…" : pruneError ? "Retry pruning" : "Run policy-bound prune"}
              </Button>
            </>
          }
        >
          <div className="space-y-3 text-sm text-ink-tertiary">
            <p>
              The server will delete only this organization’s events that are older than {resource.retention_days} days or exceed its {resource.row_cap.toLocaleString()}-row cap. Work is limited to server-controlled batches.
            </p>
            <p>This action cannot choose a different cutoff and cannot flush every event.</p>
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

import { useCallback, useEffect, useState } from "react";
import { api, apiErrorMessage, loadOne, type HealthCheck } from "../lib/api";
import { Button, Card, ErrorText, Field, Input, Select } from "./ui";
import { LoadRetry } from "./LoadRetry";
import { POSTURE_HONESTY_LINE, buildOsVersionParam, checkModeOf, osVersionCoverage, osVersionMins, wouldFailCopy, type CheckMode } from "../lib/postureview";

export function PostureChecksSection({
  orgId,
  canManage,
}: {
  orgId: string;
  canManage: boolean;
}) {
  const [checks, setChecks] = useState<HealthCheck[] | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [saveNote, setSaveNote] = useState<string | null>(null);
  // os_version editor state (min inputs live-preview the coverage indicator).
  const [osMode, setOsMode] = useState<CheckMode>("off");
  const [osMacos, setOsMacos] = useState("");
  const [osWindows, setOsWindows] = useState("");

  const load = useCallback(async () => {
    const r = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/health-checks", {
        params: { path: { orgId } },
      }),
    );
    setLoadError(r.ok ? null : r.error);
    if (r.ok) {
      const list = r.data as HealthCheck[];
      setChecks(list);
      setOsMode(checkModeOf(list, "os_version"));
      const mins = osVersionMins(list.find((c) => c.kind === "os_version"));
      setOsMacos(mins.macos);
      setOsWindows(mins.windows);
    }
  }, [orgId]);
  useEffect(() => {
    load();
  }, [load]);

  async function saveCheck(
    kind: HealthCheck["kind"],
    mode: CheckMode,
    param?: Record<string, unknown> | null,
  ) {
    setBusy(true);
    setErr(null);
    setSaveNote(null);
    if (mode === "off") {
      const { error } = await api.DELETE(
        "/api/v1/organizations/{orgId}/health-checks/{checkKind}",
        {
          params: { path: { orgId, checkKind: kind } },
        },
      );
      setBusy(false);
      if (error)
        return setErr(apiErrorMessage(error, "Could not turn the check off."));
      return load();
    }
    const { data, error } = await api.PUT(
      "/api/v1/organizations/{orgId}/health-checks/{checkKind}",
      {
        params: { path: { orgId, checkKind: kind } },
        body: {
          mode,
          param: (param ?? undefined) as Record<string, never> | undefined,
        },
      },
    );
    setBusy(false);
    if (error)
      return setErr(apiErrorMessage(error, "Could not save the check."));
    setSaveNote(
      wouldFailCopy(mode, (data as HealthCheck | undefined)?.would_fail_count),
    );
    load();
  }

  function saveOsVersion() {
    if (osMode === "off") return saveCheck("os_version", "off");
    const param = buildOsVersionParam({ macos: osMacos, windows: osWindows });
    if (!param)
      return setErr(
        "Set a minimum version for at least one platform, or turn the check off.",
      );
    return saveCheck("os_version", osMode, param);
  }

  const diskMode = checkModeOf(checks, "disk_encryption");
  const coverage = osVersionCoverage({
    macos: osMode === "off" ? "" : osMacos,
    windows: osMode === "off" ? "" : osWindows,
  });

  return (
    <Card className="mt-4">
      <h2 className="text-sm font-semibold text-slate-300">
        Device posture checks
      </h2>
      <p className="mt-1 text-xs text-slate-500">
        Per-check requirements evaluated on every device self-report.{" "}
        <span className="text-slate-400">warn</span> surfaces a warning;{" "}
        <span className="text-amber-300">require</span> disconnects a
        non-compliant device within seconds of its report.
      </p>
      {/* The honesty line — verbatim, at the point of configuration (D6, locked). */}
      <div className="mt-2 rounded-md border border-white/10 bg-white/5 px-3 py-2 text-xs text-slate-400">
        {POSTURE_HONESTY_LINE}
      </div>

      {loadError && <LoadRetry error={loadError} onRetry={load} />}
      <ErrorText>{err}</ErrorText>
      {saveNote && (
        <div className="mt-3 rounded-md border border-warn/30 bg-warn/5 px-3 py-2 text-xs text-amber-300">
          {saveNote}
        </div>
      )}

      {checks != null && !loadError && (
        <div className="mt-4 space-y-4">
          {/* Disk encryption */}
          <div className="rounded-md bg-white/5 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-200">Disk encryption</p>
                <p className="text-xs text-slate-500">
                  FileVault (macOS) / BitLocker (Windows), as reported by the
                  device.
                </p>
              </div>
              {canManage ? (
                <Select
                  width="auto"
                  value={diskMode}
                  disabled={busy}
                  onChange={(e) =>
                    saveCheck("disk_encryption", e.target.value as CheckMode)
                  }
                >
                  <option value="off">Off</option>
                  <option value="warn">Warn</option>
                  <option value="require">Require</option>
                </Select>
              ) : (
                <span className="text-xs text-slate-400">{diskMode}</span>
              )}
            </div>
            {/* A device that reports the fact as ABSENT (couldn't read it) is UNKNOWN for this
                check — unknown never blocks, and it is not compliance. */}
          </div>

          {/* OS version */}
          <div className="rounded-md bg-white/5 px-3 py-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-slate-200">Minimum OS version</p>
                <p className="text-xs text-slate-500">
                  Per-platform floors; leave a platform empty to not constrain
                  it.
                </p>
              </div>
              {canManage ? (
                <Select
                  width="auto"
                  value={osMode}
                  disabled={busy}
                  onChange={(e) => setOsMode(e.target.value as CheckMode)}
                >
                  <option value="off">Off</option>
                  <option value="warn">Warn</option>
                  <option value="require">Require</option>
                </Select>
              ) : (
                <span className="text-xs text-slate-400">
                  {checkModeOf(checks, "os_version")}
                </span>
              )}
            </div>
            {osMode !== "off" && canManage && (
              <div className="mt-3 flex flex-wrap items-end gap-3">
                <Field label="macOS minimum">
                  <Input
                    value={osMacos}
                    onChange={(e) => setOsMacos(e.target.value)}
                    placeholder="e.g. 14.0"
                  />
                </Field>
                <Field label="Windows minimum">
                  <Input
                    value={osWindows}
                    onChange={(e) => setOsWindows(e.target.value)}
                    placeholder="e.g. 10.0.22631"
                  />
                </Field>
                <Button disabled={busy} onClick={saveOsVersion}>
                  Save
                </Button>
                {/* [6] Windows-version foot-gun: Win 11 reports major 10 (10.0.22000+),
                    so "11.0" would block the whole Windows fleet. Steer to build numbers. */}
                <p className="w-full text-xs text-slate-500">
                  Windows uses build numbers. Windows 11 reports as{" "}
                  <span className="font-mono text-slate-400">10.0.22000</span>,
                  not 11.0. Enter the build (e.g.{" "}
                  <span className="font-mono text-slate-400">10.0.22631</span>{" "}
                  for 23H2); run{" "}
                  <span className="font-mono text-slate-400">winver</span> to
                  check a device.
                </p>
              </div>
            )}
            {/* WF-OVPN-walk-3: "Off" hid the min-version inputs AND the Save button, so the setting
                could not be persisted from the UI (a dead-end). Off has nothing to configure, but it
                still needs its own Save affordance — saveOsVersion() already handles the off case. */}
            {osMode === "off" && canManage && (
              <div className="mt-3">
                <Button disabled={busy} onClick={saveOsVersion}>
                  Save
                </Button>
              </div>
            )}
            {/* THE coverage indicator (ratified rider): every reporting platform is named —
                a constrained platform shows its floor, an unconstrained one SAYS so. Never
                a silent gap. */}
            {osMode !== "off" && (
              <ul className="mt-2 space-y-0.5 text-xs">
                {coverage.map((c) => (
                  <li
                    key={c.platform}
                    className={c.covered ? "text-slate-400" : "text-amber-400"}
                  >
                    {c.label}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </div>
      )}
    </Card>
  );
}

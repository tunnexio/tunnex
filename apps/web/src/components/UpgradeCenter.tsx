import "../resource-summary.css";
import { useCallback, useEffect, useRef, useState } from "react";
import { api, apiErrorCode, apiErrorMessage, type HostUpgradeStatus, type Meta } from "../lib/api";
import { InlineTerminalMfa } from "./InlineTerminalMfa";
import { useAuth } from "../lib/auth";

const activeStates = new Set(["requested", "verifying", "backing_up", "preflight", "pulling", "restarting", "health_check"]);
const stageLabel: Record<string, string> = {
  idle: "Ready",
  requested: "Request accepted",
  verifying: "Verifying signed release",
  backing_up: "Creating and verifying database backup",
  preflight: "Running preflight checks",
  pulling: "Pulling verified images",
  restarting: "Restarting the control plane",
  health_check: "Checking control-plane health",
  healthy: "Upgrade completed and healthy",
  failed: "Upgrade stopped",
};

/** Deployment upgrade surface. Docker/root authority stays in the local runner. */
export function UpgradeCenter() {
  const { state } = useAuth();
  const cpAdmin = state.status === "authed" && Boolean(state.user.cp_admin);
  const [meta, setMeta] = useState<Meta | null>(null);
  const [host, setHost] = useState<HostUpgradeStatus | null>(null);
  const [confirming, setConfirming] = useState(false);
  const [confirmingRerun, setConfirmingRerun] = useState(false);
  // Both host actions need the SA-UI-1 re-authentication (founder ruling).
  const [reauthPassword, setReauthPassword] = useState("");
  const [needsMfa, setNeedsMfa] = useState(false);
  const [busy, setBusy] = useState(false);
  const [reconnecting, setReconnecting] = useState(false);
  const [error, setError] = useState("");
  // A request result is newer than an in-flight polling read. Without this
  // epoch, an initial idle read can land after the accepted POST and hide the
  // durable "Request accepted" state until the next polling interval.
  const refreshEpoch = useRef(0);

  const refresh = useCallback(async () => {
    if (!cpAdmin) return;
    const epoch = refreshEpoch.current;
    try {
      const [metaResult, hostResult] = await Promise.all([
        api.GET("/api/v1/meta"),
        api.GET("/api/v1/admin/upgrade"),
      ]);
      if (epoch !== refreshEpoch.current) return;
      if (metaResult.data) setMeta(metaResult.data);
      if (hostResult.data) setHost(hostResult.data);
      setReconnecting(Boolean(metaResult.error || hostResult.error));
    } catch {
      // Expected while Compose recreates the API. Keep the last durable stage.
      setReconnecting(true);
    }
  }, [cpAdmin]);

  useEffect(() => {
    if (!cpAdmin) return;
    void refresh();
    const timer = window.setInterval(() => void refresh(), activeStates.has(host?.state ?? "") ? 2000 : 10000);
    return () => window.clearInterval(timer);
  }, [cpAdmin, host?.state, refresh]);

  if (!cpAdmin) return null;
  const upgrade = meta?.upgrade;
  const hasAvailableUpgrade = Boolean(upgrade?.available);
  const active = activeStates.has(host?.state ?? "");
  const statusMatchesAvailable = Boolean(host?.target_source_sha && host.target_source_sha === upgrade?.source_sha);
  const showProgress = Boolean(host && (active || host.state === "failed" || (host.state === "healthy" && statusMatchesAvailable)));
  if (!hasAvailableUpgrade && !showProgress) return null;
  if (upgrade && (!upgrade.verified || upgrade.state === "failed")) {
    return (
      <section className="rounded-xl border border-red-400/30 bg-red-400/10 p-4" aria-label="Upgrade blocked">
        <h2 className="text-sm font-semibold text-ink-heading">Update blocked</h2>
        <p className="mt-1 text-sm text-ink-secondary">Installation verification failed. This installation may be tampered or incomplete.</p>
        <p className="mt-2 text-xs text-ink-tertiary">Restore the last verified backup or contact your deployment administrator.</p>
      </section>
    );
  }

  const repairCommand = "curl -fsSL https://get.tunnex.io | sh";
  const requestUpgrade = async (rerun = false) => {
    setBusy(true);
    setError("");
    try {
      const body = host?.reauthentication?.password ? { current_password: reauthPassword } : {};
      const { data, error: requestError } = rerun
        ? await api.POST("/api/v1/admin/upgrade/rerun", { body })
        : await api.POST("/api/v1/admin/upgrade", { body });
      if (apiErrorCode(requestError) === "mfa_step_up_required") {
        setNeedsMfa(true);
        return;
      }
      if (requestError || !data) {
        setError(apiErrorMessage(requestError, "Could not request the host upgrade."));
        return;
      }
      refreshEpoch.current += 1;
      setHost(data);
      setConfirming(false);
      setConfirmingRerun(false);
      setReauthPassword("");
      setNeedsMfa(false);
    } catch {
      setError("Could not reach the API. No new request was confirmed.");
    } finally {
      setBusy(false);
    }
  };

  const reauth = host?.reauthentication;
  const cancelConfirm = () => { setConfirming(false); setConfirmingRerun(false); setReauthPassword(""); setNeedsMfa(false); };
  // The MFA step-up is rendered outside each form (mfaStep): forms must not nest.
  const reauthFields = (submitLabel: string) => (
    <>
      {reauth?.password && (
        <label className="mt-3 block text-sm">Current password
          <input className="mt-1 block w-full rounded-md border border-line bg-transparent px-2 py-1" type="password" autoComplete="current-password" required value={reauthPassword} disabled={busy} onChange={event => setReauthPassword(event.target.value)} />
        </label>
      )}
      {!needsMfa && (
        <div className="mt-3 flex gap-2">
          <button type="submit" className="rounded-md border border-amber-300/40 px-3 py-2 text-sm" disabled={busy}>{busy ? "Requesting…" : submitLabel}</button>
          <button type="button" className="rounded-md border border-line px-3 py-2 text-sm" disabled={busy} onClick={cancelConfirm}>Cancel</button>
        </div>
      )}
      {reauth?.mfa && !needsMfa && <p className="mt-2 text-xs text-ink-secondary">You may be asked to verify MFA.</p>}
    </>
  );
  const mfaStep = (action: string, rerun: boolean) => needsMfa && (
    <InlineTerminalMfa action={action} freshnessSeconds={300} onVerified={() => { setNeedsMfa(false); void requestUpgrade(rerun); }} onCancel={() => setNeedsMfa(false)} />
  );
  const noReauthNote = (what: string) => reauth && !reauth.available && (
    <p className="mt-3 text-sm text-ink-secondary" role="note">{what} needs re-authentication, and your account has no password or authenticator on this server. Set up an authenticator app in your account settings, or run the upgrade on the server.</p>
  );

  const direct = upgrade?.approval_mode === "host_updater" && host?.available;
  // UPG-1 D2 forward fix: the server offers this only for the same verified
  // release (same sequence and source SHA) after a failed upgrade to it.
  const rerunAvailable = Boolean(direct && host?.state === "failed" && host.rerun_available && !hasAvailableUpgrade);
  const titleVersion = statusMatchesAvailable ? (host?.target_version ?? upgrade?.version ?? "new release") : (upgrade?.version ?? host?.target_version ?? "new release");
  return (
    <section className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4" aria-label="Upgrade available">
      <h2 className="text-sm font-semibold text-ink-heading">
        {host?.state === "healthy"
          ? `Tunnex ${titleVersion} upgrade completed`
          : host?.state === "failed" && !hasAvailableUpgrade
            ? `Tunnex ${titleVersion} upgrade stopped`
            : `Tunnex ${titleVersion} is available`}
      </h2>
      {upgrade && (
        <p className="mt-1 text-sm text-ink-secondary">
          {upgrade.compatibility ?? "Review compatibility before upgrading."}
          {upgrade.downtime ? ` Downtime: ${upgrade.downtime}.` : ""}
        </p>
      )}
      <dl className="tnx-resource-facts">
        {upgrade && <div><dt className="font-semibold">Installed version</dt><dd>{upgrade.current_version || "unknown"}</dd></div>}
        <div><dt className="font-semibold">Target version</dt><dd>{titleVersion}</dd></div>
        {host && showProgress && <div><dt className="font-semibold">Upgrade state</dt><dd>{stageLabel[host.state] ?? host.state}</dd></div>}
        {host?.backup_dump && <div><dt className="font-semibold">Database backup</dt><dd>{host.backup_dump}</dd></div>}
        {host?.backup_manifest && <div><dt className="font-semibold">Backup manifest</dt><dd>{host.backup_manifest}</dd></div>}
      </dl>
      {reconnecting && <p className="mt-2 text-xs text-amber-200">Control plane is restarting or temporarily unreachable. Reconnecting…</p>}
      {host?.state === "failed" && (host.reason_code === "local_sharing_unmanaged" ? <p className="mt-2 text-sm text-red-200">Upgrade not started: Local Sharing serving is part of this installation, and the one-command upgrade does not manage it yet. Nothing was changed. Remove the Local Sharing overlay, upgrade, then add it back (deploy/beam/README.md, "Upgrading").</p> : <p className="mt-2 text-sm text-red-200">Upgrade stopped before completion ({host.reason_code ?? "upgrade_failed"}). Review the local runner journal and retain the displayed backup.</p>)}
      {error && <p className="mt-2 text-sm text-red-200" role="alert">{error}</p>}
      {upgrade?.release_notes_url && (
        <a className="mt-2 inline-block text-sm underline" href={upgrade.release_notes_url} target="_blank" rel="noreferrer">Read release notes</a>
      )}

      {direct && hasAvailableUpgrade && !active && !(host?.state === "healthy" && statusMatchesAvailable) && noReauthNote("Upgrading from the dashboard")}
      {direct && hasAvailableUpgrade && !active && !(host?.state === "healthy" && statusMatchesAvailable) && reauth?.available !== false && (
        confirming ? (
          <div className="mt-3 rounded-md border border-amber-300/30 p-3">
            <form aria-label="Confirm upgrade" onSubmit={event => { event.preventDefault(); void requestUpgrade(); }}>
              <p className="text-sm text-ink-secondary">Create and verify a database backup, run preflight, then upgrade this control plane to {upgrade.version}. Running tunnels continue from their applied state during the brief management-plane restart.</p>
              {reauthFields("Confirm upgrade")}
            </form>
            {mfaStep("Upgrade the control plane", false)}
          </div>
        ) : (
          <button type="button" className="mt-3 rounded-md border border-amber-300/40 px-3 py-2 text-sm" onClick={() => setConfirming(true)}>Upgrade control plane</button>
        )
      )}

      {rerunAvailable && noReauthNote("Running the upgrade again")}
      {rerunAvailable && reauth?.available !== false && (
        confirmingRerun ? (
          <div className="mt-3 rounded-md border border-amber-300/30 p-3">
            <form aria-label="Confirm running the upgrade again" onSubmit={event => { event.preventDefault(); void requestUpgrade(true); }}>
              <p className="text-sm text-ink-secondary">Run the same verified release {titleVersion} again. A new database backup is created and verified first, then preflight runs and the upgrade finishes. An older release is never installed.</p>
              {reauthFields("Confirm and run again")}
            </form>
            {mfaStep("Run the upgrade again", true)}
          </div>
        ) : (
          <div className="mt-3">
            <p className="text-sm text-ink-secondary">Running the upgrade again is the supported fix after a failed upgrade.</p>
            <button type="button" className="mt-2 rounded-md border border-amber-300/40 px-3 py-2 text-sm" onClick={() => setConfirmingRerun(true)}>Run the upgrade again</button>
          </div>
        )
      )}

      {!direct && hasAvailableUpgrade && (
        <div className="mt-3">
          <p className="text-sm text-ink-secondary">This installation predates UI-managed upgrades. Repair the managed host upgrade support, then return here.</p>
          <button type="button" className="mt-2 rounded-md border border-amber-300/40 px-3 py-2 text-sm" onClick={() => void navigator.clipboard?.writeText(repairCommand)}>Copy repair installer command</button>
        </div>
      )}
      <p className="mt-2 text-xs text-ink-tertiary">The local runner verifies the signed release, creates the database backup, runs preflight, upgrades, and checks health. The browser and API never receive Docker/root authority.</p>
    </section>
  );
}

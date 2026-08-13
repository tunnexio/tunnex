import { useEffect, useState } from "react";
import { api, type Member, type Meta } from "../lib/api";
import { useAuth } from "../lib/auth";
import { useOrg } from "../lib/useOrg";

/**
 * Read-only upgrade notice. The browser never receives host/Docker authority: it
 * only explains a verified release and points an operator at the host-side runbook.
 * Both the verified flag and the per-org owner/admin check are fail-closed.
 */
export function UpgradeCenter() {
  const { org } = useOrg();
  const { state } = useAuth();
  const [meta, setMeta] = useState<Meta | null>(null);
  const [admin, setAdmin] = useState(false);
  const [requested, setRequested] = useState(false);

  useEffect(() => {
    let cancelled = false;
    if (!org || state.status !== "authed") return;
    void Promise.all([
      api.GET("/api/v1/meta"),
      api.GET("/api/v1/organizations/{orgId}/members", {
        params: { path: { orgId: org.id } },
      }),
    ]).then(([metaRes, membersRes]) => {
      if (cancelled) return;
      setMeta(metaRes.data ?? null);
      const me = (membersRes.data as Member[] | undefined)?.find(
        (m) => m.user_id === state.user.id,
      );
      setAdmin(me?.role === "owner" || me?.role === "admin");
    });
    return () => {
      cancelled = true;
    };
  }, [org, state]);

  const upgrade = meta?.upgrade;
  if (!admin || !upgrade || (!upgrade.available && upgrade.state !== "failed")) return null;
  if (!upgrade.verified || upgrade.state === "failed") {
    return (
      <section className="rounded-xl border border-red-400/30 bg-red-400/10 p-4" aria-label="Upgrade blocked">
        <h2 className="text-sm font-semibold text-ink-heading">Update blocked</h2>
        <p className="mt-1 text-sm text-ink-secondary">Installation verification failed. This installation may be tampered or incomplete.</p>
        <p className="mt-2 text-xs text-ink-tertiary">Restore the last verified backup or contact your administrator.</p>
        <details className="mt-3 text-xs text-ink-tertiary">
          <summary className="cursor-pointer font-medium">View details</summary>
          <p className="mt-2">{upgrade.reason || "Release signature or installation metadata is invalid."}</p>
        </details>
      </section>
    );
  }
  const hostCommand = "./upgrade.sh --apply";
  const copyHostCommand = () => {
    void navigator.clipboard?.writeText(hostCommand);
    setRequested(true);
  };
  return (
    <section className="rounded-xl border border-amber-400/30 bg-amber-400/10 p-4" aria-label="Upgrade available">
      <h2 className="text-sm font-semibold text-ink-heading">
        Tunnex {upgrade.version ?? "new release"} is available
      </h2>
      <p className="mt-1 text-sm text-ink-secondary">
        {upgrade.compatibility ?? "Review compatibility before upgrading."}
        {upgrade.downtime ? ` Downtime: ${upgrade.downtime}.` : ""}
      </p>
      <dl className="mt-3 grid gap-1 text-xs text-ink-tertiary sm:grid-cols-2">
        <div><dt className="font-semibold">Installed version</dt><dd>{upgrade.current_version || "unknown"}</dd></div>
        <div><dt className="font-semibold">Available version</dt><dd>{upgrade.version ?? "new release"}</dd></div>
      </dl>
      {upgrade.release_notes_url && (
        <a className="mt-2 inline-block text-sm underline" href={upgrade.release_notes_url} target="_blank" rel="noreferrer">
          Read release notes
        </a>
      )}
      <details className="mt-3 text-xs text-ink-tertiary">
        <summary className="cursor-pointer font-medium">View upgrade details</summary>
        <dl className="mt-2 grid gap-1 sm:grid-cols-2">
          <div><dt className="font-semibold">Upgrade state</dt><dd>{requested ? "requested" : upgrade.state ?? "available"}</dd></div>
          <div><dt className="font-semibold">Preflight</dt><dd>{upgrade.preflight_state ?? "unknown"}</dd></div>
          <div><dt className="font-semibold">Backup</dt><dd>{upgrade.backup_state ?? "unknown"}</dd></div>
          <div><dt className="font-semibold">Rollback</dt><dd>{upgrade.rollback_state ?? "not_needed"}</dd></div>
        </dl>
      </details>
      <button type="button" className="mt-3 rounded-md border border-amber-300/40 px-3 py-2 text-sm" onClick={copyHostCommand}>
        {requested ? "Host command copied" : "Approve and copy host upgrade command"}
      </button>
      <p className="mt-2 text-xs text-ink-tertiary">
        The host command verifies the release, creates the backup, runs preflight, upgrades, and checks health in one run. The browser never executes Docker/root commands; if health fails, restore guidance is shown on the host.
      </p>
    </section>
  );
}

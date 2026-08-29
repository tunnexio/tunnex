import { useEffect, useState } from "react";
import { api, type LicenseStatus } from "../lib/api";
import { useLicenceResource } from "../lib/licenceResource";
import {
  Button,
  ErrorText,
  Input,
  SettingDialogRow,
  SettingValue,
} from "./ui";
import { Icon, type IconName } from "./Icon";

type PlanTier = "community" | "trial" | "starter" | "growth" | "scale";

const PLAN_VISUALS: Record<
  PlanTier,
  { label: string; icon: IconName; className: string }
> = {
  community: {
    label: "Community",
    icon: "users",
    className: "text-slate-300",
  },
  trial: { label: "Trial", icon: "timer", className: "text-amber-300" },
  starter: { label: "Starter", icon: "rocket", className: "text-sky-300" },
  growth: {
    label: "Growth",
    icon: "chart-no-axes-column-increasing",
    className: "text-violet-300",
  },
  scale: {
    label: "Scale",
    icon: "building-2",
    className: "text-fuchsia-300",
  },
};

function planVisual(tier: string | undefined) {
  const normalized = tier?.toLowerCase() as PlanTier | undefined;
  return normalized && normalized in PLAN_VISUALS
    ? PLAN_VISUALS[normalized]
    : {
        label: tier || "Plan unavailable",
        icon: "key" as IconName,
        className: "text-slate-400",
      };
}

function PlanTierBadge({
  tier,
  prominent = false,
}: {
  tier?: string;
  prominent?: boolean;
}) {
  const visual = planVisual(tier);
  return (
    <span
      className={`inline-flex items-center gap-2 ${prominent ? "text-sm" : "text-xs"}`}
    >
      <span
        aria-hidden
        className={`inline-flex shrink-0 items-center justify-center rounded-lg bg-white/[0.055] ring-1 ring-inset ring-white/[0.08] ${
          prominent ? "h-9 w-9" : "h-7 w-7"
        } ${visual.className}`}
      >
        <Icon name={visual.icon} size={prominent ? 17 : 14} />
      </span>
      <span className="font-medium text-ink-body">{visual.label}</span>
    </span>
  );
}

export type LicenceStatus = LicenseStatus;

export type LicenceCardCache = {
  status: LicenceStatus | null;
  request?: Promise<LicenceStatus | null> | null;
};

/**
 * ⭐ AN OPERATOR WHO PASTES A KEY AND SEES NOTHING CANNOT TELL SUCCESS FROM SILENCE.
 *
 * So this always renders the CURRENT entitlement — tier, gateway ceiling, expiry — and re-renders it from
 * the install response. The change is visible in the same place the action happened.
 *
 * ⛔ AND "unlicensed" IS NOT AN ERROR STATE. A deployment with no key is a complete, supported Community
 * deployment. Rendering it as a problem would be a false claim about a working product.
 */
// ⚠ NO orgId. The licence is DEPLOYMENT-WIDE and the org-scoped URL it used to call was an error — the
// org was never passed to the manager, only to authorization and the audit row. Taking an orgId here would
// have kept implying a per-tenant licence that the data cannot hold.
export function LicenceCard({
  canManage,
  cache,
}: {
  canManage: boolean;
  cache?: LicenceCardCache;
}) {
  const sharedLicence = useLicenceResource();
  const [status, setStatus] = useState<LicenceStatus | null>(
    cache?.status ?? null,
  );
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    if (status) return;
    let cancelled = false;
    const request =
      cache?.request ??
      (sharedLicence
        ? sharedLicence
            .read()
            .then((result) => (result.ok ? (result.data as LicenceStatus) : null))
        : (async () => {
            const { data } = await api.GET("/api/v1/license", {});
            return data ? (data as LicenceStatus) : null;
          })());
    if (cache) cache.request = request;
    void request
      .then((next) => {
        if (!next) return;
        if (cache) cache.status = next;
        if (!cancelled) setStatus(next);
      })
      .finally(() => {
        if (cache?.request === request) cache.request = null;
      });
    return () => {
      cancelled = true;
    };
  }, [cache, sharedLicence, status]);

  // Closes only after the install is confirmed — a licence that failed to apply must leave the key and
  // the reason on screen, not vanish behind a closed dialog.
  async function install(e?: React.FormEvent, onDone?: () => void) {
    e?.preventDefault();
    setBusy(true);
    setError(null);
    const { data, error: err } = await api.POST("/api/v1/license", {
      body: { key: key.trim() },
    });
    setBusy(false);
    if (err) {
      // ⚠ The server's message names WHICH half was wrong and what to do — a truncated key and a key for
      // another deployment need opposite actions. Surfacing it verbatim rather than "invalid key".
      setError(
        (err as { error?: { message?: string } }).error?.message ??
          "That key was not accepted.",
      );
      return;
    }
    if (data) {
      const next = data as LicenceStatus;
      if (cache) cache.status = next;
      sharedLicence?.publish(next);
      setStatus(next);
      setKey("");
      onDone?.();
    }
  }

  const ceiling = (n: number | null | undefined) =>
    n === null || n === undefined ? "unlimited" : String(n);

  // ⛔ THREE STATES THAT LOOK ALIKE AND MUST NOT BE COLLAPSED (S12.1 persistence).
  //
  //   nothing here            → the verdict is current. "No licence installed" is a HEALTHY version of this.
  //   store_stale             → the store is unreachable; the tier shown is the LAST KNOWN one and nobody
  //                             has been downgraded. Reassure BEFORE explaining.
  //   store_rejected          → a key IS stored and does not verify. Community is being served on purpose,
  //                             and the reason is named so the remedy is obvious.
  //
  // ⚠ `self_verify_failed` is why the reason is rendered rather than a generic failure: an opaque refusal
  // cost a live session to diagnose, and the operator reading this has no other source of truth.
  const storeNote =
    status?.store_rejected != null
      ? {
          tone: "warn" as const,
          text: status.store_detail ?? "The stored licence key was rejected.",
        }
      : status?.store_stale
        ? {
            tone: "info" as const,
            text: status.store_detail ?? "Serving the last known entitlement.",
          }
        : null;

  return (
    // ⛔ THE TIER IS THE ANSWER MOST VISITS COME FOR; the ceilings, expiry and state copy are what you
    // read when that answer is surprising. So the row states the tier and the dialog holds the rest —
    // including the key field, which is the one control here and is owner-only.
    <SettingDialogRow
      label="Plan"
      description={
        canManage
          ? "View entitlement or install a licence key."
          : "Deployment entitlement and limits."
      }
      value={
        status ? (
          <PlanTierBadge tier={status.tier} />
        ) : (
          <SettingValue>…</SettingValue>
        )
      }
      actionLabel={canManage ? "Manage" : "View details"}
      dialogTitle="Plan & licence"
      error={error}
      actions={(close) => (
        <>
          <Button variant="ghost" onClick={close}>
            {canManage ? "Cancel" : "Close"}
          </Button>
          {canManage && (
            <Button
              disabled={busy || !key.trim()}
              onClick={() => void install(undefined, close)}
            >
              {busy ? "Installing…" : "Install licence"}
            </Button>
          )}
        </>
      )}
    >
      {() => (
        <div className="flex flex-col gap-1">
      {storeNote && (
        <p
          className={`mt-2 text-cell ${
            storeNote.tone === "warn" ? "text-warn" : "text-ink-secondary"
          }`}
        >
          {storeNote.text}
        </p>
      )}

      {status && (
        <>
          <div className="mb-4 flex items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3">
            <PlanTierBadge tier={status.tier} prominent />
            <span
              className={`text-xs ${
                status.state === "lapsed" || status.state === "expired"
                  ? "text-warn"
                  : "text-ink-tertiary"
              }`}
            >
              {status.state === "unlicensed"
                ? "No key installed"
                : status.state}
            </span>
          </div>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-cell">
            <dt className="text-ink-tertiary">Gateways</dt>
            <dd className="text-ink-body">
              {ceiling(status.gateway_ceiling)}
            </dd>
            <dt className="text-ink-tertiary">Organizations</dt>
            <dd className="text-ink-body">{ceiling(status.org_ceiling)}</dd>
            {status.expires_at && (
              <>
                <dt className="text-ink-tertiary">Expires</dt>
                <dd className="text-ink-body">
                  {status.expires_at.slice(0, 10)}
                </dd>
              </>
            )}
          </dl>
        </>
      )}

      {/* ⛔ EXPIRED IS NOT LAPSED, AND THE COPY MUST NOT CONFLATE THEM. Nothing stops at expiry. */}
      {status?.state === "expired" && (
        <p className="mt-3 text-explainer text-warn">
          This licence expired
          {status.grace_ends_at
            ? ` and its grace period ends ${status.grace_ends_at.slice(0, 10)}`
            : ""}
          . Nothing has stopped — everything keeps working until then.
        </p>
      )}
      {status?.state === "lapsed" && (
        <p className="mt-3 text-explainer text-warn">
          The grace period has ended, so this deployment is back to Community
          limits. Gateways and organizations already running are unaffected —
          only enrolling new ones is.
        </p>
      )}
      {status?.state === "unlicensed" && (
        <p className="mt-3 text-explainer text-ink-tertiary">
          No licence installed. This is the complete product on one gateway and
          one organization.
        </p>
      )}
      {status?.clock_went_backwards && (
        <p className="mt-2 text-explainer text-warn">
          This server's clock moved backwards. Licence dates may read
          incorrectly until it is corrected — nothing has been refused because
          of it.
        </p>
      )}

      {canManage && (
        <div className="mt-4 flex flex-col gap-2">
          <Input
            aria-label="Licence key"
            placeholder="tnxl_…"
            value={key}
            onChange={(e) => setKey(e.target.value)}
          />
          {error && <ErrorText>{error}</ErrorText>}
          {/* ⚠ Says the thing an operator most needs to know before pasting into a live system. */}
          <p className="text-explainer text-ink-tertiary">
            Takes effect immediately. No restart.
          </p>
        </div>
      )}
        </div>
      )}
    </SettingDialogRow>
  );
}

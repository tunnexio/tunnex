import { useEffect, useState } from "react";
import { api } from "../lib/api";
import { Button, Card, ErrorText, Input } from "./ui";

type Status = {
  state: "unlicensed" | "valid" | "expired" | "lapsed";
  tier: string;
  gateway_ceiling?: number | null;
  org_ceiling?: number | null;
  features: string[];
  expires_at?: string | null;
  grace_ends_at?: string | null;
  clock_went_backwards?: boolean;
  // ⚠ STORE HEALTH, NOT ENTITLEMENT. These ride BESIDE the tier and never replace it: a deployment whose
  // store is unreachable is still entitled to whatever it last knew.
  store_stale?: boolean;
  store_rejected?:
    "expired" | "malformed" | "unknown_kid" | "bad_signature" | null;
  store_detail?: string | null;
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
export function LicenceCard({ canManage }: { canManage: boolean }) {
  const [status, setStatus] = useState<Status | null>(null);
  const [key, setKey] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    void (async () => {
      const { data } = await api.GET("/api/v1/license", {});
      if (data) setStatus(data as Status);
    })();
  }, []);

  async function install(e: React.FormEvent) {
    e.preventDefault();
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
      setStatus(data as Status);
      setKey("");
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
    <Card>
      <h2 className="text-title font-semibold text-ink-heading">Licence</h2>

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
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1.5 text-cell">
          <dt className="text-ink-tertiary">Tier</dt>
          <dd className="text-ink-body">{status.tier}</dd>
          <dt className="text-ink-tertiary">Gateways</dt>
          <dd className="text-ink-body">{ceiling(status.gateway_ceiling)}</dd>
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
        <form onSubmit={install} className="mt-4 flex flex-col gap-2">
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
          <Button type="submit" disabled={busy || !key.trim()}>
            {busy ? "Installing…" : "Install licence"}
          </Button>
        </form>
      )}
    </Card>
  );
}

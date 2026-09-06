import { useCallback, useEffect, useRef, useState } from "react";

import {
  api,
  apiErrorMessage,
  loadOne,
  type FQDNResourceSetting,
  type FQDNResourceSettingImpact,
  type Member,
} from "../lib/api";
import { can } from "../lib/rbac";
import { LoadRetry } from "./LoadRetry";
import { Button, Card, ErrorText, Loading, Modal } from "./ui";

type Change = "enable" | "disable";

/**
 * Organization-wide FQDN enforcement is deliberately separate from creating
 * resolver and hostname resources. This control exposes the server's bounded
 * impact preview and sends its opaque token back when enabling; the browser
 * never guesses which rules will compile.
 */
export function FQDNEnforcementSetting({
  orgId,
  role,
}: {
  orgId: string;
  role: Member["role"] | undefined;
}) {
  const canView = can(role, "fqdn_resource:view");
  const canManage = can(role, "fqdn_resource:manage");
  const [setting, setSetting] = useState<FQDNResourceSetting | null>(null);
  const [error, setError] = useState("");
  const [change, setChange] = useState<Change | null>(null);
  const [impact, setImpact] = useState<FQDNResourceSettingImpact | null>(null);
  const [impactError, setImpactError] = useState("");
  const [impactLoading, setImpactLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const settingRequest = useRef(0);
  const impactRequest = useRef(0);

  const reload = useCallback(async () => {
    if (!canView) return;
    const request = ++settingRequest.current;
    setSetting(null);
    setError("");
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/fqdn-resources/setting", {
        params: { path: { orgId } },
      }),
    );
    if (request !== settingRequest.current) return;
    if (!result.ok) {
      setError(result.error);
      return;
    }
    setSetting(result.data as FQDNResourceSetting);
  }, [canView, orgId]);

  useEffect(() => {
    void reload();
    return () => {
      settingRequest.current += 1;
      impactRequest.current += 1;
    };
  }, [reload]);

  const loadImpact = useCallback(async () => {
    const request = ++impactRequest.current;
    setImpact(null);
    setImpactError("");
    setImpactLoading(true);
    const result = await loadOne(() =>
      api.GET("/api/v1/organizations/{orgId}/fqdn-resources/setting/impact", {
        params: { path: { orgId } },
      }),
    );
    if (request !== impactRequest.current) return;
    setImpactLoading(false);
    if (!result.ok) {
      setImpactError(result.error);
      return;
    }
    setImpact(result.data as FQDNResourceSettingImpact);
  }, [orgId]);

  function open(next: Change) {
    setChange(next);
    void loadImpact();
  }

  function dismiss() {
    impactRequest.current += 1;
    setChange(null);
    setImpact(null);
    setImpactError("");
    setImpactLoading(false);
  }

  async function confirm() {
    if (!change || !impact) return;
    const enabling = change === "enable";
    if (enabling && (!impact.entitlement_available || !impact.expected_impact_token)) return;
    setBusy(true);
    setImpactError("");
    try {
      const result = await api.PUT(
        "/api/v1/organizations/{orgId}/fqdn-resources/setting",
        {
          params: { path: { orgId } },
          body: {
            enabled: enabling,
            expected_impact_token: enabling
              ? impact.expected_impact_token ?? null
              : null,
          },
        },
      );
      if (result.error || !result.data) {
        setImpactError(
          apiErrorMessage(
            result.error,
            `Could not ${enabling ? "enable" : "disable"} FQDN enforcement.`,
          ),
        );
        return;
      }
      setSetting(result.data as FQDNResourceSetting);
      dismiss();
    } catch {
      setImpactError("Could not reach the API. The organization setting was not confirmed.");
    } finally {
      setBusy(false);
    }
  }

  if (!canView) return null;
  const enabled = setting?.enabled === true;
  const enabling = change === "enable";
  const confirmDisabled =
    busy ||
    impactLoading ||
    Boolean(impactError) ||
    !impact ||
    (enabling && (!impact.entitlement_available || !impact.expected_impact_token));

  return (
    <Card>
      <section aria-labelledby="fqdn-enforcement-heading" className="space-y-3">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <h2 id="fqdn-enforcement-heading" className="text-lg font-semibold text-ink-heading">
              FQDN enforcement
            </h2>
            <p className="text-sm text-ink-tertiary">
              Organization setting · controls whether eligible FQDN rules may authorize traffic.
            </p>
          </div>
          {setting && (
            <span
              role="status"
              className={`tnx-status rounded-full border px-2.5 py-1 font-mono text-xs font-semibold ${
                enabled
                  ? "border-emerald-800/50 bg-emerald-950/40 text-emerald-400"
                  : "border-warn/40 bg-warn/10 text-warn"
              }`}
            >
              {enabled ? "ENABLED" : "DISABLED · NO FQDN TRAFFIC"}
            </span>
          )}
        </div>

        {setting === null ? (
          error ? (
            <LoadRetry error={`Could not load FQDN enforcement setting: ${error}`} onRetry={() => void reload()} />
          ) : (
            <Loading label="Loading FQDN enforcement setting…" />
          )
        ) : (
          <div className="flex flex-wrap items-center justify-between gap-3 rounded-md border border-line bg-white/[.025] p-3">
            <p className="max-w-3xl text-sm text-ink-tertiary">
              {enabled
                ? "Enabled FQDN rules can compile only when their selected resolver has a current active generation."
                : "FQDN resources and resolver history remain visible, but every FQDN destination fails closed until this setting is enabled."}
            </p>
            {canManage ? (
              <Button variant={enabled ? "ghost" : "enforce"} onClick={() => open(enabled ? "disable" : "enable")}>
                Review and {enabled ? "disable" : "enable"}
              </Button>
            ) : (
              <span className="text-sm text-ink-tertiary">Read only</span>
            )}
          </div>
        )}

        {change && (
          <Modal
            title={`${enabling ? "Enable" : "Disable"} FQDN enforcement?`}
            danger={!enabling}
            onDismiss={dismiss}
            actions={
              <>
                <Button variant="ghost" disabled={busy} onClick={dismiss}>Cancel</Button>
                <Button
                  variant={enabling ? "enforce" : "danger"}
                  disabled={confirmDisabled}
                  onClick={() => void confirm()}
                >
                  {busy ? "Saving…" : `${enabling ? "Enable" : "Disable"} FQDN enforcement`}
                </Button>
              </>
            }
          >
            <div className="space-y-3 text-sm text-ink-tertiary">
              {impactLoading ? (
                <Loading label="Loading server impact preview…" />
              ) : impactError ? (
                <div className="space-y-3">
                  <ErrorText>{impactError}</ErrorText>
                  <Button size="sm" variant="ghost" onClick={() => void loadImpact()}>Retry preview</Button>
                </div>
              ) : impact ? (
                <>
                  {!impact.entitlement_available && enabling && (
                    <p role="alert" className="rounded-md border border-warn/40 bg-warn/10 p-3 text-warn">
                      The server reports that this organization does not have the fqdn_resources licence entitlement. Enabling is unavailable.
                    </p>
                  )}
                  <p>
                    Server preview: <strong className="text-ink-heading">{impact.enforcement_ready_rule_count}</strong>{" "}
                    enforcement-ready {impact.enforcement_ready_rule_count === 1 ? "rule" : "rules"}.
                    {enabling
                      ? " These rules may begin authorizing traffic after the next policy projection."
                      : " These rules will stop authorizing FQDN traffic after the setting is disabled."}
                  </p>
                  {impact.enforcement_ready_rule_ids.length > 0 && (
                    <details className="rounded-md border border-line p-3">
                      <summary className="cursor-pointer text-ink-heading">
                        Review affected rule IDs{impact.rule_ids_truncated ? " (partial list)" : ""}
                      </summary>
                      <ul className="mt-2 space-y-1 font-mono text-xs">
                        {impact.enforcement_ready_rule_ids.map((id) => <li key={id}>{id}</li>)}
                      </ul>
                    </details>
                  )}
                  <p className="text-xs">
                    This preview is recomputed by the server when you confirm. Resolver health, rule lifecycle, and Zero Trust enforcement still apply.
                  </p>
                </>
              ) : null}
            </div>
          </Modal>
        )}
      </section>
    </Card>
  );
}

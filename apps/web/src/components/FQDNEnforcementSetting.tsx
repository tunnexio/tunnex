import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";

import {
  api,
  apiErrorMessage,
  loadOne,
  type FQDNResourceSetting,
  type FQDNResourceSettingImpact,
  type Role,
} from "../lib/api";
import { can } from "../lib/rbac";
import { LoadRetry } from "./LoadRetry";
import { Button, ErrorText, Loading, Modal, SettingRow, SettingValue } from "./ui";

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
  central = false,
  canEdit = false,
}: {
  orgId: string;
  role: Role | readonly Role[] | undefined;
  central?: boolean;
  canEdit?: boolean;
}) {
  return <FQDNSettingForScope key={`${orgId}:${Array.isArray(role) ? role.join(",") : role}:${central}:${canEdit}`} orgId={orgId} role={role} central={central} canEdit={canEdit} />;
}

function FQDNSettingForScope({ orgId, role, central, canEdit }: { orgId: string; role: Role | readonly Role[] | undefined; central: boolean; canEdit: boolean }) {
  const canView = can(role, "fqdn_resource:view");
  const canManage = central && canEdit && can(role, "fqdn_resource:manage");
  const [setting, setSetting] = useState<FQDNResourceSetting | null>(null);
  const [error, setError] = useState("");
  const [change, setChange] = useState<Change | null>(null);
  const [impact, setImpact] = useState<FQDNResourceSettingImpact | null>(null);
  const [impactError, setImpactError] = useState("");
  const [impactLoading, setImpactLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const settingRequest = useRef(0);
  const impactRequest = useRef(0);
  const alive = useRef(true), pending = useRef(false);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);

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
    if (typeof result.data?.enabled !== "boolean") { setError("The server returned incomplete FQDN settings."); return; }
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
    if (!canManage) return;
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
    const value = result.data;
    if (!value || typeof value.enabled !== "boolean" || !Number.isInteger(value.enforcement_ready_rule_count) || value.enforcement_ready_rule_count < 0 || !Array.isArray(value.enforcement_ready_rule_ids) || value.enforcement_ready_rule_ids.some(id => typeof id !== "string") || typeof value.rule_ids_truncated !== "boolean" || typeof value.entitlement_available !== "boolean" || (value.expected_impact_token != null && typeof value.expected_impact_token !== "string")) { setImpactError("The server returned incomplete impact evidence. Retry the preview."); return; }
    setImpact(value as FQDNResourceSettingImpact);
  }, [orgId, canManage]);

  function open(next: Change) {
    if (!canManage || busy) return;
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
    if (!alive.current || !canManage || !change || !impact || pending.current || impactError || impactLoading) return;
    const enabling = change === "enable";
    if (enabling && (!impact.entitlement_available || !impact.expected_impact_token)) return;
    pending.current = true; setBusy(true);
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
      if (!alive.current) return;
      if (result.error || !result.data) {
        setImpactError(
          apiErrorMessage(
            result.error,
            `Could not ${enabling ? "enable" : "disable"} FQDN enforcement.`,
          ),
        );
        return;
      }
      if (typeof result.data.enabled !== "boolean") { setError("The server did not confirm the setting. Reload before retrying."); setSetting(null); dismiss(); return; }
      setSetting(result.data as FQDNResourceSetting);
      dismiss();
    } catch {
      if (alive.current) setImpactError("Could not reach the API. The organization setting was not confirmed.");
    } finally {
      pending.current = false; if (alive.current) setBusy(false);
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

  const status = setting ? enabled ? "Enabled" : "Off · FQDN traffic denied" : error ? "Unavailable" : "Loading…";
  return <>
    {central ? <SettingRow label="FQDN enforcement" description="Allow eligible hostname rules to authorize traffic through a current resolver generation.">
      <div className="features-control"><SettingValue>{status}</SettingValue>{setting && canManage && <Button variant="ghost" disabled={busy} onClick={() => open(enabled ? "disable" : "enable")}>Review and {enabled ? "disable" : "enable"}</Button>}</div>
      {error && <LoadRetry error={`Could not load FQDN enforcement setting: ${error}`} onRetry={() => void reload()} />}
    </SettingRow> : <section id="fqdn-enforcement-heading" className="features-referral" aria-label="FQDN enforcement"><span role="status">FQDN enforcement: {status}</span><Link to="/settings?section=features&feature=fqdn">Manage in Features</Link>{error && <LoadRetry error={`Could not load FQDN enforcement setting: ${error}`} onRetry={() => void reload()} />}</section>}
        {central && change && canManage && (
          <Modal
            placement="right"
            showClose
            title={`${enabling ? "Enable" : "Disable"} FQDN enforcement?`}
            danger={!enabling}
            onDismiss={() => { if (!busy) dismiss(); }}
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
  </>;
}

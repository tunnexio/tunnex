import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage, loadOne } from "../lib/api";
import { Button, Loading, SettingRow, Switch } from "./ui";

type Settings = components["schemas"]["AppAccessSettings"];

export function AppAccessFeatureSettings({ orgId, permitted, canEdit }: {
  orgId: string; permitted: boolean; canEdit: boolean;
}) {
  if (!permitted) return null;
  return <FeatureToggle key={orgId} orgId={orgId} canEdit={canEdit} />;
}

function FeatureToggle({ orgId, canEdit }: { orgId: string; canEdit: boolean }) {
  const [settings, setSettings] = useState<Settings | null>(null);
  const [error, setError] = useState("");
  const [attempt, setAttempt] = useState(0);
  const [busy, setBusy] = useState(false);
  const mounted = useRef(true);
  const changing = useRef(false);
  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);
  useEffect(() => {
    let cancelled = false;
    setSettings(null); setError("");
    void loadOne(() => api.GET("/api/v1/organizations/{orgId}/app-access/settings", {
      params: { path: { orgId } },
    })).then(result => {
      if (cancelled) return;
      if (result.ok) setSettings(result.data);
      else setError(result.error);
    });
    return () => { cancelled = true; };
  }, [orgId, attempt]);

  async function toggle(enabled: boolean) {
    if (!settings || !canEdit || changing.current || error ||
      (enabled && (!settings.entitlement_available || !settings.domain_ready))) return;
    changing.current = true; setBusy(true); setError("");
    try {
      const result = await api.PATCH("/api/v1/organizations/{orgId}/app-access/settings", {
        params: { path: { orgId } },
        body: { enabled, expected_version: settings.version },
      });
      if (!mounted.current) return;
      if (result.error || !result.data) {
        setError(["version_conflict", "stale_version"].includes(apiErrorCode(result.error) ?? "")
          ? "Applications settings changed. Reload the setting before trying again."
          : apiErrorMessage(result.error, "Could not update Applications. Reload to check its current state."));
      } else setSettings(result.data);
    } catch {
      if (mounted.current) setError("Could not reach the API. Reload to check the current setting.");
    } finally {
      changing.current = false;
      if (mounted.current) setBusy(false);
    }
  }
  const enableBlocked = settings && !settings.enabled &&
    (!settings.entitlement_available || !settings.domain_ready);
  return <div>
    <SettingRow label="Applications"
      description="Open private web apps in a browser. Turning this off blocks access; saved apps and grants stay."
      error={error}>
      {settings ? <Switch label="Applications" checked={settings.enabled}
        disabled={!canEdit || busy || !!error || !!enableBlocked} onChange={next => void toggle(next)} />
        : error ? <span className="text-sm text-ink-secondary">Unavailable</span> : <Loading size="inline" label="Loading Applications…" />}
    </SettingRow>
    {settings && !settings.entitlement_available && <p className="text-sm text-ink-secondary">An eligible licence is required to enable Applications.</p>}
    {settings && !settings.domain_ready && <p className="text-sm text-ink-secondary">Configure Applications domains before enabling it.</p>}
    {error && <Button variant="ghost" disabled={busy} onClick={() => setAttempt(value => value + 1)}>Reload Applications setting</Button>}
  </div>;
}

import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import { Button, Card, ErrorText, Modal, SettingRow, SettingValue, Switch } from "./ui";

type Application = components["schemas"]["AppAccessApplication"];

export default function AppAccessMfaPolicy({ orgId, application, canManage, dirty = false, onChanged, onReload }: {
  orgId: string; application: Application; canManage: boolean; dirty?: boolean;
  onChanged: (application: Application) => void; onReload: () => void;
}) {
  const [confirmation, setConfirmation] = useState<boolean | null>(null);
  const [busy, setBusy] = useState(false);
  const locked = useRef(false);
  const active = useRef(true);
  useEffect(() => { active.current = true; return () => { active.current = false; }; }, []);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const known = typeof application.require_mfa === "boolean";
  const editable = canManage && application.state !== "archived" && !dirty;

  async function save() {
    if (confirmation === null || !editable || locked.current) return;
    locked.current = true; setBusy(true); setError(""); setNotice("");
    const desired = confirmation;
    try {
      const result = await api.PATCH("/api/v1/organizations/{orgId}/app-access/applications/{appId}/mfa-policy", {
        params: { path: { orgId, appId: application.id } },
        body: { require_mfa: desired, expected_version: application.version },
      });
      if (!active.current) return;
      if (result.error || !result.data) {
        setError(["stale_version", "version_conflict"].includes(apiErrorCode(result.error) ?? "")
          ? "This application changed. Reload its saved settings before changing MFA."
          : apiErrorMessage(result.error, "Could not update the MFA requirement. Reload to check its current state."));
        return;
      }
      onChanged(result.data);
      setConfirmation(null);
      setNotice(result.data.require_mfa ? "MFA is now required for this application." : "The extra MFA requirement is now off for this application.");
    } catch { if (active.current) setError("Could not confirm the MFA change. Reload the saved settings before trying again."); }
    finally { locked.current = false; if (active.current) setBusy(false); }
  }

  return <Card className="space-y-3" aria-label="Application MFA">
    <h3 className="text-lg font-semibold">Application security</h3>
    <SettingRow label="Require MFA" description="Require recent multi-factor verification before accessing this app. Applies to local and SSO users, independently of organization login requirements.">
      <div className="flex items-center gap-3">
        <SettingValue tone={known && application.require_mfa ? "live" : "muted"}>{known ? application.require_mfa ? "On" : "Off" : "Unavailable"}</SettingValue>
        {canManage && known && <Switch label="Require MFA" checked={application.require_mfa} disabled={!editable || busy} onChange={next => { setError(""); setNotice(""); setConfirmation(next); }} />}
      </div>
    </SettingRow>
    <p className="text-sm text-ink-secondary">A verified MFA check from the last {Math.round((application.mfa_freshness_seconds ?? 900) / 60)} minutes can be reused. Users keep the same account authenticator; they do not enroll separately for each app.</p>
    <p className="text-sm text-ink-secondary">Changes apply immediately, without republishing. Turning this off does not turn off account or organization MFA.</p>
    {dirty && <p role="status" className="text-sm text-ink-secondary">Save or discard draft changes before updating the MFA requirement.</p>}
    {!known && <ErrorText>Could not read this application's MFA policy. Reload its saved settings.</ErrorText>}
    {notice && <p role="status" className="text-sm">{notice}</p>}
    <ErrorText>{error}</ErrorText>
    {(!known || error) && <Button variant="ghost" disabled={busy || dirty} onClick={() => { setConfirmation(null); onReload(); }}>Reload application settings</Button>}
    {confirmation !== null && <Modal title={confirmation ? "Require MFA for this application?" : "Turn off application MFA?"} onDismiss={() => { if (!busy) setConfirmation(null); }} actions={<>
      <Button variant="ghost" disabled={busy} onClick={() => setConfirmation(null)}>Cancel</Button>
      <Button disabled={busy} onClick={() => void save()}>{busy ? "Updating…" : confirmation ? "Enable MFA requirement" : "Turn off MFA requirement"}</Button>
    </>}>
      <p className="text-sm">{confirmation ? "Users without recent MFA will need to verify before continuing. This includes people who already have this application open." : "Users with app permission can open this application without its extra MFA check. Account and organization login requirements remain in effect."}</p>
      <ErrorText>{error}</ErrorText>
    </Modal>}
  </Card>;
}

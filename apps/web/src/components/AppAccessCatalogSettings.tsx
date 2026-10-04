import { useEffect, useRef, useState } from "react";
import type { components } from "@tunnex/shared";
import { api, apiErrorCode, apiErrorMessage } from "../lib/api";
import AppAccessSubjectPicker from "./AppAccessSubjectPicker";
import { Button, Card, ErrorText, Loading } from "./ui";
type Management = components["schemas"]["AppAccessAccessManagement"];
type Subject = components["schemas"]["AppAccessGrantSubjects"]["items"][number];
export default function AppAccessCatalogSettings({ orgId, appId, permitted, dirty, onChanged }: { orgId: string; appId: string; permitted: boolean; dirty: boolean; onChanged: () => void }) {
  const [saved, setSaved] = useState<Management | null>(null); const [owner, setOwner] = useState<Subject | null>(null); const [visible, setVisible] = useState(false);
  const [reload, setReload] = useState(0); const [error, setError] = useState(""); const [busy, setBusy] = useState(false); const lock = useRef(false); const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let cancelled = false; setSaved(null); setError("");
    if (!permitted) return;
    void api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/access-management", { params: { path: { orgId, appId } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not load catalog and App admin settings."));
      else { setSaved(result.data); setVisible(result.data.catalog_visible); setOwner(result.data.app_admin ? { ...result.data.app_admin, kind: "user" } : null); }
    }).catch(() => { if (!cancelled) setError("Could not reach application access management."); });
    return () => { cancelled = true; };
  }, [orgId, appId, permitted, reload]);
  if (!permitted) return null;
  async function save() {
    if (!saved || dirty || lock.current) return; lock.current = true; setBusy(true); setError("");
    try {
      const result = await api.PATCH("/api/v1/organizations/{orgId}/app-access/applications/{appId}/access-management", { params: { path: { orgId, appId } }, body: { expected_version: saved.version, catalog_visible: visible, app_admin_user_id: owner?.id ?? null } });
      if (!alive.current) return;
      if (result.error || !result.data) setError(["version_conflict", "stale_version"].includes(apiErrorCode(result.error) ?? "") ? "This application changed. Reload settings and review the current App admin before saving again." : apiErrorMessage(result.error, "Could not confirm these settings. Reload before retrying."));
      else { setSaved(result.data); window.dispatchEvent(new Event("app-access-requests-changed")); onChanged(); }
    } catch { if (alive.current) setError("Could not confirm these settings. Reload before retrying."); }
    finally { lock.current = false; if (alive.current) setBusy(false); }
  }
  return <Card className="space-y-4"><div><h3 className="text-lg font-semibold">Company catalog and App admin</h3><p className="mt-1 text-sm text-ink-secondary">Choose who manages access to this app. Assignment alone does not grant permission to open it.</p></div><ErrorText>{error}</ErrorText>{!saved ? error ? <Button variant="ghost" onClick={() => setReload(value => value + 1)}>Retry access management</Button> : <Loading /> : <><fieldset disabled={busy || dirty} className="space-y-4"><AppAccessSubjectPicker orgId={orgId} appId={appId} label="App admin" usersOnly value={owner} onChange={setOwner} />{owner && <Button type="button" variant="ghost" onClick={() => { setOwner(null); }}>Remove App admin assignment</Button>}{saved.app_admin && !saved.app_admin.available && <p role="status" className="text-sm text-ink-secondary">The assigned App admin is unavailable. Organization administrators can review pending requests or reassign this app.</p>}<label className="flex items-center gap-2"><input type="checkbox" checked={visible} onChange={event => setVisible(event.target.checked)} />Show in Company apps</label><p className="text-sm text-ink-secondary">Published apps can appear to all members of this organization so they can request access. Hidden apps remain available to members who already have access. Pending requests are retained when you hide or reassign an app.</p></fieldset>{dirty && <p role="status" className="text-sm">Save or discard application draft changes before updating access management.</p>}<div className="flex flex-wrap gap-3"><Button disabled={busy || dirty || (visible && !saved.catalog_visible && !owner) || (saved.catalog_visible === visible && saved.app_admin_user_id === (owner?.id ?? null))} onClick={() => void save()}>{busy ? "Saving access management…" : "Save access management"}</Button><Button variant="ghost" disabled={busy} onClick={() => setReload(value => value + 1)}>Reload access management</Button></div></>}</Card>;
}

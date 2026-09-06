import React, { useState } from "react";
import { IdpSyncSection } from "../src/pages/Settings";
import { api } from "../src/lib/api";
import "../../../packages/shared/generated/tokens.css";
import "../src/index.css";
const orgId = "11111111-1111-4111-8111-111111111111";
const connectionId = "22222222-2222-4222-8222-222222222222";
export function DirectoryPreview() {
  const [licensed, setLicensed] = useState(true);
  const [revision, setRevision] = useState(0);
  const state = React.useRef({ enabled: true, groups: [{ id: "33333333-3333-4333-8333-333333333333", name: "Engineering", origin: "idp_sync", idp_provider: "okta", idp_group_id: "00gEngineering" }] });
  const health = () => ({ provider: "okta", enabled: state.current.enabled, provisioning_allowed: licensed, client_id: "sample-directory-client", okta_org_url: "https://acme.okta.com", sso_connection_id: connectionId, sync_health: "ok", last_sync_ok: true, last_sync_at: new Date().toISOString() });
  const client = {
    async GET(path: string) {
      if (path.endsWith("sso-connections")) return { data: { items: [{ id: connectionId, name: "Acme workforce", provider: "okta", issuer_url: "https://acme.okta.com", enabled: true }] } };
      if (path.endsWith("/health")) return { data: health() };
      if (path.endsWith("/groups")) return { data: structuredClone(state.current.groups) };
      return { error: { code: "preview_only" } };
    },
    async PUT(_path: string, req: { body: { enabled: boolean } }) { state.current.enabled = req.body.enabled; return { data: health() }; },
    async POST(path: string, req: { body?: { idp_group_id: string; name?: string } }) {
      if (path.endsWith("/trigger")) return { data: health() };
      if (req.body) state.current.groups.push({ id: crypto.randomUUID(), name: req.body.name || req.body.idp_group_id, origin: "idp_sync", idp_provider: "okta", idp_group_id: req.body.idp_group_id });
      return { data: {} };
    },
    async DELETE(_path: string, req: { params: { path: { groupId: string } } }) { state.current.groups = state.current.groups.filter((g) => g.id !== req.params.path.groupId); return {}; },
  } as unknown as typeof api;
  return <section id="directory-preview" className="settings-workspace mt-10 space-y-4 text-slate-200">
    <h2 className="text-xl font-semibold">Directory sync · Okta</h2>
    <p className="text-sm text-slate-400">LOCAL SIMULATION · Sample accounts and groups. No provider calls, credentials, imports or revocations occur.</p>
    <div className="flex gap-3"><button className="rounded border border-white/20 px-3 py-2" onClick={() => { setLicensed(!licensed); setRevision(revision + 1); }}>{licensed ? "Preview expired licence" : "Preview active trial"}</button></div>
    <IdpSyncSection key={revision} orgId={orgId} provider="okta" role="owner" isEnterprise canEdit directoryAPI={client} />
    <div className="rounded border border-white/10 p-4 text-sm"><strong>First sign-in · simulated outcome</strong><p className="mt-2">Mapped Okta group → New member imported → Continue with Okta → Dashboard</p><p className="mt-2 text-slate-400">The implementation binds Okta user ID to the verified ID-token subject. An existing unrelated email account requires explicit linking. This preview is simulated; real Okta tenant qualification remains pending.</p></div>
  </section>;
}

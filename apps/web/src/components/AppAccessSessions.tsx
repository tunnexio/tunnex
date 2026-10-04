import { useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import type { components } from "@tunnex/shared";
import { api, apiErrorMessage } from "../lib/api";
import { Button, Card, DataTable, ErrorText, Loading, Modal } from "./ui";

type Sessions = components["schemas"]["AppAccessApplicationSessions"];
type Session = components["schemas"]["AppAccessApplicationSession"];

export default function AppAccessSessions({ orgId, appId }: { orgId: string; appId: string }) {
  const [sessions, setSessions] = useState<Sessions | null>(null);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [page, setPage] = useState(1);
  const [refresh, setRefresh] = useState(0);
  const [busy, setBusy] = useState(false);
  const [selected, setSelected] = useState<Session | null>(null);
  const alive = useRef(true);
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let cancelled = false;
    setSessions(null); setError("");
    void api.GET("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions", { params: { path: { orgId, appId }, query: { limit: 20, offset: (page - 1) * 20 } } }).then(result => {
      if (cancelled) return;
      if (result.error || !result.data) setError(apiErrorMessage(result.error, "Could not read application sessions."));
      else setSessions(result.data);
    }).catch(() => { if (!cancelled) setError("Could not reach application session history."); });
    return () => { cancelled = true; };
  }, [orgId, appId, page, refresh]);
  async function revoke(session: Session) {
    setSelected(null); setBusy(true); setError(""); setNotice("");
    try {
      const result = await api.DELETE("/api/v1/organizations/{orgId}/app-access/applications/{appId}/sessions/{sessionId}", { params: { path: { orgId, appId, sessionId: session.id } } });
      if (!alive.current) return;
      if (result.error) setError(apiErrorMessage(result.error, "Session withdrawal could not be confirmed. Refresh sessions before retrying."));
      else { setNotice("New requests for this session are denied. Existing connections may take up to five seconds to close."); setRefresh(value => value + 1); }
    } catch { if (alive.current) setError("Session withdrawal outcome is unknown. Refresh sessions before retrying."); }
    finally { if (alive.current) setBusy(false); }
  }
  return <Card className="space-y-4"><div className="app-access-panel-header"><div><h3 className="text-lg font-semibold">Application sessions</h3><p className="text-sm text-ink-secondary">Withdraw one user's session without changing the application's grants. Already delivered content cannot be removed.</p></div><Button variant="ghost" disabled={busy} onClick={() => setRefresh(value => value + 1)}>Refresh application sessions</Button></div><ErrorText>{error}</ErrorText>{notice && <p role="status" className="app-access-notice">{notice}</p>}{!sessions && !error ? <Loading /> : sessions && <><DataTable caption="Application sessions" rows={sessions.items} rowKey={session => session.id} failed={false} filterable={false} empty="No current sessions in this view." columns={[
    { key: "session", header: "Session", cell: session => <span className="font-mono" title={session.id}>{session.id.slice(0, 8)}</span> },
    { key: "user", header: "User", cell: session => <span title={session.user_id}>{session.user_id.slice(0, 8)}</span> },
    { key: "started", header: "Started", cell: session => <time dateTime={session.created_at}>{new Date(session.created_at).toLocaleString()}</time> },
    { key: "expires", header: "Expires", cell: session => <time dateTime={session.expires_at}>{new Date(session.expires_at).toLocaleString()}</time> },
    { key: "actions", header: "Actions", cell: session => <div className="flex flex-wrap items-center gap-3"><Button variant="ghost" size="sm" disabled={busy} onClick={() => setSelected(session)}>Revoke {session.id.slice(0, 8)}</Button><Link className="text-brand" to={`/access-events?source=applications&app_id=${encodeURIComponent(appId)}&session_id=${encodeURIComponent(session.id)}`}>Session events</Link></div> },
  ]} /><div className="app-access-pagination flex flex-wrap items-center gap-3"><Button variant="ghost" disabled={busy || page === 1} onClick={() => setPage(value => value - 1)}>Previous sessions</Button><span>Page {page}</span><Button variant="ghost" disabled={busy || sessions.items.length < 20 || page >= 501} onClick={() => setPage(value => value + 1)}>Next sessions</Button></div></>}{selected && <Modal title="Revoke application session" danger onDismiss={() => setSelected(null)} actions={<><Button variant="ghost" onClick={() => setSelected(null)}>Keep session</Button><Button onClick={() => void revoke(selected)}>Confirm session revocation</Button></>}><p>Withdraw session {selected.id.slice(0, 8)} for user {selected.user_id.slice(0, 8)}. New requests will be denied, and live connections may take a few seconds to close.</p></Modal>}</Card>;
}

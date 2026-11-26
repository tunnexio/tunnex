import { useEffect, useState } from "react";
import { api, apiErrorCode, apiErrorMessage, listItems, type PendingAgentBootstrapToken as PendingToken } from "../lib/api";
import { relativeAge } from "../lib/format";
import { Button, DataTable, ErrorText, Modal } from "./ui";

type Load = { kind: "loading" } | { kind: "ready"; tokens: PendingToken[] } | { kind: "failed" };

function expiresIn(iso: string, now: number): string {
  const minutes = Math.ceil((new Date(iso).getTime() - now) / 60_000);
  if (minutes <= 1) return "Expires in less than a minute";
  return `Expires in ${minutes} minutes`;
}

function issuedBy(token: PendingToken): string {
  if (token.issued_by_email) return token.issued_by_email;
  return token.issued_by ? "Another member" : "Unknown";
}

/**
 * Install tokens that were created but not used yet (AI-SEC-1). A token is a
 * live credential until it is used, revoked or expires, so the people who can
 * add agents can see each one and switch it off. The value itself is never
 * loaded here: the server shows it once, when the token is created.
 *
 * Renders nothing while there are no pending tokens. A failed read is stated,
 * never shown as "none".
 */
export function PendingInstallTokens({ orgId, refreshKey }: { orgId: string; refreshKey: string }) {
  const [load, setLoad] = useState<Load>({ kind: "loading" });
  const [attempt, setAttempt] = useState(0);
  const [now, setNow] = useState(() => Date.now());
  const [confirming, setConfirming] = useState<PendingToken | null>(null);
  const [busy, setBusy] = useState(false);
  const [notice, setNotice] = useState("");
  const [revokeError, setRevokeError] = useState("");

  useEffect(() => {
    let cancelled = false;
    void api.GET("/api/v1/organizations/{orgId}/agents/bootstrap-tokens", { params: { path: { orgId } } }).then(({ data, error }) => {
      if (cancelled) return;
      if (error || !data) { setLoad({ kind: "failed" }); return; }
      setNow(Date.now());
      setLoad({ kind: "ready", tokens: listItems<PendingToken>(data) });
    }).catch(() => { if (!cancelled) setLoad({ kind: "failed" }); });
    return () => { cancelled = true; };
  }, [orgId, refreshKey, attempt]);

  // A token stops being usable the moment it expires, with or without a reload.
  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 30_000);
    return () => clearInterval(timer);
  }, []);

  async function revoke(token: PendingToken) {
    setBusy(true); setRevokeError("");
    try {
      const { error } = await api.DELETE("/api/v1/organizations/{orgId}/agents/bootstrap-tokens/{tokenId}", {
        params: { path: { orgId, tokenId: token.id } },
      });
      if (error && apiErrorCode(error) !== "bootstrap_token_not_found") {
        setRevokeError(apiErrorMessage(error, "The token could not be revoked. It may still work."));
        return;
      }
      setNotice(error ? "That token was already used, revoked, or has expired. Nothing was changed." : `The install token for ${token.agent_name} was revoked.`);
      setConfirming(null);
      setAttempt(value => value + 1);
    } catch {
      setRevokeError("Could not reach the API. The token may still work.");
    } finally { setBusy(false); }
  }

  const tokens = load.kind === "ready" ? load.tokens.filter(token => new Date(token.expires_at).getTime() > now) : [];
  if (load.kind === "loading" || (load.kind === "ready" && tokens.length === 0 && !notice)) return null;
  return <section className="agents-pending-tokens" aria-label="Pending install tokens">
    <h2>Pending install tokens</h2>
    {notice && <p role="status" className="agents-pending-tokens-note">{notice}</p>}
    {load.kind === "failed" && <div className="agents-load-error"><p role="alert">Could not load pending install tokens. Some may still be usable.</p><Button variant="ghost" onClick={() => setAttempt(value => value + 1)}>Retry</Button></div>}
    {tokens.length > 0 && <>
      <p className="agents-pending-tokens-help">These tokens can still be used to add an agent. Revoke any you did not expect or no longer need.</p>
      <div className="agents-inventory-table"><DataTable<PendingToken>
        caption="Pending install tokens" rows={tokens} rowKey={token => token.id} failed={false} filterable={false} pageSize={0} empty={null}
        columns={[
          { key: "agent", header: "Agent name", cell: token => token.agent_name },
          { key: "gateway", header: "Gateway", cell: token => token.gateway_name },
          { key: "issuer", header: "Created by", cell: token => <div><span>{issuedBy(token)}</span><span className="agents-secondary">{relativeAge(token.issued_at)}</span></div> },
          { key: "expires", header: "Expires", cell: token => expiresIn(token.expires_at, now) },
          { key: "actions", header: "Actions", cell: token => <Button size="sm" variant="ghost" aria-label={`Revoke install token for ${token.agent_name}`} onClick={() => { setRevokeError(""); setNotice(""); setConfirming(token); }}>Revoke</Button> },
        ]}
      /></div>
    </>}
    {confirming && <Modal danger title="Revoke this install token?" onDismiss={() => { if (!busy) setConfirming(null); }} actions={<><Button variant="ghost" disabled={busy} onClick={() => setConfirming(null)}>Cancel</Button><Button variant="danger" disabled={busy} onClick={() => void revoke(confirming)}>{busy ? "Revoking…" : "Revoke token"}</Button></>}>
      <p>The token for {confirming.agent_name} will stop working right away. An install that has not finished using it will fail. Agents that are already connected are not affected.</p>
      <ErrorText>{revokeError}</ErrorText>
    </Modal>}
  </section>;
}

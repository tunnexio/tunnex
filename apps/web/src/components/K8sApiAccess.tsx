import { useCallback, useEffect, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { api, apiErrorMessage, loadOne } from "../lib/api";
import {
  K8S_API_ACCESS_PATH,
  K8S_API_PORT_LABEL,
  isK8sApiAccess,
  k8sApiChangeNotice,
  kubeconfigLines,
  ruleCountPhrase,
  type K8sApiAccess,
  type K8sApiEnforcement,
  type K8sApiGate,
} from "../lib/k8sapiaccess";
import { Badge, Button, ErrorText, Modal } from "./ui";

// K8N-3 stage 1 — "API access" on a cluster's page.
//
// Turning it on gives the cluster's Kubernetes API an address and a name in the tunnel. It is a NETWORK
// PATH: Tunnex carries the connection and holds no cluster credential. The consequences are stated in the
// dialog BEFORE the administrator confirms, and what happened is stated after. This screen shows the two
// kubeconfig lines to change and never a whole kubeconfig, a credential, or a way to turn certificate
// checking off.

export function K8sApiAccessPanel({
  orgId,
  cluster,
  gate,
}: {
  orgId: string;
  cluster: { id: string; name: string };
  gate: K8sApiGate;
}) {
  const [access, setAccess] = useState<K8sApiAccess | null>(null);
  const [error, setError] = useState<string | null>(null);
  // Read only for someone who can turn API access on: it decides one warning in that dialog.
  const [enforcement, setEnforcement] = useState<K8sApiEnforcement>("unknown");
  const [confirming, setConfirming] = useState<"on" | "off" | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const epoch = useRef(0);

  const load = useCallback(async () => {
    const current = ++epoch.current;
    const [read, mode] = await Promise.all([
      loadOne(() => api.GET(K8S_API_ACCESS_PATH, { params: { path: { orgId, clusterId: cluster.id } } })),
      gate.canManage
        ? loadOne(() => api.GET("/api/v1/organizations/{orgId}/zero-trust-mode", { params: { path: { orgId } } }))
        : Promise.resolve(null),
    ]);
    if (current !== epoch.current) return;
    const served = mode && mode.ok ? (mode.data as { mode?: unknown } | null)?.mode : undefined;
    setEnforcement(served === "off" || served === "enforcing" ? served : "unknown");
    if (!read.ok || !isK8sApiAccess(read.data)) {
      setAccess(null);
      setError((!read.ok && read.error) || "Could not read API access for this cluster.");
      return;
    }
    setError(null);
    setAccess(read.data);
  }, [orgId, cluster.id, gate.canManage]);

  useEffect(() => {
    setAccess(null);
    setError(null);
    setNotice(null);
    setConfirming(null);
    void load();
    return () => { epoch.current += 1; };
  }, [load]);

  function changed(next: K8sApiAccess) {
    epoch.current += 1; // a read still in flight is older than this answer
    setAccess(next);
    setError(null);
    setNotice(k8sApiChangeNotice(next, cluster.name, enforcement));
    setConfirming(null);
  }

  const lines = access ? kubeconfigLines(access.fqdn) : null;

  return (
    <section className="kubernetes-api-access" aria-label="API access">
      <div className="kubernetes-list-toolbar">
        <div className="kubernetes-cell-stack">
          <span>
            <strong>API access</strong>{" "}
            {access && <Badge tone={access.enabled ? "ok" : "neutral"}>{access.enabled ? "On" : "Off"}</Badge>}
          </span>
          <span className="kubernetes-muted">
            A network path to this cluster's Kubernetes API for kubectl. Tunnex carries the connection; each person's own cluster credential still decides what they may do.
          </span>
        </div>
        {access && gate.canManage && (access.enabled
          ? <Button size="sm" variant="ghost" onClick={() => setConfirming("off")}>Turn off API access…</Button>
          : <Button size="sm" variant="ghost" disabled={access.ordinary_exposure} onClick={() => setConfirming("on")}>Turn on API access…</Button>)}
      </div>

      {error && <div role="alert" className="kubernetes-read-warning"><span>{error}</span><Button variant="ghost" size="sm" onClick={() => void load()}>Retry reading API access</Button></div>}
      {access === null && !error && <p className="kubernetes-muted" role="status">Reading API access…</p>}
      {notice && <p role="status" className="kubernetes-api-notice">{notice}</p>}

      {access && !access.enabled && (
        <>
          <p className="kubernetes-muted">
            Off. The cluster's Kubernetes API has no address in the tunnel. When it is on, its name will be <strong>{access.fqdn}</strong> on {K8S_API_PORT_LABEL}.
          </p>
          {access.rule_count > 0 && (
            <p className="text-warn" role="status">
              {ruleCountPhrase(access.rule_count)} {access.rule_count === 1 ? "names" : "name"} this cluster's API. {access.rule_count === 1 ? "It is" : "They are"} kept and {access.rule_count === 1 ? "allows" : "allow"} nothing while API access is off.
            </p>
          )}
          {access.ordinary_exposure && (
            <p className="text-warn" role="status">
              default/kubernetes is already exposed as an ordinary Service in this cluster. It is left in place. Unexpose it under Services before API access can be turned on.
            </p>
          )}
        </>
      )}

      {access && access.enabled && lines && (
        <>
          <dl className="kubernetes-facts tnx-resource-facts">
            <div><dt>Name in the tunnel</dt><dd>{access.fqdn}</dd></div>
            <div><dt>Address</dt><dd>{access.vip ?? "Not allocated"}</dd></div>
            <div><dt>Port</dt><dd>{K8S_API_PORT_LABEL}</dd></div>
            <div><dt>Access rules</dt><dd>{access.rule_count === 0 ? "None yet" : ruleCountPhrase(access.rule_count)}</dd></div>
          </dl>
          <p className="kubernetes-api-grant">
            Turning this on grants nothing. Nobody can reach the API until an access rule grants a person or a group.{" "}
            <Link className="kubernetes-text-link" to="/access">Create a rule in Access Policies</Link>
          </p>
          <div className="kubernetes-api-kubeconfig" aria-label="kubeconfig lines to change">
            <div className="kubernetes-api-kubeconfig-heading">
              <strong>Change two lines in your kubeconfig</strong>
              <CopyLines text={lines.join("\n")} />
            </div>
            <pre>{lines.join("\n")}</pre>
            <ul>
              <li><code>tls-server-name</code> must be the host from your kubeconfig's original <code>server:</code> line. The API server's certificate covers that name, not the Tunnex name.</li>
              <li>Certificate checking stays on. Do not turn it off to make this work.</li>
              <li>A cloud CLI that regenerates the kubeconfig overwrites these two lines. Change them again afterwards.</li>
              <li>Your own cluster credential still decides what you may do.</li>
              <li>A Tunnex refusal looks like a timeout. A 401 or 403 is the cluster's answer.</li>
            </ul>
          </div>
        </>
      )}

      {!gate.canManage && gate.whoCan && <p className="kubernetes-muted">{gate.whoCan}</p>}

      {access && gate.canManage && confirming === "on" && (
        <TurnOnApiAccessModal orgId={orgId} cluster={cluster} access={access} enforcement={enforcement} onClose={() => setConfirming(null)} onDone={changed} />
      )}
      {access && gate.canManage && confirming === "off" && (
        <TurnOffApiAccessModal orgId={orgId} cluster={cluster} access={access} onClose={() => setConfirming(null)} onDone={changed} />
      )}
    </section>
  );
}

function CopyLines({ text }: { text: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  useEffect(() => { setState("idle"); }, [text]);
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setState("copied");
    } catch {
      setState("failed");
    }
  }
  return (
    <span className="kubernetes-api-copy">
      <Button size="sm" variant="ghost" onClick={() => void copy()}>Copy the two lines</Button>
      <span role="status">{state === "copied" ? "Copied" : state === "failed" ? "Could not copy. Select the lines instead." : ""}</span>
    </span>
  );
}

async function putApiAccess(orgId: string, clusterId: string, enabled: boolean, fallback: string): Promise<{ access: K8sApiAccess } | { error: string }> {
  try {
    const { data, error } = await api.PUT(K8S_API_ACCESS_PATH, { params: { path: { orgId, clusterId } }, body: { enabled } });
    // The server's own message is shown as it is: it names the refusal (default/kubernetes already
    // exposed, a connector pool, a full address range, a missing permission).
    if (error) return { error: apiErrorMessage(error, fallback) };
    if (!isK8sApiAccess(data) || data.enabled !== enabled) return { error: "The server did not confirm the change. Refresh before trying again." };
    return { access: data };
  } catch {
    return { error: "Could not reach the API. Refresh before trying again." };
  }
}

export function TurnOnApiAccessModal({
  orgId,
  cluster,
  access,
  enforcement,
  onClose,
  onDone,
}: {
  orgId: string;
  cluster: { id: string; name: string };
  access: K8sApiAccess;
  enforcement: K8sApiEnforcement;
  onClose: () => void;
  onDone: (next: K8sApiAccess) => void;
}) {
  const [understood, setUnderstood] = useState(false);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const n = access.rule_count;
  const ready = understood && !busy && !access.ordinary_exposure;

  async function submit() {
    if (!ready) return;
    setBusy(true);
    setErr(null);
    const result = await putApiAccess(orgId, cluster.id, true, "Could not turn on API access.");
    setBusy(false);
    if ("error" in result) return setErr(result.error);
    onDone(result.access);
  }

  return (
    <Modal
      placement="right" showClose
      title={`Turn on API access for ${cluster.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button onClick={() => void submit()} disabled={!ready}>{busy ? "Turning on…" : "Turn on API access"}</Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        <p>
          The cluster's Kubernetes API gets an address and the name <strong>{access.fqdn}</strong> in the tunnel, on {K8S_API_PORT_LABEL}, so people can run kubectl through Tunnex.
        </p>
        {enforcement === "off" && (
          <p role="alert" className="kubernetes-api-open-mesh">
            <strong>Zero Trust enforcement is off.</strong> Every connected device will be able to reach this cluster's API address as soon as this is on, with or without an access rule. Turn enforcement on first if only the people you grant should reach it.
          </p>
        )}
        {enforcement === "unknown" && (
          <p role="status" className="text-warn">
            The enforcement mode could not be read. If Zero Trust enforcement is off, every connected device will be able to reach this cluster's API address as soon as this is on.
          </p>
        )}
        <div className="kubernetes-action-impact" aria-label="What turning on API access does">
          <p><strong>What happens when you confirm</strong></p>
          <ul>
            <li><strong>A network path only.</strong> Tunnex carries the connection to the API server. Each person's own cluster credential still decides what they may do. Tunnex holds no cluster credential.</li>
            {enforcement === "off" ? (
              <li><strong>Access rules do not limit it while enforcement is off.</strong> Once enforcement is on, nobody can reach it until an access rule grants a person or a group. Rules for a cluster's API name people and groups only, on {K8S_API_PORT_LABEL}.</li>
            ) : (
              <li><strong>Nobody gains access yet.</strong> Nobody can reach it until an access rule grants a person or a group. Rules for a cluster's API name people and groups only, on {K8S_API_PORT_LABEL}.</li>
            )}
            <li><strong>Everyone granted reaches whatever the API server answers without signing in.</strong> If the cluster allows anonymous requests, they can make them.</li>
            <li><strong>The cluster sees one address.</strong> All Tunnex users appear to the cluster as the gateway node's address.</li>
            <li><strong>If the cluster's gateway is down, kubectl through Tunnex is down.</strong> Keep a way into the cluster that does not use Tunnex.</li>
            {n > 0 && (
              <li><strong>{ruleCountPhrase(n)} {n === 1 ? "takes" : "take"} effect again.</strong> {n === 1 ? "One existing rule names" : `${n} existing rules name`} this cluster's API and {n === 1 ? "allows" : "allow"} access as soon as this is on.</li>
            )}
          </ul>
          <label className="kubernetes-confirm-check">
            <input type="checkbox" checked={understood} onChange={(event) => setUnderstood(event.target.checked)} />{" "}
            Open a network path to the Kubernetes API of {cluster.name}
          </label>
        </div>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

export function TurnOffApiAccessModal({
  orgId,
  cluster,
  access,
  onClose,
  onDone,
}: {
  orgId: string;
  cluster: { id: string; name: string };
  access: K8sApiAccess;
  onClose: () => void;
  onDone: (next: K8sApiAccess) => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const n = access.rule_count;

  async function submit() {
    if (busy) return;
    setBusy(true);
    setErr(null);
    const result = await putApiAccess(orgId, cluster.id, false, "Could not turn off API access.");
    setBusy(false);
    if ("error" in result) return setErr(result.error);
    onDone(result.access);
  }

  return (
    <Modal
      placement="right" showClose
      title={`Turn off API access for ${cluster.name}`}
      onDismiss={busy ? () => {} : onClose}
      actions={
        <>
          <Button variant="ghost" onClick={onClose} disabled={busy}>Cancel</Button>
          <Button variant="danger" onClick={() => void submit()} disabled={busy}>{busy ? "Turning off…" : "Turn off API access"}</Button>
        </>
      }
    >
      <div className="kubernetes-action-form">
        <p>
          <strong>kubectl through Tunnex stops for everyone.</strong> The name {access.fqdn}{access.vip ? ` and the address ${access.vip}` : ""} stop working for this cluster's API.
        </p>
        <p>
          {n === 0
            ? "No access rule names this cluster's API, so there is nothing to keep."
            : `The ${ruleCountPhrase(n)} that name${n === 1 ? "s" : ""} this cluster's API ${n === 1 ? "is" : "are"} kept and allow${n === 1 ? "s" : ""} nothing until API access is turned on again.`}
        </p>
        <p>Nothing in the cluster changes. People who reach the API another way are not affected.</p>
      </div>
      <ErrorText>{err}</ErrorText>
    </Modal>
  );
}

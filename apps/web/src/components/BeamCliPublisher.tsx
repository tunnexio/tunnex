import { useEffect, useRef, useState } from "react";
import { AudiencePicker } from "./BeamAudiencePicker";
import { Button, ErrorText, Field, Input, Loading, Modal } from "./ui";
import { beamApi, type BeamAudience, type BeamGrant, type BeamPolicy } from "../lib/beam";
import { beamPublishCommand } from "../lib/beam-cli";

export type BeamCliProject = { id: string; name: string; target: { protocol: string; address: string; port: number; routes?: { path_prefix: string; target: { protocol: string; address: string; port: number } }[] }; duration_seconds: number; grants: BeamGrant[] };
export function BeamCliPublisher({ orgId, policy, project, label = "Publish using CLI" }: { orgId: string; policy: BeamPolicy; project?: BeamCliProject; label?: string }) {
  const [open, setOpen] = useState(false);
  const opener = useRef<HTMLElement | null>(null);
  const available = policy.can_publish && policy.enabled && policy.domain_ready;
  return <><Button disabled={!available} onClick={event => { opener.current = event.currentTarget; setOpen(true); }}>{label}</Button>{open && <CliCommandDialog key={`${orgId}:${project?.id ?? "new"}`} orgId={orgId} policy={policy} project={project} opener={opener.current} onDismiss={() => setOpen(false)} />}</>;
}

function CliCommandDialog({ orgId, policy, project, opener, onDismiss }: { orgId: string; policy: BeamPolicy; project?: BeamCliProject; opener: HTMLElement | null; onDismiss: () => void }) {
  const [audience, setAudience] = useState<BeamAudience | null>(null);
  const [grants, setGrants] = useState<BeamGrant[]>([]);
  const [name, setName] = useState(project?.name ?? "Local demo");
  const [port, setPort] = useState(String(project?.target.port ?? 3000));
  const [protocol, setProtocol] = useState(project?.target.protocol ?? "http");
  const [address, setAddress] = useState(project?.target.address ?? "127.0.0.1");
  const [originCA, setOriginCA] = useState("");
  const [apiEnabled, setApiEnabled] = useState(Boolean(project?.target.routes?.length));
  const [apiRoutes, setApiRoutes] = useState(project?.target.routes?.map(route => ({ path_prefix: route.path_prefix, port: String(route.target.port) })) ?? [{ path_prefix: "/api", port: "8080" }]);
  const [minutes, setMinutes] = useState(String(project ? Math.ceil(project.duration_seconds / 60) : Math.min(60, Math.floor(policy.max_duration_seconds / 60))));
  const [includeLogin, setIncludeLogin] = useState(true);
  const [command, setCommand] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [reload, setReload] = useState(0);
  const alive = useRef(true);
  const currentCommand = useRef("");
  currentCommand.current = policy.can_publish && policy.enabled && policy.domain_ready ? command : "";
  useEffect(() => { alive.current = true; return () => { alive.current = false; }; }, []);
  useEffect(() => {
    let current = true; setAudience(null); setGrants([]); setCommand(""); setError(""); setNotice("");
    void beamApi.audience(orgId).then(result => { if (!current) return; if (result.ok) {
      setAudience(result.data);
      const permitted = (project?.grants ?? []).filter(grant => (grant.subject_kind === "user" ? result.data.users : result.data.groups).some(subject => subject.id === grant.subject_id));
      setGrants(permitted);
      if (permitted.length !== (project?.grants.length ?? 0)) setNotice("Some saved reviewers are no longer permitted. Review the current audience before generating a command.");
    } else setError(result.error); });
    return () => { current = false; };
  }, [orgId, reload]);
  const available = policy.can_publish && policy.enabled && policy.domain_ready;
  const routesSupported = policy.capabilities?.includes("path_routes_v1") ?? false;
  function edit(change: () => void) { change(); setCommand(""); setNotice(""); setError(""); }
  function generate(event: React.FormEvent) {
    event.preventDefault(); setError(""); setNotice(""); setCommand("");
    if (!available || !audience) return;
    try {
      if (apiEnabled && !routesSupported) throw new Error("This server does not support API routes. Update the control plane before publishing a multi-port app.");
      if (apiEnabled && project?.target.routes?.some(route => route.target.protocol !== protocol || route.target.address !== address)) throw new Error("The CLI generator requires API routes to use the same protocol and loopback address as the app. Edit the saved project to match.");
      setCommand(beamPublishCommand({ serverOrigin: window.location.origin, includeLogin, orgId, projectId: project?.id, name, port: Number(port), protocol, address, originCAPath: originCA || undefined, routes: apiEnabled ? apiRoutes.map(route => ({ path_prefix: route.path_prefix, port: Number(route.port) })) : [], lifetimeMinutes: Number(minutes), maxDurationSeconds: policy.max_duration_seconds, audience, grants }));
    }
    catch (error) { setError(error instanceof Error ? error.message : "Could not generate the command."); }
  }
  async function copy() {
    if (!available || !command) return;
    const copied = command;
    try { await navigator.clipboard.writeText(copied); if (alive.current && currentCommand.current === copied) setNotice("Command copied. Run it in a terminal on the computer hosting your app."); }
    catch { if (alive.current && currentCommand.current === copied) setError("Could not copy. Select and copy the command below."); }
  }
  return <Modal placement="right" title="Publish using CLI" size="wide" returnFocusTo={opener} onDismiss={onDismiss} actions={<Button variant="ghost" onClick={onDismiss}>Close</Button>}>
    <p className="text-sm text-ink-secondary">Choose your app and reviewers, then run the generated command on the computer hosting your app.</p>
    <details className="rounded border border-line p-3"><summary className="cursor-pointer font-medium text-sm">First time publishing?</summary><ol className="list-decimal pl-5 space-y-2 text-sm mt-3"><li>Start your app and open it on your own computer.</li><li>Run <code>tunnex beam --help</code> in a terminal to check that your installed CLI supports Local Sharing.</li><li>Select reviewers below, copy the generated command and run it in a second terminal.</li><li>Wait for the CLI to print the preview URL. Keep both terminals running.</li></ol><p className="text-xs text-ink-secondary mt-3">This browser cannot inspect your installed CLI or local app. The publisher checks the port and current permissions when you run the command.</p></details>
    {project && <p className="text-sm">Saved project: <strong>{project.name}</strong>. This creates a new preview session; previous sessions stay ended.</p>}
    <ErrorText>{error}</ErrorText>{notice && <p role="status">{notice}</p>}
    {!available ? <p role="status">Publishing is currently unavailable. Close this form and refresh Local Sharing to check your permissions and serving setup.</p> : !audience ? error ? <Button onClick={() => setReload(n => n + 1)}>Retry reviewer choices</Button> : <Loading label="Loading permitted reviewers…" /> : <form onSubmit={generate} className="space-y-4">
      <Field label="App name"><Input required maxLength={100} value={name} onChange={event => edit(() => setName(event.target.value))} /></Field>
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2"><Field label="Local HTTP port"><Input type="number" required min={1} max={65535} step={1} value={port} onChange={event => edit(() => setPort(event.target.value))} /></Field><Field label="Link lifetime (minutes)"><Input type="number" required min={1} max={Math.floor(policy.max_duration_seconds / 60)} step={1} value={minutes} onChange={event => edit(() => setMinutes(event.target.value))} /></Field></div>
      <div className="flex flex-wrap gap-2" aria-label="Common app ports">{[{ name: "Next.js / React", port: 3000 }, { name: "Vite", port: 5173 }, { name: "Python", port: 8000 }].map(preset => <Button key={preset.port} type="button" variant="ghost" onClick={() => edit(() => setPort(String(preset.port)))}>{preset.name} · {preset.port}</Button>)}</div>
      <p className="text-xs text-ink-secondary">Use the port printed by your app. Maximum lifetime: {Math.floor(policy.max_duration_seconds / 60)} minutes.</p>
      <details className="rounded border border-line p-3"><summary className="cursor-pointer text-sm">HTTPS or IPv6 local app</summary><div className="grid gap-3 sm:grid-cols-2 mt-3"><Field label="Local protocol"><select className="rounded border border-line bg-surface p-2" value={protocol} onChange={event => edit(() => setProtocol(event.target.value))}><option value="http">HTTP</option><option value="https">HTTPS</option></select></Field><Field label="Local address"><select className="rounded border border-line bg-surface p-2" value={address} onChange={event => edit(() => setAddress(event.target.value))}><option value="127.0.0.1">127.0.0.1</option><option value="::1">::1</option></select></Field>{protocol === "https" && <Field label="Local CA file path (optional)"><Input maxLength={2048} placeholder="/path/to/local-ca.pem" value={originCA} onChange={event => edit(() => setOriginCA(event.target.value))} /></Field>}</div><p className="text-xs text-ink-secondary mt-2">HTTPS certificates must be trusted and match the selected loopback IP. The CA file is on the publishing computer.</p></details>
      <label className="flex items-center gap-3"><input type="checkbox" checked={apiEnabled} disabled={!routesSupported && !apiEnabled} onChange={event => edit(() => setApiEnabled(event.target.checked))} /><span className="text-sm font-medium">Include a local API</span></label>
      {!routesSupported && <p className="text-xs text-ink-secondary">API routes require an updated control plane and CLI with Local Sharing support. Single-port previews remain available.</p>}
      {apiEnabled && <div className="space-y-3 rounded border border-line p-3">{apiRoutes.map((route, index) => <div key={index} className="grid gap-3 sm:grid-cols-3"><Field label={`API path ${index + 1}`}><Input required maxLength={128} value={route.path_prefix} onChange={event => edit(() => setApiRoutes(previous => previous.map((item, i) => i === index ? { ...item, path_prefix: event.target.value } : item)))} /></Field><Field label={`API port ${index + 1}`}><Input required type="number" min={1} max={65535} step={1} value={route.port} onChange={event => edit(() => setApiRoutes(previous => previous.map((item, i) => i === index ? { ...item, port: event.target.value } : item)))} /></Field><Button variant="ghost" type="button" disabled={apiRoutes.length === 1} onClick={() => edit(() => setApiRoutes(previous => previous.filter((_, i) => i !== index)))}>Remove route {index + 1}</Button></div>)}<Button type="button" variant="ghost" disabled={apiRoutes.length >= 8} onClick={() => edit(() => setApiRoutes(previous => [...previous, { path_prefix: `/api${previous.length + 1}`, port: "8080" }]))}>Add API route</Button><p className="text-xs text-ink-secondary">Requests under each path go to its API port, preserving the path. Use relative API URLs in your frontend. This requires a CLI and server that support Local Sharing API routes.</p></div>}
      <div className="space-y-2"><h3 className="font-semibold">Reviewers</h3><p className="text-sm text-ink-secondary">{policy.open_for_all_users ? "Select eligible people and groups." : "Only administrator-permitted people and groups are listed."} Groups include their eligible members.</p><AudiencePicker audience={audience} grants={grants} onChange={next => edit(() => setGrants(next))} disabled={!available} /></div>
      <label className="flex items-center gap-3"><input type="checkbox" checked={includeLogin} onChange={event => edit(() => setIncludeLogin(event.target.checked))} /><span className="text-sm font-medium">Include login command</span></label>
      <p className="text-xs text-ink-secondary">Login uses your publisher account and stops CLI shares already running under that login. Turn this off to use your current CLI login.</p>
      <Button type="submit" disabled={!grants.length}>Generate command</Button>
      {command && <div className="space-y-3"><Field label="Publish command"><textarea readOnly value={command} rows={Math.min(12, command.split("\n").length)} className="w-full rounded border border-line bg-surface p-3 font-mono text-xs" /></Field><Button type="button" onClick={() => void copy()}>Copy command</Button><p className="text-sm text-ink-secondary">Generating this command does not publish the app. Run it in a second terminal and keep both the app and CLI running. The CLI checks your current permissions before publishing.</p></div>}
    </form>}
  </Modal>;
}

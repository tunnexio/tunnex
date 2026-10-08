import type { BeamAudience, BeamGrant } from "./beam";

const uuid = /^[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}$/i;
// Quote shell arguments, including embedded apostrophes. Names remain data.
export function beamShellQuote(value: string): string { return "'" + value.replace(/'/g, "'\"'\"'") + "'"; }

export type BeamCommandRoute = { path_prefix: string; port: number };
export function beamPublishCommand(input: { serverOrigin: string; includeLogin?: boolean; orgId: string; projectId?: string; name: string; port: number; protocol?: string; address?: string; originCAPath?: string; routes?: BeamCommandRoute[]; lifetimeMinutes: number; maxDurationSeconds: number; audience: BeamAudience; grants: BeamGrant[] }): string {
  const server = new URL(input.serverOrigin);
  if (!["https:", "http:"].includes(server.protocol) || server.origin !== input.serverOrigin) throw new Error("Your control-plane address could not be identified. Reload Local Sharing.");
  const name = input.name.trim();
  if (!uuid.test(input.orgId)) throw new Error("Your organization could not be identified. Reload Local Sharing.");
  if (!name || [...name].length > 100 || /[\r\n\x00]/.test(name)) throw new Error("Enter an app name with 1 to 100 characters on one line.");
  if (!Number.isInteger(input.port) || input.port < 1 || input.port > 65535) throw new Error("Enter a local port between 1 and 65535.");
  if (input.projectId && !uuid.test(input.projectId)) throw new Error("Your saved project could not be identified. Reload Local Sharing.");
  const protocol = input.protocol ?? "http", address = input.address ?? "127.0.0.1";
  if (!["http", "https"].includes(protocol) || !["127.0.0.1", "::1"].includes(address)) throw new Error("Choose HTTP or HTTPS on a numeric loopback address.");
  if (input.originCAPath && (protocol !== "https" || /[\r\n\x00]/.test(input.originCAPath))) throw new Error("Use a local CA file path on one line for an HTTPS app.");
  if ((input.routes?.length ?? 0) > 8) throw new Error("Add at most eight API routes.");
  const routePrefixes = new Set<string>();
  const routeFlags = (input.routes ?? []).map(route => {
    if (!/^\/[A-Za-z0-9_-]+(?:\/[A-Za-z0-9_-]+)*$/.test(route.path_prefix) || route.path_prefix.length > 128 || routePrefixes.has(route.path_prefix) || !Number.isInteger(route.port) || route.port < 1 || route.port > 65535) throw new Error("Use unique route paths such as /api and valid local ports.");
    routePrefixes.add(route.path_prefix);
    return `--route ${beamShellQuote(`${route.path_prefix}=${route.port}`)}`;
  });
  const seconds = input.lifetimeMinutes * 60;
  if (!Number.isInteger(seconds) || seconds < 60 || seconds > Math.min(86400, input.maxDurationSeconds)) throw new Error("Choose a lifetime within your organization's limit.");
  if (!input.grants.length || input.grants.length > 100) throw new Error("Select 1 to 100 permitted users or groups.");
  const selected = new Set<string>();
  const flags = input.grants.map(grant => {
    const permitted = grant.subject_kind === "user" ? input.audience.users : grant.subject_kind === "group" ? input.audience.groups : [];
    const key = `${grant.subject_kind}:${grant.subject_id}`;
    if (!uuid.test(grant.subject_id) || !permitted.some(subject => subject.id === grant.subject_id) || selected.has(key)) throw new Error("Select current permitted reviewers, then generate the command again.");
    selected.add(key);
    return `--reviewer-${grant.subject_kind} ${grant.subject_id}`;
  });
  const publish = ["tunnex beam publish", `--org ${input.orgId}`, ...(input.projectId ? [`--project ${input.projectId}`] : []), `--port ${input.port}`, ...(protocol === "https" ? ["--protocol https"] : []), ...(address === "::1" ? ["--address ::1"] : []), ...(input.originCAPath ? [`--origin-ca ${beamShellQuote(input.originCAPath)}`] : []), ...routeFlags, `--name ${beamShellQuote(name)}`, `--duration ${seconds}s`, ...flags].join(" \\\n  ");
  return input.includeLogin === false ? publish : `tunnex login --server ${beamShellQuote(server.origin)} && \\\n${publish}`;
}

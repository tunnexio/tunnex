import { serverAccessReason } from "../lib/serverAccessReasons";
import { FirewallHelp } from "./FirewallHelp";

// A Server Access reason as a sentence and next step; reachability failures add firewall examples (SA-UX-2 items 1, 8).
export function ServerAccessProblem({ code, gatewayName, host, port }: { code: string; gatewayName: string; host: string; port: number }) {
  if (!code) return null;
  const reason = serverAccessReason(code);
  return <div role="alert" className="space-y-2 rounded-lg border border-white/10 p-3 text-sm">
    <p className="text-ink-heading">{reason.text}</p>
    {reason.next && <p className="text-ink-secondary">{reason.next}</p>}
    {code === "ssh_unreachable" && <FirewallHelp gatewayName={gatewayName} host={host} port={port} open />}
  </div>;
}

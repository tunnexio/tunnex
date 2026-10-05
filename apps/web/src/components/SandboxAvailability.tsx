import { Link } from "react-router-dom";
import type { SandboxCreationStatus } from "../lib/api";
export const sandboxBlockerMessages: Record<string,string> = {
 organization_disabled: "Sandbox creation is switched off for this organization.",
 policy_not_enforcing: "Sandbox creation requires enforcing network policy mode.",
 permission_denied: "Your current role does not permit sandbox creation.",
 runtime_binding_unavailable: "The configured runtime does not admit this user or organization, or its admission window has ended.",
 runtime_not_ready: "No qualified runtime is currently connected. An operator must configure and verify the worker before activation.",
 no_published_templates: "No runtime configurations have been published.",
 no_compatible_templates: "Published configurations do not match the configured runtime.",
 user_quota_reached: "Your active sandbox limit has been reached.",
 organization_quota_reached: "The organization's active sandbox limit has been reached.",
 runtime_launch_budget_used: "The bounded runtime's approved launch budget has been used. Deletion does not renew that budget.",
 historical_reservation_invalid: "The historical reservation no longer matches the approved binding or cleanup state. An operator must review it before creation can resume.",
 runtime_limits_mismatch: "Organization limits do not match the approved bounded runtime. An administrator must correct them in Sandbox setup.",
 runtime_workload_quota_reached: "The runtime's one workload is still retained. Stop and unfinished cleanup continue to occupy that slot.",
};
export function SandboxBlockedReasons({status,setupLink=true}:{status?:SandboxCreationStatus;setupLink?:boolean}) {
 if(!status)return <p className="sb-help">Creation is unavailable. This server does not provide setup details; refresh after the server is updated.</p>;
 return <div className="sb-help"><ul className="my-3 space-y-2">{status.blocked_reasons.map(reason=><li key={reason}>{sandboxBlockerMessages[reason] ?? `Creation is blocked (${reason}).`}</li>)}</ul>{status.can_admin ? (setupLink ? <Link to="/sandboxes/setup" className="sb-inline-link">Open Sandbox setup →</Link> : null) : <p>For organization settings or runtime setup, contact an administrator. A runtime restriction or launch limit requires operator review.</p>}</div>;
}

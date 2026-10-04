import type { components } from "@tunnex/shared";
import { Badge } from "./ui";
type Request = components["schemas"]["AppAccessAccessRequest"];
export function AppAccessRequestStatus({ request, showOwner = false }: { request: Request | null; showOwner?: boolean }) {
  if (!request) return null;
  return <div className="space-y-1 text-sm"><Badge tone={request.status === "pending" ? "warn" : "neutral"}>{request.status === "pending" ? "Access request pending" : request.status === "approved" ? "Request approved" : "Request rejected"}</Badge>{showOwner && <p className="text-ink-secondary">App admin: {request.app_admin ? request.app_admin.name || request.app_admin.email : "Unassigned"}{!request.app_admin?.available && " · Organization administrator review available"}</p>}{request.decision_reason && <p className="text-ink-secondary">Decision: {request.decision_reason}</p>}</div>;
}

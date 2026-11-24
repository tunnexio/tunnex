import { Link } from "react-router-dom";
import { useOptionalAuth } from "../lib/auth";

// SA-UX-2 AA-5: every "Applications is unavailable" state says who can fix it and where. Server administrators get
// the link to Application domains; the organization switch lives in Settings → Features (organization admins).
export const availabilityText: Record<string, string> = {
  available: "Only published applications granted to you appear here.",
  feature_disabled: "Applications is off for this organization. An organization administrator can turn it on in Settings → Features.",
  feature_unavailable: "Applications requires an eligible license. Ask an organization administrator about the license.",
  domain_unavailable: "Application access setup is not complete: the application domain is not configured. Ask a server administrator to finish it in Settings → Application domains.",
  parent_unavailable: "Sign in again to open applications with this login.",
};

export function AppAccessAvailabilityNotice({ availability }: { availability: string }) {
  const auth = useOptionalAuth();
  const serverAdmin = auth?.state.status === "authed" && Boolean(auth.state.user.cp_admin);
  return <p role="status" className="app-access-notice">{availabilityText[availability] ?? "Applications is unavailable right now."}
    {availability === "domain_unavailable" && serverAdmin && <> <Link to="/settings?section=app-access-domains">Open Application domains</Link></>}
  </p>;
}

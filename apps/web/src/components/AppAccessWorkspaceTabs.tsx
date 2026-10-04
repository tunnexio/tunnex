import { WorkspaceTabs } from "./WorkspaceTabs";

type Capabilities = {
  viewApplications: boolean;
  manageGrants: boolean;
  manageAssigned?: boolean;
  pending?: number;
};

/** Shared navigation projection; callers supply existing authorized capabilities. */
export default function AppAccessWorkspaceTabs({ viewApplications, manageGrants, manageAssigned = false, pending = 0 }: Capabilities) {
  const administrative = viewApplications || manageGrants;
  return <WorkspaceTabs label="App Access" items={administrative ? [
    ...(viewApplications ? [{ href: "/app-access/applications", label: "Applications" }] : []),
    ...(manageGrants ? [{ href: "/app-access/access", label: "Access" }, { href: "/app-access/requests", label: "Requests" }] : []),
    { href: "/app-access/my-applications", label: "My Applications" },
  ] : [
    { href: "/app-access/my-applications", label: "My access" },
    { href: "/app-access/company-applications", label: "Company apps" },
    { href: "/app-access/my-requests", label: "My requests" },
    ...(manageAssigned ? [{ href: "/app-access/managed-applications", label: pending ? "Manage access · " + pending + " pending" : "Manage access" }] : []),
  ]} />;
}

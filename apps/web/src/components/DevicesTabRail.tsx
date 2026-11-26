import type { ReactNode } from "react";
import { WorkspaceTabs } from "./WorkspaceTabs";
import "../devices-policy-workspace.css";

// LS-UX-2: Approvals and Posture are admin work; members see their own devices only. The Devices page
// passes `adminTabs={false}` once it knows the person cannot approve devices (UX only; the API decides).
export function DevicesTabRail({ actions, adminTabs = true }: { actions?: ReactNode; adminTabs?: boolean } = {}) {
  return <div className="devices-workspace-nav"><WorkspaceTabs label="Device sections" items={[
    { href: "/devices", label: "Devices" },
    { href: "/devices/approvals", label: "Approvals" },
    { href: "/devices/posture", label: "Posture" },
  ].filter(item => adminTabs || item.href === "/devices")} />{actions && <div className="devices-workspace-actions">{actions}</div>}</div>;
}

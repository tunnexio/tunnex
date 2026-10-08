import type { ReactNode } from "react";
import { WorkspaceTabs } from "./WorkspaceTabs";
import "../devices-policy-workspace.css";

export function DevicesTabRail({ actions }: { actions?: ReactNode } = {}) {
  return <div className="devices-workspace-nav"><WorkspaceTabs label="Device sections" items={[
    { href: "/devices", label: "Devices" },
    { href: "/devices/approvals", label: "Approvals" },
    { href: "/devices/posture", label: "Posture" },
  ]} />{actions && <div className="devices-workspace-actions">{actions}</div>}</div>;
}

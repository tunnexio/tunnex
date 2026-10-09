import { WorkspaceTabs } from "./WorkspaceTabs";
import type { ReactNode } from "react";

export function AgentsTabRail({ actions }: { actions?: ReactNode } = {}) {
  return <div className="agents-workspace-nav"><WorkspaceTabs label="AI Agents sections" items={[
    { href: "/agents", label: "Agents" },
    { href: "/agents/groups", label: "Agent groups" },
    { href: "/agents/model-access", label: "Model access" },
    { href: "/agents/policies", label: "Policy templates" },
  ]} />{actions && <div className="agents-workspace-actions">{actions}</div>}</div>;
}

import { WorkspaceTabs } from "./WorkspaceTabs";

export function AgentsTabRail() {
  return <WorkspaceTabs label="AI Agents sections" items={[
    { href: "/agents", label: "Agents" },
    { href: "/agents/groups", label: "Agent groups" },
    { href: "/agents/model-access", label: "Model access" },
    { href: "/agents/policies", label: "Policy templates" },
  ]} />;
}

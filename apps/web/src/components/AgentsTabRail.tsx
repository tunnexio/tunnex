import { WorkspaceTabs } from "./WorkspaceTabs";

export function AgentsTabRail() {
  return <WorkspaceTabs label="AI Agents sections" items={[
    { href: "/agents", label: "Agents" },
    { href: "/agents/groups", label: "Agent groups" },
    { href: "/agents/policies", label: "Policy templates" },
    { href: "/agents/mcp", label: "MCP profiles" },
    { href: "/agents/model-access", label: "Model access" },
  ]} />;
}

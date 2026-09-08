import { Navigate, useLocation } from "react-router-dom";

export function LegacyWorkspaceRedirect({ groups = false }: { groups?: boolean }) {
  const { search, hash } = useLocation();
  const params = new URLSearchParams(search);
  const agentGroup = params.get("type") === "agents" || params.get("group")?.startsWith("agents:");
  const pathname = groups ? (agentGroup ? "/agents/groups" : "/users/groups") : "/ai-gateway/models";
  return <Navigate replace to={{ pathname, search, hash }} />;
}

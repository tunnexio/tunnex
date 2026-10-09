import type { ReactNode } from "react";
import { WorkspaceTabs } from "./WorkspaceTabs";
import "../access-policies-resources.css";

export function AccessTabRail({ actions, includeKubernetesScopes = false }: { actions?: ReactNode; includeKubernetesScopes?: boolean } = {}) {
  return <div className="access-workspace-nav"><WorkspaceTabs label="Access sections" items={[
    { href: "/access", label: "Rules" },
    { href: "/access/resources", label: "Resources" },
    ...(includeKubernetesScopes ? [{ href: "/access/kubernetes-scopes", label: "Kubernetes scopes" }] : []),
  ]} />{actions && <div className="access-workspace-actions">{actions}</div>}</div>;
}

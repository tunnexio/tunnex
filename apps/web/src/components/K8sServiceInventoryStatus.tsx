import { useId, type ReactNode } from "react";
import "../kubernetes-operations.css";
import { Badge } from "./ui";

export type ConnectedAgentInventoryState =
  | { kind: "unavailable" }
  | { kind: "loading" }
  | { kind: "ready"; content: ReactNode }
  | { kind: "empty" }
  | { kind: "stale" }
  | { kind: "error"; message?: string };

/**
 * Truthful state boundary for the future authenticated connected-agent
 * inventory read. It deliberately owns no API call and never derives cluster
 * objects from the exposed-Service list.
 */
export function K8sServiceInventoryStatus({
  state,
  variant = "card",
}: {
  state: ConnectedAgentInventoryState;
  variant?: "card" | "flat";
}) {
  const headingId = useId();
  return (
    <section
      aria-labelledby={headingId}
      className={`k8s-inventory-status k8s-inventory-${variant}`}
    >
      <div className="k8s-operation-heading">
        <h3 id={headingId}>
          Connected-agent inventory
        </h3>
        {state.kind === "ready" && <Badge tone="neutral">Authenticated report</Badge>}
      </div>
      <InventoryStateBody state={state} />
    </section>
  );
}

function InventoryStateBody({ state }: { state: ConnectedAgentInventoryState }) {
  switch (state.kind) {
    case "unavailable":
      return <>
        <p role="status" className="k8s-operation-note">Authenticated inventory is unavailable. Namespace, Service and port selection requires a current connected-agent report.</p>
        <details className="k8s-operation-disclosure"><summary>Inventory source</summary><div><p>Verified dropdowns are unavailable until this cluster reports through the authenticated connected-agent inventory contract.</p><p>No cluster objects or zero counts are inferred from the exposed-Service list.</p></div></details>
      </>;
    case "loading":
      return <p role="status" className="k8s-operation-note">Loading authenticated connected-agent inventory…</p>;
    case "ready":
      return <div className="k8s-inventory-content">{state.content}</div>;
    case "empty":
      return (
        <p role="status" className="k8s-operation-note">
          The authenticated connected agent reported an empty Kubernetes inventory.
        </p>
      );
    case "stale":
      return (
        <p role="status" className="k8s-operation-note k8s-operation-warning">
          Connected-agent inventory is stale. Refresh it before selecting a namespace, Service, or port.
        </p>
      );
    case "error":
      return (
        <p role="alert" className="k8s-operation-note text-danger">
          {state.message ?? "Could not read authenticated connected-agent inventory."}
        </p>
      );
  }
}

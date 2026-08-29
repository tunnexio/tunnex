import type { ReactNode } from "react";
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
  return (
    <section
      aria-labelledby="verified-k8s-inventory"
      className={variant === "card" ? "tnx-card-surface p-3" : "py-1"}
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 id="verified-k8s-inventory" className="text-sm font-semibold text-ink-heading">
          Connected-agent inventory
        </h3>
        {state.kind === "ready" && <Badge tone="ok">VERIFIED REPORT</Badge>}
      </div>
      <InventoryStateBody state={state} />
    </section>
  );
}

function InventoryStateBody({ state }: { state: ConnectedAgentInventoryState }) {
  switch (state.kind) {
    case "unavailable":
      return (
        <p role="status" className="mt-1 text-cell text-ink-tertiary">
          Verified namespace, Service, and exact-port dropdowns are unavailable until this cluster reports through the authenticated connected-agent inventory contract. No cluster objects or zero counts are inferred from the exposed-Service list.
        </p>
      );
    case "loading":
      return <p role="status" className="mt-1 text-cell text-ink-tertiary">Loading authenticated connected-agent inventory…</p>;
    case "ready":
      return <div className="mt-3">{state.content}</div>;
    case "empty":
      return (
        <p role="status" className="mt-1 text-cell text-ink-tertiary">
          The authenticated connected agent reported an empty Kubernetes inventory.
        </p>
      );
    case "stale":
      return (
        <p role="status" className="mt-1 text-cell text-warn">
          Connected-agent inventory is stale. Refresh it before selecting a namespace, Service, or port.
        </p>
      );
    case "error":
      return (
        <p role="alert" className="mt-1 text-cell text-danger">
          {state.message ?? "Could not read authenticated connected-agent inventory."}
        </p>
      );
  }
}

import { MANAGED_BADGE } from "../lib/k8sview";

// ManagedBadge (S10.2 D2 cond 1) — the ONE badge marking an object the GitOps operator owns, shared by the
// Kubernetes + Access pages so the two never drift (L2). MANAGED_BADGE is sourced from the view-model (one
// string). Renders inline; safe to place inside a heading or a row label.
export function ManagedBadge() {
  return (
    <span className="tnx-status tnx-status-metadata">
      {MANAGED_BADGE}
    </span>
  );
}

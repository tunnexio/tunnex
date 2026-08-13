import { MANAGED_BADGE } from "../lib/k8sview";

// ManagedBadge (S10.2 D2 cond 1) — the ONE badge marking an object the GitOps operator owns, shared by the
// Kubernetes + Access pages so the two never drift (L2). MANAGED_BADGE is sourced from the view-model (one
// string). Renders inline; safe to place inside a heading or a row label.
export function ManagedBadge() {
  return (
    <span className="ml-2 rounded-sm bg-sky-500/15 px-1.5 py-0.5 align-middle text-[10px] font-medium text-sky-300">
      {MANAGED_BADGE}
    </span>
  );
}

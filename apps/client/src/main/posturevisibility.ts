import type { HealthReportResult } from "./deviceconfig";

// Posture visibility is a client presentation state, not a new server verdict.
// It remains explicit so a warn-mode result is never silently folded into a
// healthy tunnel, and so repeated report cycles cannot spam notifications.
export type PostureVisibility = "clear" | "warning" | "blocked";

export function postureVisibilityFor(result: Pick<HealthReportResult, "state" | "blocked">): PostureVisibility {
  if (result.blocked) return "blocked";
  return result.state === "noncompliant" ? "warning" : "clear";
}

export function postureVisibilityChanged(previous: PostureVisibility, next: PostureVisibility): boolean {
  return previous !== next;
}

// A required posture failure removes the peer from the gateway, but the local
// WireGuard interface may still independently report up or down for a short
// while. Neither transport fact clears the policy decision: showing
// "Disconnected" would hide WHY access stopped. Only a later compliant verdict
// or an explicit user disconnect clears the block.
export function postureBlockedOverridesTransport(state: string): boolean {
  return state === "up" || state === "down";
}

// Warn-mode posture does not remove the peer, so it must stay visible across
// routine successful heartbeats. A real down/failed transport state still wins:
// it is a separate connection problem, not evidence that the warning cleared.
export function postureWarningOverridesTransport(state: string): boolean {
  return state === "up";
}

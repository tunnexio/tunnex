import type { Node } from "./api";

/**
 * Node-selection rules for surfaces that must choose a gateway (S13.1 Slice 3, the four-surface decisions
 * census).
 *
 * WHY THIS IS A MODULE AND NOT `nodes[0]`. The device-create path used `nodes[0].id` directly, and the list it
 * indexes comes from `ListNodes` — every node in the org, revoked included, ordered by `created_at`. So on any
 * deployment whose OLDEST gateway had been revoked, every new device was homed on a dead gateway and issued a
 * config pointing at nothing. The EPIC 11 walk's own fleet was in exactly that state: `aws-gw-1` was revoked and
 * had the earliest `created_at`, so it WAS `nodes[0]`.
 *
 * The same page's sibling surfaces got it right — `Sites.tsx` filters `status === "active"` before offering a
 * gateway — which is the asymmetry class this epic keeps finding: two consumers of one list, one of them
 * remembering. Selection lives here now so there is one rule and it is testable.
 */

/** Gateways eligible to receive new work. Revoked gateways can neither renew nor reconcile. */
export function selectableNodes(nodes: Node[]): Node[] {
  return nodes.filter((n) => n.status === "active");
}

/**
 * The gateway a new device should be homed on, or null when there is none.
 *
 * Returns null rather than falling back to a revoked gateway: homing a device on a dead gateway produces a
 * one-time config that can never connect, and a one-time secret cannot be re-issued — so the failure is not
 * merely inconvenient, it burns the artifact. Refusing is the recoverable direction.
 */
export function defaultDeviceNode(nodes: Node[]): Node | null {
  const eligible = selectableNodes(nodes);
  // ⛔ ONE ELIGIBLE GATEWAY IS A DEFAULT. TWO IS A QUESTION (S14.21b).
  //
  // This returned `eligible[0]` — the FIRST ACTIVE node in `created_at` order. On the live rig that homed a
  // macOS laptop onto an in-cluster KUBERNETES gateway, because that node was enrolled four days earlier than
  // the general-purpose VM gateway sitting beside it. The device was minted, and the gateway it was homed on
  // has never recorded a handshake from any peer.
  //
  // > **`nodes[0]` OVER A FILTERED LIST IS STILL `nodes[0]`.** S13.1 replaced "first, including dead ones"
  // > with "first, excluding dead ones" and left FIRST standing. `created_at` order is an implementation
  // > detail of `ListNodes` doing duty as a product decision.
  //
  // ⛔ AND NOTHING IN THE PAYLOAD CAN DECIDE IT. Measured, not assumed: `Node` carries id · name · status ·
  // agent_version · enrolled_at · last_seen_at · policy_degraded · site_id · max_policy_version ·
  // ovpn_health · is_site_hub · policy_degraded_kind. `is_site_hub` is site TOPOLOGY. `capabilities` is not
  // exposed, and would not help — a VM gateway and a cluster gateway carry the same keys. `endpoint` is not
  // in the payload at all. There is no kind or type field. The cluster linkage lives in `k8s_clusters`,
  // keyed by `site_id`, which this path never fetches — and "belongs to a site" is not "cannot serve a
  // laptop" anyway.
  //
  // So the product CANNOT choose correctly from what it has, and a smarter sort would only hide that. The
  // honest behaviour is to return null and make the caller ask. Returning null is already this function's
  // answer for "none eligible"; it is now also its answer for "more than one, and I cannot know which".
  return eligible.length === 1 ? eligible[0] : null;
}

/**
 * Does the operator have to choose? True when more than one gateway is eligible.
 *
 * Separate from `defaultDeviceNode` returning null, because the two nulls mean OPPOSITE things: "no gateway
 * can take this device" is an error to explain, and "several can, pick one" is a question to ask. A caller
 * that cannot tell them apart will render the wrong one.
 */
export function requiresGatewayChoice(nodes: Node[]): boolean {
  return selectableNodes(nodes).length > 1;
}

/**
 * Display label for a node in a list that may contain several rows sharing a name.
 *
 * Migration 0056 made `(org_id, name)` unique only among non-revoked rows, so a name may be held by several
 * revoked gateways plus at most one active one. Any surface listing revoked rows can therefore show duplicate
 * labels, and a label alone stops identifying a gateway.
 *
 * The census decision for DISPLAYS: keep the name, and mark the revoked ones — the status is what disambiguates,
 * and it is information the operator needs anyway. (Surfaces that OFFER a gateway resolve it differently: they
 * filter to active via selectableNodes, so duplicates cannot arise there at all.)
 */
export function nodeLabel(n: Pick<Node, "name" | "status">): string {
  return n.status === "revoked" ? `${n.name} (revoked)` : n.name;
}

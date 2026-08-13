import { describe, expect, it } from "vitest";
import {
  defaultDeviceNode,
  requiresGatewayChoice,
  selectableNodes,
} from "../src/lib/nodepick";
import type { Node } from "../src/lib/api";

// ⛔ THE DEFECT: A macOS LAPTOP WAS HOMED ON AN IN-CLUSTER KUBERNETES GATEWAY.
//
// `defaultDeviceNode` returned `selectableNodes(nodes)[0]` — the first ACTIVE node in `created_at` order. On
// the live rig the `k8s` gateway was enrolled four days before the general-purpose VM gateway, so it won. The
// device was minted and that gateway has never recorded a handshake from any peer.
//
// > **`nodes[0]` OVER A FILTERED LIST IS STILL `nodes[0]`.** S13.1 replaced "first, including dead ones" with
// > "first, excluding dead ones" and left FIRST standing — an ordering detail of `ListNodes` doing duty as a
// > product decision.
//
// Measured before fixing: NOTHING in the Node payload distinguishes a gateway that can serve a laptop from
// one that cannot. No kind, no type; `endpoint` and `capabilities` are not exposed; `is_site_hub` is site
// topology; the cluster linkage lives in another table keyed by site. So the product cannot choose, and the
// fix is to stop pretending it can.

const gw = (id: string, created: string, status: Node["status"] = "active") =>
  ({ id, name: `gw-${id}`, status, enrolled_at: created }) as unknown as Node;

describe("⛔ the product asks rather than guessing", () => {
  it("ONE eligible gateway is a default — the ordinary case still works without a prompt", () => {
    const nodes = [gw("a", "2026-07-27"), gw("b", "2026-08-01", "revoked")];
    expect(requiresGatewayChoice(nodes)).toBe(false);
    expect(defaultDeviceNode(nodes)?.id).toBe("a");
  });

  it("⛔ TWO eligible gateways is a QUESTION — no default, whatever the order", () => {
    // The exact live shape: k8s (older) and the VM gateway (newer), both active.
    const nodes = [gw("k8s", "2026-07-27"), gw("vm", "2026-08-01")];
    expect(requiresGatewayChoice(nodes)).toBe(true);
    expect(defaultDeviceNode(nodes)).toBeNull();
    // ...and reversing the list must not change the answer. Under the old rule it changed WHICH gateway
    // silently received the device.
    expect(defaultDeviceNode([...nodes].reverse())).toBeNull();
  });

  it("NONE eligible is still null — but it is a DIFFERENT null", () => {
    // "no gateway can take this device" is an error to explain; "several can, pick one" is a question to
    // ask. A caller that cannot tell them apart renders the wrong sentence.
    const nodes = [gw("a", "2026-07-27", "revoked")];
    expect(defaultDeviceNode(nodes)).toBeNull();
    expect(requiresGatewayChoice(nodes)).toBe(false); // nothing to choose between
    expect(selectableNodes(nodes)).toHaveLength(0);
  });

  it("revoked gateways are never offered as a choice", () => {
    const nodes = [
      gw("a", "2026-07-27"),
      gw("b", "2026-08-01"),
      gw("c", "2026-08-02", "revoked"),
    ];
    expect(selectableNodes(nodes).map((n) => n.id)).toEqual(["a", "b"]);
  });
});

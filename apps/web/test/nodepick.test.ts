import { describe, expect, it } from "vitest";
import {
  defaultDeviceNode,
  nodeLabel,
  selectableNodes,
} from "../src/lib/nodepick";
import type { Node } from "../src/lib/api";

const node = (over: Partial<Node>): Node =>
  ({
    id: "id",
    name: "gw",
    status: "active",
    agent_version: "v0",
    ...over,
  }) as Node;

describe("device-target selection (S13.1 Slice 3)", () => {
  // THE DEFECT, as a red. Device creation used `nodes[0].id` over a list that includes revoked rows ordered by
  // created_at — so on any deployment whose OLDEST gateway had been revoked, every new device was homed on a dead
  // gateway. The EPIC 11 walk's fleet was in exactly that state: `aws-gw-1` was revoked and had the earliest
  // created_at, so it WAS nodes[0].
  it("never picks a revoked gateway, even when it is first", () => {
    const nodes = [
      node({ id: "revoked-oldest", name: "aws-gw-1", status: "revoked" }),
      node({ id: "live", name: "aws-gw-2", status: "active" }),
    ];
    expect(defaultDeviceNode(nodes)?.id).toBe("live");
  });

  // Refusing beats falling back: a device config is a ONE-TIME secret, so homing it on a dead gateway burns an
  // artifact that cannot be re-issued. null is the recoverable answer.
  it("returns null when every gateway is revoked, rather than falling back", () => {
    const nodes = [
      node({ id: "a", status: "revoked" }),
      node({ id: "b", status: "revoked" }),
    ];
    expect(defaultDeviceNode(nodes)).toBeNull();
    expect(selectableNodes(nodes)).toHaveLength(0);
  });

  it("returns null on an empty fleet", () => {
    expect(defaultDeviceNode([])).toBeNull();
  });

  // DISPLAYS census decision: migration 0056 made names unique only among non-revoked rows, so a list showing
  // revoked rows can show duplicate labels and the name alone stops identifying a gateway. The status is what
  // disambiguates.
  it("marks revoked rows in labels, since a name alone no longer identifies a gateway", () => {
    expect(nodeLabel({ name: "aws-gw-1", status: "revoked" })).toBe(
      "aws-gw-1 (revoked)",
    );
    expect(nodeLabel({ name: "aws-gw-1", status: "active" })).toBe("aws-gw-1");
  });
});

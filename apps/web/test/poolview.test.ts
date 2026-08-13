import { describe, expect, it } from "vitest";
import {
  RESIZE_ATOMIC_NOTE,
  orphanReasonCopy,
  orphanTail,
} from "../src/lib/poolview";

// ⛔ THE REFUSAL IS ATOMIC AND THE PANEL NOW SAYS SO.
//
// Not a reassurance — a fact read off the transaction boundary. `ResizePool` returns
// `&ShrinkOrphansError{...}` inside `withTx` (devices/service.go:539), BEFORE
// `UpdateOrgPoolCidr` (:541), so the tx rolls back and the pool row is untouched. Without
// the sentence, an operator facing a red box of device names cannot tell a clean refusal
// from a partial resize — and on a shrink that is the difference between "try again" and
// "audit the fleet".
describe("RESIZE_ATOMIC_NOTE", () => {
  it("tells the operator nothing was written", () => {
    expect(RESIZE_ATOMIC_NOTE).toMatch(/nothing was changed/i);
  });
});

// ⛔ THE SUBTLE REASON, EXPLAINED. A `reserved_collision` address is numerically INSIDE the
// new range (ipalloc.go:78) — it looks fine next to the CIDR — but sits on the network,
// gateway or broadcast address the allocator will never hand out. An operator checking by
// eye concludes the server is wrong. Naming the three addresses is what stops that.
describe("orphanReasonCopy", () => {
  it("says WHY an address inside the new range is still stranded", () => {
    const copy = orphanReasonCopy("reserved_collision");
    expect(copy).toMatch(/inside the new range/i);
    expect(copy).toMatch(/network/i);
    expect(copy).toMatch(/gateway/i);
    expect(copy).toMatch(/broadcast/i);
  });

  it("keeps the out_of_range case plain", () => {
    expect(orphanReasonCopy("out_of_range")).toBe("outside the new range");
  });

  it("does not invent a reason it was not given", () => {
    // A reason the client does not know must not be rendered as one it does — the enum can
    // grow server-side (ipalloc.go's const block) and this is what a new value must hit.
    const copy = orphanReasonCopy("some_future_reason");
    expect(copy).toBe("stranded by this resize");
    expect(copy).not.toMatch(/outside the new range/i);
  });
});

// The server caps the rendered list at 20 (`orphanCap`, resize_handlers.go:19) while
// `orphan_count` stays honest, so the panel must reconcile the two numbers rather than let
// the visible list imply the total.
describe("orphanTail", () => {
  it("reports the hidden remainder when the list is capped", () => {
    expect(orphanTail(27, 20)).toBe("…and 7 more.");
  });

  it("says nothing when the list is complete", () => {
    expect(orphanTail(7, 7)).toBeNull();
  });

  it("does not render a negative tail if the server ever sends fewer than it shows", () => {
    expect(orphanTail(3, 5)).toBeNull();
  });
});

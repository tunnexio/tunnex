// Pool CIDR resize — the refusal, in words.
//
// The panel itself already existed and was already right about the hard part: it renders the
// server's capped orphan list and reports `orphan_count` as the honest total (Settings.tsx's
// PoolSection). This module carries the two things it did NOT say, both of which are facts
// about the server rather than reassurances invented for the operator.

/**
 * ⛔ NAMING A CODE THE SERVER NEVER EMITS.
 *
 * The wireframe labels this refusal **`409 resize_conflict`**. MEASURED: that string exists
 * NOWHERE in the repository — not in `openapi.yaml`, not in the handlers, not in the
 * generated types. The 409 body is a bare `ResizeConflict` schema (`openapi.yaml:2883`) with
 * exactly two fields, `orphan_count` and `orphans`, and **no `code` at all**; the client
 * recognises it structurally (`isResizeConflict` duck-types the two keys) precisely because
 * there is no code to switch on.
 *
 * Rendering `resize_conflict` verbatim would print an identifier that no support engineer
 * could grep, in the one place an operator would copy it from. So the error code is NOT
 * rendered — the constant below exists to hold the finding, not the string.
 */
export const RESIZE_CONFLICT_HAS_NO_CODE = true;

/**
 * ⛔ THE REFUSAL IS ATOMIC, AND THE OPERATOR WAS NEVER TOLD.
 *
 * Verified at the transaction boundary, not assumed: `ResizePool` builds the orphan list and
 * `return &ShrinkOrphansError{...}` INSIDE `withTx` (devices/service.go:539), which is
 * BEFORE `UpdateOrgPoolCidr` (:541) — so the transaction rolls back and the pool row is
 * untouched. The wireframe says *"none were changed"* and it is right; the shipped panel
 * showed a red box listing devices and left the operator to guess whether a partial resize
 * had landed. On a shrink refusal that guess is the difference between "try again" and
 * "audit the fleet".
 */
export const RESIZE_ATOMIC_NOTE = "Nothing was changed.";

/**
 * Why one stranded device blocks the shrink.
 *
 * `reserved_collision` is the subtle one and the shipped copy under-explained it. The
 * address is numerically INSIDE the new range — it looks fine in the list — but it sits on
 * the range's network, gateway or broadcast address, which the allocator will never hand
 * out (ipalloc.go:78). An operator comparing the address against the new CIDR by eye
 * concludes the server is wrong. Naming the three reserved addresses is what stops that.
 */
export function orphanReasonCopy(reason: string): string {
  switch (reason) {
    case "reserved_collision":
      return "inside the new range, but on its network, gateway or broadcast address";
    case "out_of_range":
      return "outside the new range";
    default:
      // A reason the client does not know is not a reason to claim one.
      return "stranded by this resize";
  }
}

/**
 * The capped-list tail. The server caps the rendered list at 20 (`orphanCap`,
 * resize_handlers.go:19) while `orphan_count` stays honest, so the panel must reconcile the
 * two numbers rather than let the list imply the total.
 */
export function orphanTail(orphanCount: number, shown: number): string | null {
  const rest = orphanCount - shown;
  return rest > 0 ? `…and ${rest} more.` : null;
}

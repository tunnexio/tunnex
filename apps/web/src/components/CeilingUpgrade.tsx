import { Link } from "react-router-dom";

/**
 * ⛔ THE MOMENT A CUSTOMER WOULD HAVE PAID, AND THE PRODUCT USED TO SAY NOTHING.
 *
 * `gateway_limit_reached` and `org_limit_reached` are the only two refusals in this product that mean
 * "you have outgrown what you have". Until now both surfaced as a generic red error string: correct,
 * unactionable, and offering no route. The operator was told no at the exact instant they were deciding
 * to buy, and handed nowhere to go.
 *
 * > ## ⭐ **A LIMIT WITHOUT A ROUTE IS A DEAD END. A LIMIT WITH ONE IS A PRICE.**
 *
 * ⚠ IT NAMES THE BAND AND THE CEILING BECAUSE THE SERVER ALREADY DOES. The refusal message from the API is
 * rendered verbatim above these links — it says which band, which ceiling, how many exist, and that
 * nothing running is affected. This component adds only what the server cannot: navigation.
 *
 * ⛔ AND IT IS NOT AN UPSELL BANNER. It appears ONLY when a refusal has actually happened. A permanent
 * "upgrade now" on a screen the customer is using correctly teaches them to stop reading the screen.
 */
export function CeilingUpgrade({
  /** The server's own refusal text — already names band, ceiling, and what is unaffected. */
  message,
  /** Which limit was hit. Only changes the wording of the route, never whether one is offered. */
  kind,
}: {
  message: string;
  kind: "gateway" | "organization";
}) {
  const what = kind === "gateway" ? "more gateways" : "more organizations";
  return (
    <div className="mt-3 rounded-card border border-warn/30 bg-warn/5 p-3">
      <p className="text-cell text-ink-body">{message}</p>
      <div className="mt-2.5 flex flex-wrap items-center gap-x-4 gap-y-1.5">
        {/* ⭐ INSTALL COMES FIRST, DELIBERATELY. A customer who already HOLDS a key — bought minutes ago,
            or sitting in an inbox from a trial request — is one paste away from being unblocked, and
            sending them to a request form they do not need is the more annoying of the two wrong orders. */}
        <Link
          to="/settings#licence"
          className="text-cell font-medium text-accent hover:underline"
        >
          Install a licence key
        </Link>
        {/* ⚠ EXTERNAL, AND IT SAYS SO. The request flow lives on tunnex.io, not in the product — a
            deployment is air-gappable and must never depend on reaching us, so this is a link a human
            follows, never a call the product makes. */}
        <a
          href="https://tunnex.io/trial"
          target="_blank"
          rel="noreferrer"
          className="text-cell font-medium text-accent hover:underline"
        >
          Request a licence for {what} ↗
        </a>
      </div>
    </div>
  );
}

/**
 * ceilingKind maps an API error code to the limit it refers to, or null when the error is something else.
 *
 * ⛔ CODE, NEVER PROSE. Matching on the message would break the first time the wording improved — and the
 * wording is meant to improve, because it is the part the operator reads.
 */
export function ceilingKind(
  code: string | null | undefined,
): "gateway" | "organization" | null {
  if (code === "gateway_limit_reached") return "gateway";
  if (code === "org_limit_reached") return "organization";
  return null;
}

/**
 * ceilingSentence is the STANDING notice on the Gateways page — shown whenever `used >= ceiling`, with no
 * refusal to hang it on.
 *
 * ⛔ THERE IS NO REFUSAL TO REACT TO, AND THAT IS THE WHOLE REASON THIS EXISTS. Gateways enrol by CLI or
 * API: the agent redeems a join token on the customer's own server, so the 403 lands in a terminal
 * hundreds of miles from anyone reading a screen. An operator about to add a gateway opens this page
 * first — so this page is where they must learn there is no room, BEFORE they go and try.
 *
 * ⭐ AT-CEILING AND OVER-CEILING ARE DIFFERENT SENTENCES, AND SAYING THE WRONG ONE MISLEADS.
 *
 *   used === ceiling → "no room left". True, and the remedy is either a licence OR revoking one.
 *   used  >  ceiling → "past your limit". Also true — and the difference is ACTIONABLE: at 6 against 1,
 *                      revoking a gateway does NOT free a slot, because five would still be over. Telling
 *                      that operator "you have no room left" invites them to revoke one and try again,
 *                      which fails, and now they have destroyed a working gateway for nothing.
 *
 * ⚠ SO THE OVER-CEILING SENTENCE MUST SAY HOW FAR OVER, and must not offer revocation as a route. That is
 * the state this deployment is in today (6 against 1) and it is the first one the founder will meet.
 */
export function ceilingSentence(
  used: number,
  ceiling: number,
  tier: string,
): string {
  if (used > ceiling) {
    const over = used - ceiling;
    return (
      `This deployment is on the ${tier} band, which allows ${ceiling} ` +
      `${ceiling === 1 ? "gateway" : "gateways"}, and ${used} are enrolled — ${over} past the limit. ` +
      `Nothing running is affected and no gateway will be stopped. ` +
      // ⛔ THE CLAUSE THAT PREVENTS A DESTRUCTIVE MISTAKE. Without it the obvious move is to revoke one.
      `Revoking one will not free a slot at this count; enrolling another needs a licence.`
    );
  }
  return (
    `This deployment is on the ${tier} band, which allows ${ceiling} ` +
    `${ceiling === 1 ? "gateway" : "gateways"}, and ${used} ${used === 1 ? "is" : "are"} enrolled. ` +
    // ⛔ "REVOKE ONE YOU NO LONGER USE" READ AS HOUSEKEEPING AND WAS A DISCONNECTION.
    //
    // Revoking cascades to every device homed to that gateway (`RevokeDevicesForNode`, in the same
    // transaction), so the remedy this notice recommends can drop fifty people off the network. The
    // sentence was TRUE — revoking really does free a slot — and it named none of that.
    //
    // ⛔ AND IT IS PERMANENT. `restoreNodeDevices` requires a LIVE target gateway because "a revoked
    // gateway is never active again" (openapi.yaml:3538) — so the word "retire" has to carry irreversibility
    // here, not just in the confirm two clicks later.
    //
    // ⛔ AND THE SENTENCE CHANGED AGAIN WHEN THE TRANSFER STEP SHIPPED (S12.12 D1), because "disconnects
    // every device homed to it" stopped being true: the revoke is now REFUSED while any device is homed
    // there. So the cost this notice names is no longer an outage — it is WORK, and naming the work is what
    // stops an operator planning a five-second retirement and finding a fleet-wide re-import.
    //
    // ⚠ IT NAMES THE RE-ISSUE, which is the part that surprises. Moving the devices is one click; every
    // moved device holds a config baking the old gateway's endpoint, so their owners must re-import. An
    // operator who learns that at the ceiling can schedule it; one who learns it afterwards cannot.
    //
    // ⚠ THE COUNT ITSELF BELONGS ON THE CONFIRM, NOT HERE. This notice is deployment-scoped and does not
    // know which gateway an operator will pick; promising a number it cannot compute would be the same
    // mistake in the other direction. It states the KIND of cost and sends them where the number is.
    `There is no room for another — install a licence, or retire a gateway. ` +
    `Retiring one is permanent, and a gateway cannot be retired while devices are homed to it: ` +
    `move them to another gateway first, which re-issues their configurations.`
  );
}

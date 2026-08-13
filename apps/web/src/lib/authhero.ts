// Auth screens — the hero panel, and the claims it is allowed to make.
//
// ⛔ THE WIREFRAME'S TRUST BADGES ASSERT TWO THINGS WE DO NOT HAVE, ON THE MOST-VIEWED PAGE IN THE
// PRODUCT. Read the block, cut what has no backing, and say why — the section protocol applied to
// a claim rather than to an endpoint.
//
//   "SOC 2 Type II certified"      ⛔ CUT. MEASURED: zero mentions of SOC 2 anywhere in this
//                                  repository outside the wireframe itself. There is no audit, no
//                                  report, no auditor. This is a FALSE COMPLIANCE CLAIM shown to
//                                  every visitor before they authenticate, and it is the highest-
//                                  stakes unbuilt claim in the epic precisely because of where it
//                                  sits. It goes back when there is a report to point at.
//
//   "SSO + SCIM enterprise ready"  ⛔ CUT AS WRITTEN. SSO ships. SCIM is explicitly OUT of v1 and
//                                  deferred to S7.5.2b (D4, S7.5.2-decisions.md:131). The badge is
//                                  half true, and the false half is the SPECIFIC STANDARD NAMED —
//                                  which is the half a buyer checks. Replaced with the true claim.
//
//   "WireGuard® kernel-fast tunnels"  ✅ KEPT. The data plane is wgctrl over the kernel module.
//
// > **A CLAIM ON A LOGIN PAGE IS A PRODUCT SURFACE LIKE ANY OTHER, AND THE RENDER FLOOR APPLIES TO
// > IT: do not state more than the system can support.** The same test this epic applied to our own
// > "world's first" headline, applied to a badge the design supplied.

/**
 * ⛔ THE DESIGN'S STAT BLOCK IS TWO LINES, NOT ONE. "WireGuard®" over "kernel-fast tunnels" — a
 * headline and a qualifier. The first build flattened it to a bulleted string, which is why it read
 * as a feature list rather than as the design's three columns.
 */
export type TrustBadge = {
  headline: string;
  detail: string;
  text: string;
  why: string;
};

/**
 * What the hero may claim. Each entry carries the reason it is TRUE, so a future edit has to
 * defeat an argument rather than delete a string.
 */
export const TRUST_BADGES: readonly TrustBadge[] = [
  {
    headline: "WireGuard®",
    detail: "kernel-fast tunnels",
    text: "WireGuard® kernel tunnels",
    why: "the data plane is wgctrl driving the kernel module; apps/node owns it directly",
  },
  {
    headline: "SSO",
    detail: "Microsoft Entra",
    text: "SSO with Microsoft Entra",
    why: "getSsoConfig/setSsoConfig ship and Entra is the implemented provider; Google is refused at config time by supportedProvider",
  },
  {
    headline: "Zero Trust",
    detail: "default-deny policy",
    text: "Zero Trust by default",
    why: "default-deny policy model with a pure, deterministic compiler (policyspec.Compiled)",
  },
] as const;

/**
 * ⛔ CLAIMS THAT MUST NOT APPEAR. Pinned as data so the assertion is about the RENDERED SET rather
 * than about one string someone might re-add in a different casing.
 */
export const FORBIDDEN_CLAIMS: readonly string[] = [
  "SOC 2",
  "SOC2",
  "SCIM",
  "ISO 27001",
  "HIPAA",
  "FedRAMP",
  "PCI",
] as const;

/** The mesh nodes, verbatim from the block — these are the six the design names. */
export const MESH_NODES: readonly string[] = [
  "AWS VPC",
  "Azure",
  "GCP",
  "On-prem",
  "Kubernetes",
  "Remote",
] as const;

export const HERO_HEADLINE = "Connect everything. Trust nothing.";
export const HERO_SUBHEAD =
  "Every cloud, VPC, site and device — joined into one encrypted mesh.";

/**
 * ⛔ THE GENERIC-202 NOTE, AND IT IS A SECURITY PROPERTY RATHER THAN REASSURANCE.
 *
 * Signup and reset answer the same 202 whether or not the address exists, so neither confirms nor
 * denies an account. Saying so on the page is what stops a user reading "check your email" as
 * evidence that the address was recognised — and it is the same no-oracle rule the 401s follow.
 */
export const GENERIC_202_NOTE =
  "Sign-up and password reset always answer the same way, whether or not an account exists — so neither confirms nor denies an address.";

/**
 * ⛔ THE RECOVERY-CODE COUNT IS CARDINALITY ONLY — and the server says so in the schema.
 *
 * `recovery_codes_remaining` (openapi.yaml:3572) is documented "CARDINALITY ONLY, never the codes
 * (nothing recoverable)". So the count is renderable and the codes never are. The warning tiers
 * come from the count alone.
 */
export function recoveryWarning(remaining: number): {
  text: string;
  loud: boolean;
} | null {
  if (remaining <= 0) {
    return {
      text: "No recovery codes left. If you lose your authenticator you will need an administrator to reset MFA.",
      loud: true,
    };
  }
  if (remaining === 1) {
    return {
      text: "1 recovery code left — this is the last one. Generate a new set after signing in.",
      loud: true,
    };
  }
  if (remaining <= 3) {
    return {
      text: `${remaining} recovery codes left. Generate a new set after signing in.`,
      loud: false,
    };
  }
  // Above the threshold the count is not news, and a warning that always shows is not a warning.
  return null;
}

/** The count line itself — always says the codes are not re-shown, because that surprises people. */
export function recoveryCountLabel(remaining: number): string {
  return `${remaining} recovery code${remaining === 1 ? "" : "s"} remaining — count only, codes are never re-shown.`;
}

// SSI-4 (finding F2) — what creating or extending a network links, said BEFORE it is applied.
//
// Approving a range on one site makes it reachable from every other site's ranges: site links are
// automatic. With Zero Trust enforcement off the gateways render the mesh, so that reach is every address,
// every port, both directions — and until now the wizard's only words on the subject were "existing access
// policies still apply", which is true and tells the operator nothing about what they are about to open.
//
// PURE projection. It can claim only what its inputs attest: an unread enforcement mode is "unknown",
// never guessed to be the safe one.

export type EnforcementMode = "off" | "enforcing" | "unknown";

export interface OtherNetwork {
  name: string;
  /** APPROVED ranges only: a pending range is routed nowhere. */
  ranges: string[];
}

export interface SiteLinkExposure {
  /** open: the mesh forwards everything. rules: default-deny. unknown: the mode could not be read. */
  kind: "open" | "rules" | "unknown";
  networks: OtherNetwork[];
  heading: string;
  body: string;
  /** The operator must tick this before the network is created. null when nothing opens. */
  acknowledgement: string | null;
}

/**
 * siteLinkExposure returns null when creating the range links nothing: no other network has an approved
 * range, so there is no second side. Otherwise it names the other networks and says what crosses the link.
 */
export function siteLinkExposure(input: {
  mode: EnforcementMode;
  newRange: string;
  others: OtherNetwork[];
}): SiteLinkExposure | null {
  const networks = input.others
    .map((n) => ({ name: n.name, ranges: [...n.ranges].sort() }))
    .filter((n) => n.ranges.length > 0)
    .sort((a, b) => a.name.localeCompare(b.name));
  if (networks.length === 0) return null;
  const range = input.newRange.trim() || "this range";
  const count = networks.length === 1 ? "1 other network" : `${networks.length} other networks`;
  if (input.mode === "enforcing") {
    return {
      kind: "rules",
      networks,
      heading: `This links ${range} to ${count}`,
      body: "Zero Trust enforcement is on, so nothing crosses the link until an access rule allows it.",
      acknowledgement: null,
    };
  }
  if (input.mode === "off") {
    return {
      kind: "open",
      networks,
      heading: `This opens ${range} to ${count}`,
      body:
        "Zero Trust enforcement is off, so every address in these networks can reach every address in " +
        `${range}, and the reverse, on every port. Access rules do not narrow it until enforcement is on.`,
      acknowledgement: "I understand this link is open in both directions",
    };
  }
  return {
    kind: "unknown",
    networks,
    heading: `This links ${range} to ${count}`,
    body:
      "The enforcement mode could not be read. If enforcement is off, every address in these networks can " +
      `reach every address in ${range}, and the reverse, on every port.`,
    acknowledgement: "I understand this link may be open in both directions",
  };
}

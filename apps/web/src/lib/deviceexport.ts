// deviceexport: the pure view-model for the device-export ceremony (S9.1 4b-wiring WEB). Kept
// electron-free + side-effect-free so it unit-tests without a DOM.

export type ExportKind = "wireguard" | "openvpn";

export interface ExportCeremony {
  title: string;
  ext: "conf" | "ovpn";
  // showQR is TRUE only for WireGuard: official WG apps import a QR natively, but OpenVPN Connect /
  // Tunnelblick import .ovpn FILES (no native QR import) — so a QR is a WireGuard-only affordance
  // (Part-4 caveat: never offer QR for OpenVPN).
  showQR: boolean;
  // honesty is the site-routes staleness line, shown at issuance (the one-time-secret discipline):
  // a static profile's baked routes go stale silently when a subnet is added later.
  honesty: string;
}

export function exportCeremony(kind: ExportKind): ExportCeremony {
  const wg = kind !== "openvpn";
  return {
    title: wg
      ? "Your configuration — shown once"
      : "Your OpenVPN profile — shown once",
    ext: wg ? "conf" : "ovpn",
    showQR: wg,
    honesty: wg
      ? "This profile includes your current site routes and DNS. Add a subnet later? Re-export and re-import on the device."
      : // WF-OVPN-9: the .ovpn lists the current gateway(s) at export time and fails over between them
        // automatically. If the gateway set changes later, re-export to pick up the new list.
        "This profile includes your current site routes, DNS, and gateway list (with automatic failover). Change a subnet or your gateways later? Re-export and re-import on the device.",
  };
}

// shouldRenderQR gates the QR on BOTH the kind AND the secret being present. When the one-time modal
// is dismissed the caller clears the secret (null), so the QR stops rendering — it is NEVER
// re-rendered after close (the secret it encodes lives only in caller state and is never re-fetched).
// A re-viewable QR would break the D2 one-time-secret discipline.
export function shouldRenderQR(
  kind: ExportKind,
  secret: string | null,
): boolean {
  return kind === "wireguard" && secret != null && secret !== "";
}

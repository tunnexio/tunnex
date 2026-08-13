import { describe, it, expect } from "vitest";
import { exportCeremony, shouldRenderQR } from "../src/lib/deviceexport";

describe("device export ceremony (S9.1 4b-wiring)", () => {
  it("WireGuard offers a QR + a .conf and states the honesty line", () => {
    const c = exportCeremony("wireguard");
    expect(c.ext).toBe("conf");
    expect(c.showQR).toBe(true);
    expect(c.honesty).toContain("site routes");
    expect(c.honesty).toContain("Re-export");
  });

  it("OpenVPN offers NO QR (Part-4: OpenVPN Connect has no native QR import) + a .ovpn", () => {
    const c = exportCeremony("openvpn");
    expect(c.ext).toBe("ovpn");
    expect(c.showQR).toBe(false); // never a QR for OpenVPN
    expect(c.honesty).toContain("site routes");
  });

  it("the QR renders ONLY while the secret is present — never after the modal closes (no re-view, D2)", () => {
    expect(shouldRenderQR("wireguard", "the-config")).toBe(true);
    expect(shouldRenderQR("wireguard", null)).toBe(false); // dismissed -> secret cleared -> no QR
    expect(shouldRenderQR("wireguard", "")).toBe(false);
    expect(shouldRenderQR("openvpn", "the-profile")).toBe(false); // OpenVPN never renders a QR
  });
});

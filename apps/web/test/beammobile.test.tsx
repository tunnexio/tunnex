import { afterEach, describe, expect, it } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { BeamShareMobile, beamMobileURL } from "../src/components/BeamShareMobile";
import type { BeamShare } from "../src/lib/beam";

afterEach(cleanup);
const share = { id: "test", name: "Checkout", hostname: "p-preview.example.net", url: "https://p-preview.example.net/", state: "active", connectivity: "online", can_open: true, expires_at: "2099-01-01T00:00:00Z" } as BeamShare;
describe("Beam mobile review", () => {
  it("shares the canonical public URL and withdraws an open QR when access is lost", () => {
    const view = render(<BeamShareMobile share={share} />);
    fireEvent.click(screen.getByRole("button", { name: "Open on phone" }));
    expect(screen.getByText(share.url)).toBeTruthy();
    expect(screen.getByTitle("Preview link for Checkout")).toBeTruthy();
    expect(screen.getByText(/Sign in on your phone/)).toBeTruthy();
    view.rerender(<BeamShareMobile share={{ ...share, can_open: false }} />);
    expect(screen.queryByRole("dialog")).toBeNull();
    expect(screen.queryByRole("button", { name: "Open on phone" })).toBeNull();
  });
  it.each(["https://wrong.example.net/", "http://p-preview.example.net/", "https://p-preview.example.net/_beam/redeem?code=secret", "https://p-preview.example.net/?token=secret", "https://p-preview.example.net/#secret"])("refuses handoff or noncanonical URL %s", url => {
    expect(beamMobileURL({ ...share, url })).toBeNull();
  });
  it.each(["paused", "stopped", "expired", "revoked"] as const)("does not advertise %s shares", state => {
    expect(beamMobileURL({ ...share, state })).toBeNull();
  });
  it("does not advertise expired or offline previews", () => {
    expect(beamMobileURL(share, Date.parse(share.expires_at))).toBeNull();
    expect(beamMobileURL({ ...share, connectivity: "offline" })).toBeNull();
  });
});

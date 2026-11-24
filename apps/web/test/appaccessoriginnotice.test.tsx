import { afterEach, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { OriginRangeNotice } from "../src/components/AppAccessOriginNotice";
afterEach(cleanup);

it("warns before saving that the gateway will refuse a private origin outside the ranges (AA-1)", () => {
  const allow = vi.fn();
  render(<OriginRangeNotice originUrl="http://10.70.0.9:8080" allowed={["10.80.0.0/16"]} gatewayName="onprem-gw-a" onAllow={allow} />);
  expect(screen.getByText(/The gateway onprem-gw-a will refuse 10\.70\.0\.9/)).toBeTruthy();
  fireEvent.click(screen.getByRole("button", { name: "Allow 10.70.0.9/32" }));
  expect(allow).toHaveBeenCalledWith("10.70.0.9/32");
});
it("says nothing when the range already covers the origin", () => {
  const { container } = render(<OriginRangeNotice originUrl="http://10.70.0.9:8080" allowed={["10.70.0.0/16"]} gatewayName="gw" />);
  expect(container.textContent).toBe("");
});
it("explains that a hostname is resolved by the gateway when it connects", () => {
  render(<OriginRangeNotice originUrl="https://wiki.internal" allowed={[]} gatewayName="gw" />);
  expect(screen.getByText(/The gateway gw resolves wiki\.internal when it connects/)).toBeTruthy();
});

it("has words for every App Access event reason, never the code (AA-6)", async () => {
  const { eventReasonText } = await import("../src/pages/AppAccessEvents");
  const reasons = ["none","session_invalid","parent_unavailable","user_inactive","membership_unavailable","no_use_permission","no_active_grant","feature_disabled","feature_unavailable","publication_unavailable","installation_changed","session_revoked","lease_expired","connection_closed","self","admin","recovery","infrastructure_unavailable","dropped_events"];
  for (const reason of reasons) {
    expect(eventReasonText[reason], reason).toBeTruthy();
    expect(eventReasonText[reason]).not.toMatch(/_/);
  }
});

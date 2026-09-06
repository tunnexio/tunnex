import { afterEach, it, expect, vi } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { SsoSelfLink } from "../src/components/SsoSelfLink";
vi.mock("../src/lib/api", () => ({
  api: { GET: vi.fn().mockResolvedValue({ data: { items: [] } }) },
  apiErrorMessage: () => "Failed",
}));
afterEach(() => {
  cleanup();
  window.history.replaceState({}, "", "/");
});
it("shows callback failure when the connection was disabled during self-link", async () => {
  window.history.replaceState(
    {},
    "",
    "/settings?section=authentication&sso_org=org&sso_test=sso_test_stale",
  );
  render(<SsoSelfLink orgId="org" />);
  expect((await screen.findByRole("status")).textContent).toContain(
    "changed during the test",
  );
});

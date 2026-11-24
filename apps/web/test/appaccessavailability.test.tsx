import { afterEach, expect, it, vi } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
const auth = vi.hoisted(() => ({ cpAdmin: false }));
vi.mock("../src/lib/auth", () => ({ useOptionalAuth: () => ({ state: { status: "authed", user: { cp_admin: auth.cpAdmin } } }) }));
import { AppAccessAvailabilityNotice } from "../src/components/AppAccessAvailabilityNotice";
afterEach(() => { cleanup(); auth.cpAdmin = false; });

it("links server administrators to Application domains when setup is incomplete (AA-5)", () => {
  auth.cpAdmin = true;
  render(<MemoryRouter><AppAccessAvailabilityNotice availability="domain_unavailable" /></MemoryRouter>);
  expect(screen.getByRole("link", { name: "Open Application domains" }).getAttribute("href")).toBe("/settings?section=app-access-domains");
});
it("tells everyone else whom to ask, without a link", () => {
  render(<MemoryRouter><AppAccessAvailabilityNotice availability="domain_unavailable" /></MemoryRouter>);
  expect(screen.getByText(/Ask a server administrator/)).toBeTruthy();
  expect(screen.queryByRole("link")).toBeNull();
  cleanup();
  render(<MemoryRouter><AppAccessAvailabilityNotice availability="feature_disabled" /></MemoryRouter>);
  expect(screen.getByText(/An organization administrator can turn it on in Settings → Features/)).toBeTruthy();
});

import { afterEach, expect, it } from "vitest";
import { cleanup, render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { personLabel } from "../src/lib/personLabel";
import { ServerAccountGrants } from "../src/components/ServerAccountGrants";
afterEach(cleanup);

it("names a person as name and email, or email alone (SA-UX-2 item 10)", () => {
  expect(personLabel({ name: "Control Plane Admin", email: "support@tunnex.io" })).toBe("Control Plane Admin (support@tunnex.io)");
  expect(personLabel({ name: "", email: "support@tunnex.io" })).toBe("support@tunnex.io");
  expect(personLabel({ name: "support@tunnex.io", email: "support@tunnex.io" })).toBe("support@tunnex.io");
  expect(personLabel(undefined, "user-9")).toBe("user-9");
});

it("the grant list uses the same label as the picker", () => {
  const future = new Date(Date.now() + 3600000).toISOString(), past = new Date(Date.now() - 60000).toISOString();
  render(<MemoryRouter><ServerAccountGrants grants={[{ id: "g", server_id: "s", account: "ubuntu", user_id: "u", starts_at: past, expires_at: future, enabled: true } as never]} servers={[{ id: "s", name: "Host", accounts: ["ubuntu"] } as never]} members={[{ user_id: "u", name: "Control Plane Admin", email: "support@tunnex.io" } as never]} groups={[]} disabled={false} onRevoke={() => {}} onRenew={async () => {}} /></MemoryRouter>);
  expect(screen.getByText("Control Plane Admin (support@tunnex.io)")).toBeTruthy();
});

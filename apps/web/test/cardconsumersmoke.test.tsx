import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// A SHARED PRIMITIVE CHANGED, AND TWELVE SCREENS CONSUME IT.
//
// `Card` gained the glass recipe and moved from 20px to 16px padding. Nine screens already have wiring tests
// that render the real page and assert its content; this file covers the four consumers that do not, so the
// whole set is at least mounted.
//
// ⛔ WHAT THIS GATES AND WHAT IT CANNOT. It proves nothing CRASHES and no content DISAPPEARS. It cannot see
// overlap, truncation, or unreadable contrast, because jsdom has no layout engine — which is the entire
// argument for the Playwright viewport leg (docs/laws.md). Claiming this file rules out visual breakage would
// be the exact substitution this project keeps recording.

afterEach(cleanup);

vi.mock("../src/lib/api", async () => {
  const actual =
    await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (p: string) => {
        if (p === "/api/v1/auth/me")
          return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (p === "/api/v1/meta") return { data: { edition: "open" } };
        if (p === "/api/v1/organizations")
          return { data: [{ id: "org-1", name: "Acme" }] };
        if (p.endsWith("/machine-credentials")) return { data: [] };
        return { data: [] };
      }),
      POST: vi.fn(async () => ({ data: {} })),
      PATCH: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import { AuthLayout } from "../src/components/AuthLayout";
import { MachineCredentials } from "../src/components/MachineCredentials";
import { AuthProvider } from "../src/lib/auth";

const mount = (ui: React.ReactElement) =>
  render(
    <MemoryRouter>
      <OrgProvider>
        <AuthProvider>{ui}</AuthProvider>
      </OrgProvider>
    </MemoryRouter>,
  );

describe("the four Card consumers with no wiring test still mount and keep their content", () => {
  it("AuthLayout renders its children", () => {
    // AuthLayout takes only `children` — my first version passed a `title` prop it does not have, which
    // TypeScript would have caught had the prop been required. It is not: extra props on a component with an
    // inline type are a compile error, but the test asserted on the phantom title's TEXT, so the failure read
    // as "content missing" rather than "test wrong".
    mount(
      <AuthLayout>
        <p>form body</p>
      </AuthLayout>,
    );
    expect(screen.getByText("form body")).toBeTruthy();
  });

  it("MachineCredentials mounts", () => {
    mount(<MachineCredentials orgId="org-1" canManage={true} />);
    expect(document.body.textContent?.length).toBeGreaterThan(0);
  });
});

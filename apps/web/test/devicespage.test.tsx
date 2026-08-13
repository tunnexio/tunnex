import { afterEach, describe, expect, it, vi, beforeEach } from "vitest";
import {
  render,
  screen,
  fireEvent,
  waitFor,
  cleanup,
} from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// THE FIRST COMPONENT TEST IN THIS REPO, and it exists for a gap the pure tier cannot close.
//
// Slice 3 extracted `defaultDeviceNode` into src/lib, which made the RULE testable. But a pure test of the rule
// passes just as happily while the page still reads `nodes[0]` — nothing asserted that the component uses the fix.
// That is the vacuous-check trap one tier up (docs/laws.md, COULD THIS CHECK HAVE FAILED?): the guard tests the
// extracted decision, not the decision the user actually gets.
//
// So this asserts the WIRING: given a fleet whose oldest gateway is revoked — the EPIC 11 walk's exact fleet
// state, where `aws-gw-1` was revoked and had the earliest created_at and therefore WAS nodes[0] — the POST that
// creates a device must carry the ACTIVE gateway's id.
//
// Scope is deliberately Slice 3's surfaces. This is the foothold for the registered component-test-tier ledger
// item, not a retroactive suite for the whole app.

const posts: Array<{ path: string; body: Record<string, unknown> }> = [];
// ⚠ A failure switch: the mock had no way to make a create FAIL, so no test could reach the error path —
// which is exactly the path the founder hit and found rendering behind the dialog.
let createFails = false;

vi.mock("../src/lib/api", () => ({
  apiErrorMessage: (_e: unknown, fallback: string) => fallback,
  api: {
    GET: vi.fn(async (path: string) => {
      if (path === "/api/v1/organizations")
        return { data: [{ id: "org-1", name: "Acme" }] };
      if (path.endsWith("/nodes")) {
        return {
          data: [
            // REVOKED and FIRST — ListNodes orders by created_at, so this is what `nodes[0]` used to select.
            {
              id: "revoked-oldest",
              name: "aws-gw-1",
              status: "revoked",
              agent_version: "0.1.0",
            },
            {
              id: "live-gateway",
              name: "aws-gw-2",
              status: "active",
              agent_version: "0.1.0",
            },
          ],
        };
      }
      return { data: [] };
    }),
    POST: vi.fn(
      async (path: string, opts: { body: Record<string, unknown> }) => {
        posts.push({ path, body: opts.body });
        if (createFails) return { error: { error: { message: "refused" } } };
        return { data: { device: { status: "active" }, config: "wg-conf" } };
      },
    ),
  },
}));

// qrcode.react pulls a canvas-ish dependency chain that jsdom does not need for this assertion.
vi.mock("qrcode.react", () => ({ QRCodeSVG: () => null }));

import { OrgProvider } from "../src/lib/useOrg";
import Devices from "../src/pages/Devices";
import { deviceModeLabel } from "../src/pages/Devices";

describe("device mode rendering", () => {
  it("labels the API's full_tunnel flag without inventing a third state", () => {
    expect(deviceModeLabel(true)).toBe("Full tunnel");
    expect(deviceModeLabel(false)).toBe("Split tunnel");
    expect(deviceModeLabel(undefined)).toBe("Split tunnel");
  });
});

// ⚠ NO CLEANUP EXISTED IN THIS FILE. That was survivable while every test rendered once; the moment two
// do, the first render's DOM is still mounted and "Add device" matches twice — a strict-mode violation that
// looks like a component bug and is a harness one. At module scope so it covers the older tests too.
afterEach(cleanup);

describe("device creation homes on an ACTIVE gateway (S13.1 Slice 3 — the wiring)", () => {
  beforeEach(() => {
    posts.length = 0;
  });

  it("posts the active gateway's id even when a revoked gateway sorts first", async () => {
    // ⛔ WRAPPED AT THE EPIC 14 MERGE, NOT BECAUSE THE FIX CHANGED. The rewritten Devices page renders
    // a <Link>, which throws without a Router context — so this test began failing on the merge for a
    // reason that has nothing to do with what it asserts. The assertion below is untouched.
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );

    // Wait for the fleet to load, then create a device through the real form.
    // ⚠ The create form is a MODAL now (matching Add rule), so it has to be opened before its fields
    // exist. The subject of this test is unchanged: which gateway id the POST carries.
    fireEvent.click(await screen.findByRole("button", { name: "Add device" }));
    const nameInput = await waitFor(() =>
      screen.getByPlaceholderText("my-laptop"),
    );
    fireEvent.change(nameInput, { target: { value: "test-laptop" } });
    fireEvent.click(screen.getByRole("button", { name: /create device/i }));

    await waitFor(() => expect(posts.length).toBeGreaterThan(0));
    const created = posts.find((p) => p.path.endsWith("/devices"));
    expect(created, "a device POST must have been issued").toBeTruthy();
    expect(
      created!.body.node_id,
      "the device must be homed on the ACTIVE gateway; homing it on the revoked one issues a one-time config " +
        "that can never connect, and a one-time secret cannot be re-issued",
    ).toBe("live-gateway");
  });
});

/**
 * ⛔ THE CREATE FORM IS A MODAL, AND THE ROSTER OWNS THE TOP OF THE PAGE.
 *
 * Inline, it was a permanently-open four-control card between the title and the list — and the list is what
 * this screen is FOR. A trigger costs one click on the rare visit that creates a device, and gives the
 * roster the top of the page on every other one.
 */
describe("Devices — creation is a dialog, not a permanent form", () => {
  const open = async () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    const btn = await screen.findByRole("button", { name: "Add device" });
    fireEvent.click(btn);
  };
  it("⛔ THE FORM IS ABSENT UNTIL ASKED FOR", async () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    const trigger = await screen.findByRole("button", { name: "Add device" });
    // Nothing of the form is on the page…
    expect(screen.queryByPlaceholderText("my-laptop")).toBeNull();
    expect(screen.queryByRole("button", { name: /create device/i })).toBeNull();
    // …until the trigger is used.
    fireEvent.click(trigger);
    expect(screen.getByPlaceholderText("my-laptop")).toBeTruthy();
    expect(screen.getByRole("button", { name: /create device/i })).toBeTruthy();
  });

  it("⚠ AND EXACTLY ONE SUBMIT — moving a control must not leave a copy behind", async () => {
    // The first attempt kept the form's own button AND added one to the modal's action row, so two controls
    // claimed the same verb. Playwright and testing-library both call that ambiguous; an operator would too.
    await open();
    expect(
      screen.getAllByRole("button", {
        name: /create device|export openvpn profile/i,
      }),
    ).toHaveLength(1);
  });

  it("⛔ THE MIGRATION BANNER IS GONE — a first-time reader is not owed a note about where something USED to be", () => {
    render(
      <MemoryRouter>
        <OrgProvider>
          <Devices />
        </OrgProvider>
      </MemoryRouter>,
    );
    expect(
      screen.queryByText(/Gateways moved to their own screen/i),
    ).toBeNull();
  });
});

/**
 * ⛔ A DIALOG'S REFUSAL BELONGS IN THE DIALOG.
 *
 * Ticking "Full tunnel" on a gateway that cannot route it returns
 * `this gateway can't route full-tunnel internet traffic yet; use split tunnel`. That message was written to
 * the PAGE-level error and rendered BEHIND the open modal — the founder saw a dialog that had visibly done
 * nothing, with the explanation on the obscured page underneath it.
 */
describe("Devices — a create failure is readable where it happened", () => {
  it("⛔ THE ERROR RENDERS INSIDE THE DIALOG, AND THE DIALOG STAYS OPEN", async () => {
    createFails = true;
    try {
      render(
        <MemoryRouter>
          <OrgProvider>
            <Devices />
          </OrgProvider>
        </MemoryRouter>,
      );
      fireEvent.click(
        await screen.findByRole("button", { name: "Add device" }),
      );
      fireEvent.change(screen.getByPlaceholderText("my-laptop"), {
        target: { value: "x" },
      });
      fireEvent.click(
        screen.getByRole("button", {
          name: /create device|export openvpn profile/i,
        }),
      );

      // ⚠ The mock's apiErrorMessage returns the FALLBACK, so this asserts the string the component renders.
      // The claim is unchanged: the refusal is readable without dismissing the thing that caused it.
      const msg = await screen.findByText(/Could not create the device/i);
      expect(msg).toBeTruthy();
      // ⛔ And the dialog is STILL OPEN with the typed name intact: dismissing on error would discard the
      // operator's input and hide the message explaining why.
      expect(
        (screen.getByPlaceholderText("my-laptop") as HTMLInputElement).value,
      ).toBe("x");
    } finally {
      createFails = false; // a module-level switch left set would fail every later test in this file
    }
  });
});

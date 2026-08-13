import { afterEach, describe, expect, it, vi } from "vitest";
import { fireEvent, render, screen, cleanup } from "@testing-library/react";
import { OneTimeSecretModal } from "../src/components/OneTimeSecret";

// ⛔ THE THREE DISMISSAL RULES, ASSERTED RATHER THAN ASSUMED.
//
// The wireframe's forced-enrollment ceremony specifies: *"Modal cannot be dismissed by click-away
// or Esc — only by the 'I've saved them' checkbox + button."*
//
// Two of the three were already true BY ABSENCE — there is no backdrop onClick and no key handler.
// **Absence is not a guarantee.** Nothing stopped a later edit adding either, and nothing tested
// it, so the property was true by accident rather than by decision. These tests convert it.
//
// Recovery codes are shown ONCE. A dismiss that takes one stray click is the difference between a
// user who has their codes and a user who needs an administrator.
// ⛔ EXPLICIT CLEANUP. This project has no `setupFiles` and no `globals: true`, so Testing
// Library's auto-cleanup NEVER REGISTERS — every render accumulates in the document. My first
// version called cleanup() at the END of each test, which does not run when the test fails, so one
// failure cascaded into "found multiple elements" on the next two. afterEach always runs.
afterEach(cleanup);

/** No jest-dom in this project, so `disabled` is read off the element rather than matched. */
function isDisabled(el: HTMLElement): boolean {
  return (el as HTMLButtonElement).disabled === true;
}

function open(onDismiss = vi.fn(), requireAck?: string) {
  render(
    <OneTimeSecretModal
      title="Save your recovery codes"
      caption="Shown once."
      secret={"AAAA-BBBB\nCCCC-DDDD"}
      onDismiss={onDismiss}
      requireAck={requireAck}
    />,
  );
  return onDismiss;
}

describe("OneTimeSecretModal — dismissal", () => {
  it("⛔ CLICK-AWAY on the backdrop does NOT dismiss", () => {
    const onDismiss = open();
    // The backdrop is the fixed overlay; clicking it must do nothing.
    const backdrop = document.querySelector(".fixed.inset-0") as HTMLElement;
    expect(backdrop).toBeTruthy();
    fireEvent.click(backdrop);
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("⛔ ESCAPE does NOT dismiss", () => {
    const onDismiss = open();
    fireEvent.keyDown(document, { key: "Escape", code: "Escape" });
    fireEvent.keyUp(document, { key: "Escape", code: "Escape" });
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("⛔ with requireAck, the button is DISABLED until the box is ticked", () => {
    const onDismiss = open(vi.fn(), "I have saved my recovery codes.");
    const btn = screen.getByRole("button", { name: /saved it/i });
    expect(isDisabled(btn)).toBe(true);
    // Clicking a disabled button must not dismiss either — belt and braces, because "disabled"
    // is a rendering and the handler is the behaviour.
    fireEvent.click(btn);
    expect(onDismiss).not.toHaveBeenCalled();
  });

  it("ticking the box enables it, and THEN the button dismisses", () => {
    // The positive arm: a gate that never opens is not a gate, it is a broken modal.
    const onDismiss = open(vi.fn(), "I have saved my recovery codes.");
    fireEvent.click(screen.getByTestId("ots-ack"));
    const btn = screen.getByRole("button", { name: /saved it/i });
    expect(isDisabled(btn)).toBe(false);
    fireEvent.click(btn);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });

  it("without requireAck the existing callers are unchanged — button live immediately", () => {
    // The opt-in must not silently gate every other one-time secret in the product.
    const onDismiss = open();
    const btn = screen.getByRole("button", { name: /saved it/i });
    expect(isDisabled(btn)).toBe(false);
    fireEvent.click(btn);
    expect(onDismiss).toHaveBeenCalledTimes(1);
  });
});

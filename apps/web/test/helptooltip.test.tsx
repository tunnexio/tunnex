import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { afterEach, expect, it } from "vitest";
import { HelpTooltip } from "../src/components/HelpTooltip";
afterEach(cleanup);
it("keeps help optional and supports keyboard focus, Escape and blur", () => {
  render(<HelpTooltip label="About access">Access applies to new requests.</HelpTooltip>);
  const trigger = screen.getByRole("button", { name: "About access" });
  expect(screen.queryByRole("tooltip")).toBeNull();
  fireEvent.focus(trigger);
  expect(trigger.getAttribute("aria-describedby")).toBe(screen.getByRole("tooltip").id);
  fireEvent.keyDown(trigger, { key: "Escape" });
  expect(screen.queryByRole("tooltip")).toBeNull();
  fireEvent.click(trigger);
  expect(screen.getByRole("tooltip").textContent).toContain("new requests");
  fireEvent.blur(trigger);
  expect(screen.queryByRole("tooltip")).toBeNull();
});

import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import {
  PageHeader,
  Section,
  SettingRow,
  Switch,
} from "../src/components/ui";

afterEach(cleanup);

describe("Section", () => {
  // A group heading that is only visually a heading is invisible to anyone navigating by landmark —
  // which is the failure the settings page had at scale: 15 boxes, no announced structure.
  it("is a region named by its own heading", () => {
    render(
      <Section title="Authentication" description="How people sign in.">
        <p>body</p>
      </Section>,
    );
    const region = screen.getByRole("region", { name: "Authentication" });
    expect(region.tagName).toBe("SECTION");
    expect(screen.getByRole("heading", { name: "Authentication" })).toBeTruthy();
    expect(screen.getByText("How people sign in.")).toBeTruthy();
  });

  it("omits the description entirely when not given one", () => {
    const { container } = render(
      <Section title="Network">
        <p>body</p>
      </Section>,
    );
    expect(container.querySelectorAll("p")).toHaveLength(1); // the body only
  });
});

describe("SettingRow", () => {
  // ⛔ THE POINT OF THE ROW. The control must be announced as "OpenVPN", not "switch" — the row owns the
  // only text that says WHAT is being toggled, so it has to lend it.
  it("lends its label to the control as an accessible name", () => {
    render(
      <SettingRow label="OpenVPN" description="Off by default.">
        <Switch checked={false} onChange={() => {}} />
      </SettingRow>,
    );
    expect(screen.getByRole("switch", { name: "OpenVPN" })).toBeTruthy();
  });

  it("does not overwrite a control that already names itself", () => {
    render(
      <SettingRow label="Row label">
        <Switch checked={false} onChange={() => {}} label="Its own name" />
      </SettingRow>,
    );
    expect(screen.getByRole("switch", { name: "Its own name" })).toBeTruthy();
    expect(screen.queryByRole("switch", { name: "Row label" })).toBeNull();
  });

  it("carries non-element children through untouched", () => {
    render(<SettingRow label="Plain">just text</SettingRow>);
    expect(screen.getByText("just text")).toBeTruthy();
  });
});

describe("Switch", () => {
  it("reports its state as a switch, not a checkbox or a button", () => {
    render(<Switch checked onChange={() => {}} label="MFA" />);
    const el = screen.getByRole("switch", { name: "MFA" });
    expect(el.getAttribute("aria-checked")).toBe("true");
    // A bare <button> inside a <form> submits it. Every one of these lives in a settings form.
    expect(el.getAttribute("type")).toBe("button");
  });

  it("asks for the OPPOSITE of its current state", () => {
    const onChange = vi.fn();
    const { rerender } = render(
      <Switch checked={false} onChange={onChange} label="MFA" />,
    );
    fireEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenLastCalledWith(true);

    rerender(<Switch checked onChange={onChange} label="MFA" />);
    fireEvent.click(screen.getByRole("switch"));
    expect(onChange).toHaveBeenLastCalledWith(false);
  });

  // It is controlled: the parent owns the value. A switch that flipped itself would show "on" while the
  // request that would make it true was still in flight, or had failed.
  it("does not change its own state on click", () => {
    render(<Switch checked={false} onChange={() => {}} label="MFA" />);
    fireEvent.click(screen.getByRole("switch"));
    expect(screen.getByRole("switch").getAttribute("aria-checked")).toBe(
      "false",
    );
  });

  it("does not fire while disabled", () => {
    const onChange = vi.fn();
    render(<Switch checked={false} onChange={onChange} disabled label="MFA" />);
    fireEvent.click(screen.getByRole("switch"));
    expect(onChange).not.toHaveBeenCalled();
  });
});

describe("PageHeader", () => {
  it("renders the title as the page's h1", () => {
    render(<PageHeader title="Settings" subtitle="Demo Organization" />);
    const h1 = screen.getByRole("heading", { level: 1, name: "Settings" });
    expect(h1).toBeTruthy();
    expect(screen.getByText("Demo Organization")).toBeTruthy();
  });
});

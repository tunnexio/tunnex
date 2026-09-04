import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, fireEvent } from "@testing-library/react";
import { Link, MemoryRouter } from "react-router-dom";
import {
  Button,
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

  it("keeps a visible action name and associates the row as its description", () => {
    render(
      <SettingRow label="Run pruning now">
        <Button variant="ghost">Review manual prune</Button>
      </SettingRow>,
    );

    const action = screen.getByRole("button", { name: "Review manual prune" });
    const descriptionId = action.getAttribute("aria-describedby");
    expect(descriptionId).toBeTruthy();
    expect(document.getElementById(descriptionId ?? "")?.textContent).toBe(
      "Run pruning now",
    );
    expect(screen.queryByRole("button", { name: "Run pruning now" })).toBeNull();
  });

  it("keeps a direct Link's visible name and describes it with the row", () => {
    render(
      <MemoryRouter>
        <SettingRow label="Access-event evidence">
          <Link to="/access-events">View Access Events</Link>
        </SettingRow>
      </MemoryRouter>,
    );

    const link = screen.getByRole("link", { name: "View Access Events" });
    expect(link.getAttribute("href")).toBe("/access-events");
    expect(
      document.getElementById(link.getAttribute("aria-describedby") ?? "")
        ?.textContent,
    ).toBe("Access-event evidence");
  });

  it("does not replace the names of actions nested in a wrapper", () => {
    render(
      <SettingRow label="Access-event retention">
        <div data-testid="row-actions">
          <span>30 days</span>
          <Button variant="ghost">Edit policy</Button>
        </div>
      </SettingRow>,
    );

    expect(screen.getByRole("button", { name: "Edit policy" })).toBeTruthy();
    const wrapperLabelId = screen
      .getByTestId("row-actions")
      .getAttribute("aria-labelledby");
    expect(document.getElementById(wrapperLabelId ?? "")?.textContent).toBe(
      "Access-event retention",
    );
  });

  it("preserves an action's existing descriptions when adding the row", () => {
    render(
      <>
        <p id="request-warning">Deletes eligible evidence.</p>
        <SettingRow label="Run pruning now">
          <Button variant="ghost" aria-describedby="request-warning">
            Review manual prune
          </Button>
        </SettingRow>
      </>,
    );

    const action = screen.getByRole("button", { name: "Review manual prune" });
    const descriptionIds =
      action.getAttribute("aria-describedby")?.split(" ") ?? [];
    expect(descriptionIds).toContain("request-warning");
    expect(
      descriptionIds.some(
        (id) => document.getElementById(id)?.textContent === "Run pruning now",
      ),
    ).toBe(true);
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

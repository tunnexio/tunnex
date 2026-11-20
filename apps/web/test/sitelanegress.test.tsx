import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
const mock = vi.hoisted(() => ({ put: vi.fn() }));
vi.mock("../src/lib/api", () => ({
  api: { PUT: mock.put },
  apiErrorMessage: (error: { error?: { message?: string } } | undefined, fallback: string) => error?.error?.message ?? fallback,
}));
import { SiteLanEgress } from "../src/components/SiteLanEgress";
import { lanEgressOf, lanEgressOptions } from "../src/lib/sitesview";

afterEach(cleanup);
beforeEach(() => mock.put.mockReset());

// SSI-8: how a network's LAN sees traffic from other networks.
describe("SiteLanEgress", () => {
  const show = (current: "preserve_source" | "gateway_address", canManage = true, onSaved = vi.fn()) => {
    render(<SiteLanEgress orgId="org-a" siteId="site-1" current={current} canManage={canManage} onSaved={onSaved} />);
    return onSaved;
  };
  const radio = (name: RegExp) => screen.getByRole("radio", { name }) as HTMLInputElement;

  it("shows the applied mode and says what each choice means for the operator", () => {
    show("preserve_source");
    expect(radio(/Original address/).checked).toBe(true);
    expect(screen.getByText(/No cloud return route is needed/)).toBeTruthy();
    expect(screen.getByText(/Your cloud must route the other networks' ranges to this gateway/)).toBeTruthy();
    expect(screen.getByText(/Access rules match the remote machine's real address either way/)).toBeTruthy();
    // Nothing to save until the choice differs from what is applied.
    expect((screen.getByRole("button", { name: "Save" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("changes nothing on click and saves only on Save", async () => {
    mock.put.mockResolvedValue({ data: { lan_egress: "gateway_address" } });
    const onSaved = show("preserve_source");
    fireEvent.click(radio(/Gateway address/));
    expect(mock.put).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await waitFor(() => expect(onSaved).toHaveBeenCalledOnce());
    expect(mock.put).toHaveBeenCalledWith("/api/v1/organizations/{orgId}/sites/{siteId}/lan-egress", {
      params: { path: { orgId: "org-a", siteId: "site-1" } },
      body: { lan_egress: "gateway_address" },
    });
    expect(radio(/Gateway address · current/).checked).toBe(true);
  });

  it("keeps the applied mode marked and shows the server's reason on a refusal", async () => {
    mock.put.mockResolvedValue({ error: { error: { message: "gateway gw-old cannot translate site traffic yet; upgrade it before choosing the gateway address for this network" } } });
    const onSaved = show("preserve_source");
    fireEvent.click(radio(/Gateway address/));
    fireEvent.click(screen.getByRole("button", { name: "Save" }));
    await screen.findByText(/gateway gw-old cannot translate site traffic yet/);
    expect(onSaved).not.toHaveBeenCalled();
    // "current" still marks what the server last confirmed, not what was clicked.
    expect(screen.getByRole("radio", { name: /Original address · current/ })).toBeTruthy();
  });

  it("is read-only without site management access", () => {
    show("gateway_address", false);
    expect(radio(/Gateway address/).disabled).toBe(true);
    expect(screen.queryByRole("button", { name: "Save" })).toBeNull();
  });
});

describe("lanEgressOf", () => {
  it("reads an absent or unknown mode as preserve_source, the only value that cannot overstate", () => {
    expect(lanEgressOf({})).toBe("preserve_source");
    expect(lanEgressOf({ lan_egress: "something-new" })).toBe("preserve_source");
    expect(lanEgressOf({ lan_egress: "gateway_address" })).toBe("gateway_address");
    expect(lanEgressOptions.map((o) => o.value)).toEqual(["gateway_address", "preserve_source"]);
  });
});

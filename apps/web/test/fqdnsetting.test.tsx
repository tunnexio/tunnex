import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

let enabled = false;
let entitled = true;
let role: "admin" | "member" = "admin";
let impactError = "";
let impactToken = "impact-token-a";
let putError = "";

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string) => {
        if (path.endsWith("/setting/impact")) {
          return impactError
            ? { error: { error: { message: impactError } } }
            : {
                data: {
                  enabled,
                  entitlement_available: entitled,
                  enforcement_ready_rule_count: 1,
                  enforcement_ready_rule_ids: ["rule-a"],
                  rule_ids_truncated: false,
                  expected_impact_token: impactToken,
                },
              };
        }
        if (path.endsWith("/setting")) return { data: { enabled } };
        return { data: [] };
      }),
      PUT: vi.fn(async (_path: string, options: { body: { enabled: boolean } }) => {
        if (putError) return { error: { error: { message: putError } } };
        enabled = options.body.enabled;
        return { data: { enabled } };
      }),
    },
  };
});

import { FQDNEnforcementSetting } from "../src/components/FQDNEnforcementSetting";
import { api } from "../src/lib/api";

function panel() {
  return render(<FQDNEnforcementSetting orgId="org-a" role={role} />);
}

beforeEach(() => {
  enabled = false;
  entitled = true;
  role = "admin";
  impactError = "";
  impactToken = "impact-token-a";
  putError = "";
  vi.mocked(api.GET).mockClear();
  vi.mocked(api.PUT).mockClear();
});
afterEach(cleanup);

describe("organization FQDN enforcement setting", () => {
  it("loads disabled state, previews impact, and enables with the server token", async () => {
    panel();
    expect(await screen.findByText("DISABLED · NO FQDN TRAFFIC")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Review and enable" }));
    expect(await screen.findByText(/Server preview:/)).toBeTruthy();
    expect(screen.getByText("rule-a")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Enable FQDN enforcement" }));
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/fqdn-resources/setting",
      {
        params: { path: { orgId: "org-a" } },
        body: { enabled: true, expected_impact_token: "impact-token-a" },
      },
    ));
    expect(await screen.findByText("ENABLED")).toBeTruthy();
  });

  it("previews a disable and sends an explicit false setting", async () => {
    enabled = true;
    panel();
    expect(await screen.findByText("ENABLED")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Review and disable" }));
    expect(await screen.findByText(/will stop authorizing FQDN traffic/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Disable FQDN enforcement" }));
    await waitFor(() => expect(vi.mocked(api.PUT)).toHaveBeenCalledWith(
      "/api/v1/organizations/{orgId}/fqdn-resources/setting",
      {
        params: { path: { orgId: "org-a" } },
        body: { enabled: false, expected_impact_token: null },
      },
    ));
  });

  it("fails closed when the entitlement or impact preview is unavailable", async () => {
    entitled = false;
    panel();
    await screen.findByText("DISABLED · NO FQDN TRAFFIC");
    fireEvent.click(screen.getByRole("button", { name: "Review and enable" }));
    expect(await screen.findByText(/does not have the fqdn_resources licence entitlement/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Enable FQDN enforcement" }) as HTMLButtonElement).disabled).toBe(true);
    expect(vi.mocked(api.PUT)).not.toHaveBeenCalled();

    cleanup();
    entitled = true;
    impactError = "preview unavailable";
    panel();
    await screen.findByText("DISABLED · NO FQDN TRAFFIC");
    fireEvent.click(screen.getByRole("button", { name: "Review and enable" }));
    expect(await screen.findByText("preview unavailable")).toBeTruthy();
    expect(screen.getByRole("button", { name: "Retry preview" })).toBeTruthy();
  });

  it("requires a fresh preview after a stale-token mutation failure", async () => {
    putError = "the setting impact preview is missing or stale";
    panel();
    await screen.findByText("DISABLED · NO FQDN TRAFFIC");
    fireEvent.click(screen.getByRole("button", { name: "Review and enable" }));
    await screen.findByText(/Server preview:/);
    fireEvent.click(screen.getByRole("button", { name: "Enable FQDN enforcement" }));
    expect(await screen.findByText(/missing or stale/)).toBeTruthy();
    expect((screen.getByRole("button", { name: "Enable FQDN enforcement" }) as HTMLButtonElement).disabled).toBe(true);

    impactToken = "impact-token-b";
    putError = "";
    fireEvent.click(screen.getByRole("button", { name: "Retry preview" }));
    await waitFor(() => expect((screen.getByRole("button", { name: "Enable FQDN enforcement" }) as HTMLButtonElement).disabled).toBe(false));
    fireEvent.click(screen.getByRole("button", { name: "Enable FQDN enforcement" }));
    await waitFor(() => expect(vi.mocked(api.PUT).mock.calls.at(-1)?.[1]).toMatchObject({
      body: { enabled: true, expected_impact_token: "impact-token-b" },
    }));
  });

  it("shows the authoritative setting without mutation controls to read-only roles", async () => {
    role = "member";
    const rendered = panel();
    expect(rendered.container.childElementCount).toBe(0);
    expect(vi.mocked(api.GET)).not.toHaveBeenCalled();
  });
});

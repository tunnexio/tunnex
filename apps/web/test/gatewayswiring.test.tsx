import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

const mocks = vi.hoisted(() => {
  const admin = {
    allowed: true,
    configured: true,
    url: "https://gateway-control.example.com:8443",
    readError: false,
  };
  const meta = {
    gatewayControlURL: "https://gateway-control.example.com:8443",
    publicBaseURL: "https://cp.example.com",
  };
  return {
    admin,
    meta,
    apiGet: vi.fn(async (path: string) => {
      if (path === "/api/v1/meta") {
        return {
          data: {
            public_base_url: meta.publicBaseURL,
            gateway_control_url: meta.gatewayControlURL || undefined,
          },
        };
      }
      if (path === "/api/v1/admin/gateway-endpoint") {
        if (admin.readError) {
          return { error: { error: { code: "settings_unavailable" } } };
        }
        return admin.allowed
          ? { data: { configured: admin.configured, url: admin.url } }
          : { error: { error: { code: "gateway_endpoint_admin_required" } } };
      }
      return { data: undefined, error: undefined };
    }),
    apiPut: vi.fn(async (_path: string, request: { body: { url: string } }) => ({
      data: { configured: true, url: request.body.url },
    })),
    apiPost: vi.fn(async () => ({ data: { join_token: "one-time-token" } })),
  };
});

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      ...actual.api,
      GET: mocks.apiGet,
      PUT: mocks.apiPut,
      POST: mocks.apiPost,
    },
    apiErrorMessage: (_error: unknown, fallback: string) => fallback,
  };
});

import { Gateways } from "../src/components/Gateways";

afterEach(cleanup);
beforeEach(() => {
  vi.clearAllMocks();
  mocks.admin.allowed = true;
  mocks.admin.configured = true;
  mocks.admin.url = "https://gateway-control.example.com:8443";
  mocks.admin.readError = false;
  mocks.meta.gatewayControlURL = "https://gateway-control.example.com:8443";
  mocks.meta.publicBaseURL = "https://cp.example.com";
});

const org = { id: "org-1", name: "Acme" } as never;

describe("Gateway enrollment ceremony", () => {
  it("collapses a configured endpoint and reveals the editor only after authorized Change", async () => {
    render(<Gateways org={org} initiallyOpen hideHeader />);
    expect(
      await screen.findByText("gateway-control.example.com"),
    ).toBeTruthy();
    expect(screen.getByText("Configured")).toBeTruthy();
    expect(
      screen.queryByLabelText("Gateway control URL (DNS hostname)"),
    ).toBeNull();

    fireEvent.click(screen.getByRole("button", { name: "Change" }));
    expect(
      screen.getByDisplayValue("https://gateway-control.example.com:8443"),
    ).toBeTruthy();
    expect(screen.getByText(/raw mTLS endpoint/i)).toBeTruthy();
    expect(screen.getByText(/port 8443/i)).toBeTruthy();
    expect(screen.getByRole("button", { name: "Cancel" })).toBeTruthy();
  });

  it("first-time setup saves through the existing PUT and later commands use the saved authoritative URL", async () => {
    mocks.admin.configured = false;
    mocks.admin.url = "";
    mocks.meta.gatewayControlURL = "";
    render(<Gateways org={org} initiallyOpen hideHeader />);

    const controlURL = await screen.findByLabelText(
      "Gateway control URL (DNS hostname)",
    );
    expect(
      (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
    fireEvent.change(controlURL, {
      target: { value: "https://gateway-new.example.com:8443" },
    });
    fireEvent.click(screen.getByRole("button", { name: "Save endpoint" }));
    await waitFor(() => expect(mocks.apiPut).toHaveBeenCalledTimes(1));
    expect((mocks.apiPut.mock.calls[0] as unknown as [string])[0]).toBe(
      "/api/v1/admin/gateway-endpoint",
    );
    expect(
      (mocks.apiPut.mock.calls[0] as unknown as [string, { body: { url: string } }])[1]
        .body.url,
    ).toBe("https://gateway-new.example.com:8443");
    expect(
      await screen.findByText("gateway-new.example.com"),
    ).toBeTruthy();
    expect(screen.getByText("Configured")).toBeTruthy();

    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Generate join token" }));
    const command = await screen.findByText(/TUNNEX_JOIN_TOKEN=one-time-token/);
    expect(command.textContent).toContain(
      'TUNNEX_AGENT_URL="https://gateway-new.example.com:8443"',
    );
    expect(command.textContent).toContain(
      'TUNNEX_API_URL="https://cp.example.com"',
    );
  });

  it("a restricted user sees configured status without Change and can never issue the PUT", async () => {
    mocks.admin.allowed = false;
    render(<Gateways org={org} initiallyOpen hideHeader />);
    await waitFor(() =>
      expect(mocks.apiGet).toHaveBeenCalledWith(
        "/api/v1/admin/gateway-endpoint",
      ),
    );
    expect(
      screen.queryByLabelText("Gateway control URL (DNS hostname)"),
    ).toBeNull();
    expect(
      await screen.findByText("gateway-control.example.com"),
    ).toBeTruthy();
    expect(screen.getByText("Configured")).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Change" })).toBeNull();
    expect(screen.queryByRole("button", { name: "Save endpoint" })).toBeNull();
    expect(mocks.apiPut).not.toHaveBeenCalled();
    expect(
      (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
        .disabled,
    ).toBe(false);
  });

  it("blocks a restricted enrollment when no deployment endpoint is configured", async () => {
    mocks.admin.allowed = false;
    mocks.meta.gatewayControlURL = "";
    render(<Gateways org={org} initiallyOpen hideHeader />);

    expect(
      await screen.findByText(/A deployment admin must configure/i),
    ).toBeTruthy();
    expect(screen.queryByRole("button", { name: "Change" })).toBeNull();
    expect(
      (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
        .disabled,
    ).toBe(true);
    expect(mocks.apiPut).not.toHaveBeenCalled();
  });

  it("uses the configured metadata fallback when the endpoint read is unconfigured", async () => {
    mocks.admin.configured = false;
    mocks.admin.url = "";
    mocks.meta.gatewayControlURL = "";
    render(<Gateways org={org} initiallyOpen hideHeader />);

    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    expect(screen.getByText(/No explicit Gateway control URL is saved/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Generate join token" }));
    expect(await screen.findByText(/TUNNEX_JOIN_TOKEN=one-time-token/)).toBeTruthy();
    expect(screen.getByText(/TUNNEX_AGENT_URL="https:\/\/cp.example.com:8443"/)).toBeTruthy();
    expect(mocks.apiPut).not.toHaveBeenCalled();
  });

  it("keeps a metadata-configured command issuable when the admin endpoint read fails", async () => {
    mocks.admin.readError = true;
    render(<Gateways org={org} initiallyOpen hideHeader />);

    expect(await screen.findByText("Could not load the Gateway control endpoint.")).toBeTruthy();
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Generate join token" }));
    expect(await screen.findByText(/TUNNEX_JOIN_TOKEN=one-time-token/)).toBeTruthy();
    expect(screen.getByText(/TUNNEX_AGENT_URL="https:\/\/gateway-control.example.com:8443"/)).toBeTruthy();
    expect(mocks.apiPut).not.toHaveBeenCalled();
  });

  it("issues the one-time token only after submit and preserves one-time secrecy", async () => {
    const onEnrollmentAcknowledged = vi.fn();
    render(
      <Gateways
        org={org}
        initiallyOpen
        hideHeader
        onEnrollmentAcknowledged={onEnrollmentAcknowledged}
      />,
    );
    expect(mocks.apiPost).not.toHaveBeenCalled();
    fireEvent.change(screen.getByLabelText("Gateway name (optional)"), {
      target: { value: "edge-london" },
    });
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Generate join token" }));
    await waitFor(() => expect(mocks.apiPost).toHaveBeenCalledTimes(1));
    expect((mocks.apiPost.mock.calls[0] as unknown as [string])[0]).toContain(
      "/nodes/join-token",
    );
    expect(await screen.findByText("exactly once")).toBeTruthy();
    expect(screen.getByText(/TUNNEX_JOIN_TOKEN=one-time-token/)).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "I’ve saved it" }));
    expect(screen.queryByText(/TUNNEX_JOIN_TOKEN=one-time-token/)).toBeNull();
    expect(onEnrollmentAcknowledged).toHaveBeenCalledOnce();
  });

  it("surfaces a failed token issue instead of claiming a command exists", async () => {
    mocks.apiPost.mockResolvedValueOnce({
      error: { error: { code: "bootstrap_unavailable" } },
    } as never);
    render(<Gateways org={org} initiallyOpen hideHeader />);
    await waitFor(() =>
      expect(
        (screen.getByRole("button", { name: "Generate join token" }) as HTMLButtonElement)
          .disabled,
      ).toBe(false),
    );
    fireEvent.click(screen.getByRole("button", { name: "Generate join token" }));
    expect(await screen.findByText("Could not issue a join token.")).toBeTruthy();
    expect(screen.queryByText(/TUNNEX_JOIN_TOKEN=/)).toBeNull();
  });

  it("contains no hidden lifecycle mutation caller after S20 moved lifecycle to detail", () => {
    render(<Gateways org={org} initiallyOpen hideHeader />);
    expect(screen.queryByRole("button", { name: /revoke/i })).toBeNull();
    expect(screen.queryByRole("button", { name: /restore devices/i })).toBeNull();
  });
});

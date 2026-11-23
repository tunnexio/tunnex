import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

// K8N-3 stage 1 — a cluster's Kubernetes API on the Access page: the rule list, the rule builder and
// "Test access". Mocked at the network boundary; queried by role and name.

afterEach(cleanup);

const FQDN = "kubernetes.default.svc.prod.k8s.acme.com";
const NOTE = "Tunnex allows the connection. The cluster still decides what you may do: a 401 or 403 from kubectl is the cluster's answer, not Tunnex's.";
const API_ACCESS = "/api/v1/organizations/{orgId}/k8s/clusters/{clusterId}/api-access";

let rulesForTest: Array<Record<string, unknown>> = [];
let clustersFail = false;
let diagnostic: Record<string, unknown> = {};
let postedBodies: unknown[] = [];
let postError: { code: string; message: string } | null = null;
let apiAccessReads: string[] = [];

vi.mock("../src/lib/api", async () => {
  const actual = await vi.importActual<typeof import("../src/lib/api")>("../src/lib/api");
  return {
    ...actual,
    api: {
      GET: vi.fn(async (path: string, request?: { params?: { path?: { clusterId?: string } } }) => {
        if (path === "/api/v1/auth/me") return { data: { id: "u1", email: "a@b.c", email_verified: true } };
        if (path === "/api/v1/meta") return { data: { edition: "enterprise" } };
        if (path === "/api/v1/organizations") return { data: [{ id: "org-1", name: "Acme" }] };
        if (path.endsWith("/members")) return { data: [{ user_id: "u1", role: "admin", email: "a@b.c", name: "Ada", email_verified: true }] };
        if (path.endsWith("/zero-trust-mode")) return { data: { mode: "enforcing" } };
        if (path.endsWith("/policies")) return { data: rulesForTest };
        if (path.endsWith("/groups")) return { data: [{ id: "g1", name: "Engineering" }] };
        if (path.endsWith("/sites")) return { data: [{ id: "s1", name: "eu-lan" }] };
        if (path.endsWith("/agents")) return { data: [{ device_id: "agent-1", name: "build-bot", gateway_name: "gw-1" }] };
        if (path.endsWith("/k8s/services")) return { data: [{ id: "k1", cluster_id: "c-prod", name: "payments", namespace: "shop", protocol: "tcp", port_low: 8080, port_high: 8080, vip: "100.66.0.4", fqdn: "payments.shop.svc.prod.k8s.acme.com" }] };
        if (path.endsWith("/k8s/clusters")) {
          return clustersFail ? { error: { error: { message: "cluster inventory unavailable" } } } : { data: [{ id: "c-prod", name: "prod" }, { id: "c-staging", name: "staging" }] };
        }
        if (path === API_ACCESS) {
          const clusterId = request?.params?.path?.clusterId ?? "";
          apiAccessReads.push(clusterId);
          return clusterId === "c-prod"
            ? { data: { cluster_id: "c-prod", enabled: true, fqdn: FQDN, port: 443, vip: "100.66.0.9", rule_count: 1, ordinary_exposure: false, enabled_at: "2026-11-23T06:00:00Z" } }
            : { data: { cluster_id: clusterId, enabled: false, fqdn: "kubernetes.default.svc.staging.k8s.acme.com", port: 443, vip: null, rule_count: 1, ordinary_exposure: false, enabled_at: null } };
        }
        if (path.endsWith("/devices")) return { data: [{ id: "dev-1", name: "ops-laptop", owner_email: "ops@example.test", kind: "user", status: "active" }] };
        if (path.endsWith("/test-access")) return { data: diagnostic };
        return { data: [] };
      }),
      POST: vi.fn(async (_path: string, request?: { body?: unknown }) => {
        postedBodies.push(request?.body);
        return postError ? { error: { error: postError } } : { data: { id: `created-${postedBodies.length}` } };
      }),
      PATCH: vi.fn(async () => ({ data: {} })),
      PUT: vi.fn(async () => ({ data: {} })),
      DELETE: vi.fn(async () => ({ data: {} })),
    },
  };
});

import { OrgProvider } from "../src/lib/useOrg";
import { AuthProvider } from "../src/lib/auth";
import Access from "../src/pages/Access";

const page = () => render(<AuthProvider><OrgProvider><MemoryRouter><Access /></MemoryRouter></OrgProvider></AuthProvider>);

const API_RULE = { id: "r-api", enabled: true, src_kind: "group", src_group_id: "g1", dst_kind: "k8s_api", dst_k8s_api_cluster_id: "c-prod", dst_k8s_api_access_off: false, created_at: "2026-11-23T06:00:00Z" };
const API_RULE_OFF = { ...API_RULE, id: "r-api-off", dst_k8s_api_cluster_id: "c-staging", dst_k8s_api_access_off: true };
const SERVICE_RULE = { id: "r-svc", enabled: true, src_kind: "group", src_group_id: "g1", dst_kind: "k8s_service", dst_k8s_service_id: "k1", created_at: "2026-11-23T06:00:00Z" };

beforeEach(() => {
  rulesForTest = [];
  clustersFail = false;
  diagnostic = {};
  postedBodies = [];
  postError = null;
  apiAccessReads = [];
});

async function openBuilder() {
  const add = await screen.findByRole("button", { name: "Add rule" });
  await waitFor(() => expect((add as HTMLButtonElement).disabled).toBe(false));
  fireEvent.click(add);
  return screen.getByRole("dialog", { name: "Add rule" });
}

describe("Access rules — a cluster's Kubernetes API (K8N-3)", () => {
  it("names the destination 'Kubernetes API of <cluster>' on TCP 443, apart from a Service rule", async () => {
    rulesForTest = [API_RULE, SERVICE_RULE];
    page();
    const table = await screen.findByRole("table", { name: "Rules" });
    const apiRow = (await within(table).findByText("Kubernetes API of prod")).closest("tr")!;
    expect(within(apiRow).getByText("TCP 443")).toBeTruthy();
    expect(within(apiRow).queryByText(/API access off/)).toBeNull();
    // The Service rule keeps its own name and is not labelled as the API.
    const serviceRow = within(table).getByText("payments.shop.svc.prod.k8s.acme.com").closest("tr")!;
    expect(serviceRow).not.toBe(apiRow);
    expect(serviceRow.textContent).not.toMatch(/Kubernetes API/);
    // Each registered cluster's API access was read once.
    expect(apiAccessReads.sort()).toEqual(["c-prod", "c-staging"]);
  });

  it("warns on a rule whose cluster has API access off: kept, and allows nothing", async () => {
    rulesForTest = [API_RULE, API_RULE_OFF];
    page();
    const table = await screen.findByRole("table", { name: "Rules" });
    const offRow = (await within(table).findByText("Kubernetes API of staging")).closest("tr")!;
    const badge = within(offRow).getByText("API access off · allows nothing");
    expect(badge.getAttribute("title")).toBe("API access is off for this cluster. The rule is kept and allows nothing until API access is turned on again.");
    const onRow = within(table).getByText("Kubernetes API of prod").closest("tr")!;
    expect(within(onRow).queryByText(/API access off/)).toBeNull();

    // The warning is findable by its own words.
    fireEvent.change(screen.getByRole("textbox", { name: "Search rules" }), { target: { value: "api access off" } });
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Rules" })).queryByText("Kubernetes API of prod")).toBeNull());
    expect(within(screen.getByRole("table", { name: "Rules" })).getByText("Kubernetes API of staging")).toBeTruthy();
    fireEvent.change(screen.getByRole("textbox", { name: "Search rules" }), { target: { value: "kubernetes api" } });
    await waitFor(() => expect(within(screen.getByRole("table", { name: "Rules" })).getByText("Kubernetes API of prod")).toBeTruthy());
  });

  it("never shows an id-only or empty destination when the cluster list could not be read", async () => {
    rulesForTest = [API_RULE];
    clustersFail = true;
    page();
    const table = await screen.findByRole("table", { name: "Rules" });
    expect(await within(table).findByText(/Kubernetes API of cluster c-prod\. refresh/)).toBeTruthy();
    expect(within(table).queryByText(/deleted resource/)).toBeNull();
    expect(await screen.findByText(/failed to load\. names may show as unavailable\. Refresh\./)).toBeTruthy();
  });

  it("creates a rule for a group with dst_kind k8s_api and the cluster id", async () => {
    page();
    const dialog = await openBuilder();
    fireEvent.focus(within(dialog).getByRole("combobox", { name: "Destination" }));
    // A cluster whose API access is off is shown with the reason and cannot be chosen.
    const staging = await within(dialog).findByRole("button", { name: /Kubernetes API of staging/ });
    expect(staging).toHaveProperty("disabled", true);
    expect(staging.textContent).toMatch(/API access is off for this cluster\. Turn it on on the cluster's page first\./);

    const prod = within(dialog).getByRole("button", { name: /Kubernetes API of prod/ });
    expect(prod).toHaveProperty("disabled", false);
    expect(prod.textContent).toContain(`${FQDN} · TCP 443`);
    fireEvent.click(prod);

    const effect = within(dialog).getByTestId("rule-effect");
    expect(effect.textContent).toMatch(/every device of Engineering will be able to reach the Kubernetes API of prod on TCP 443 only\./);
    expect(effect.textContent).toMatch(/each person's own cluster credential still decides what they may do/);
    expect(within(effect).getByText("TCP · port 443")).toBeTruthy();

    fireEvent.click(within(dialog).getByRole("button", { name: "Review rule" }));
    expect(postedBodies).toHaveLength(0);
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    await waitFor(() => expect(postedBodies).toHaveLength(1));
    expect(postedBodies[0]).toEqual({ src_kind: "group", src_group_id: "g1", dst_kind: "k8s_api", dst_k8s_api_cluster_id: "c-prod" });
  });

  it("does not offer it for a site or an agent source, and says why", async () => {
    page();
    const dialog = await openBuilder();
    for (const source of [/eu-lan/, /build-bot/]) {
      fireEvent.focus(within(dialog).getByRole("combobox", { name: "Source" }));
      fireEvent.click(await within(dialog).findByRole("button", { name: source }));
      fireEvent.focus(within(dialog).getByRole("combobox", { name: "Destination" }));
      const prod = await within(dialog).findByRole("button", { name: /Kubernetes API of prod/ });
      expect(prod).toHaveProperty("disabled", true);
      expect(prod.textContent).toMatch(/A cluster's Kubernetes API can be granted to a person or a group only\./);
      fireEvent.click(prod);
      expect((within(dialog).getByRole("combobox", { name: "Destination" }) as HTMLInputElement).value).not.toMatch(/Kubernetes API/);
      expect(within(dialog).getByRole("button", { name: "Review rule" })).toHaveProperty("disabled", true);
    }
    expect(postedBodies).toHaveLength(0);
  });

  it("with the API chosen, refuses an address-range source in the form and never sends it", async () => {
    page();
    const dialog = await openBuilder();
    fireEvent.focus(within(dialog).getByRole("combobox", { name: "Destination" }));
    fireEvent.click(await within(dialog).findByRole("button", { name: /Kubernetes API of prod/ }));
    const review = within(dialog).getByRole("button", { name: "Review rule" });
    expect(review).toHaveProperty("disabled", false);

    // A site and an agent are shown as not selectable for this destination.
    const source = within(dialog).getByRole("combobox", { name: "Source" });
    fireEvent.focus(source);
    for (const name of [/eu-lan/, /build-bot/]) {
      const option = await within(dialog).findByRole("button", { name });
      expect(option).toHaveProperty("disabled", true);
      expect(option.textContent).toMatch(/can be granted to a person or a group only/);
    }

    // A typed address range can still be picked as a source; the form then refuses the pair.
    fireEvent.change(source, { target: { value: "10.9.0.0/24" } });
    fireEvent.click(await within(dialog).findByRole("button", { name: /10\.9\.0\.0\/24/ }));
    expect(within(dialog).getByTestId("k8s-api-refusal").textContent).toBe("A cluster's Kubernetes API can be granted to a person or a group only. Choose a person or a group as the source.");
    expect(review).toHaveProperty("disabled", true);
    fireEvent.click(review);
    expect(within(dialog).queryByRole("button", { name: "Create" })).toBeNull();
    expect(postedBodies).toHaveLength(0);
  });

  it("shows the server's refusal as it was sent", async () => {
    postError = { code: "k8s_api_not_enabled", message: "API access is off for this cluster; turn it on for the cluster before granting it" };
    page();
    const dialog = await openBuilder();
    fireEvent.focus(within(dialog).getByRole("combobox", { name: "Destination" }));
    fireEvent.click(await within(dialog).findByRole("button", { name: /Kubernetes API of prod/ }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Review rule" }));
    fireEvent.click(within(dialog).getByRole("button", { name: "Create" }));
    expect(await within(dialog).findByText("API access is off for this cluster; turn it on for the cluster before granting it")).toBeTruthy();
  });

  it("the rule's detail spells the kind and the port, and says it is a network path", async () => {
    rulesForTest = [API_RULE_OFF];
    page();
    const table = await screen.findByRole("table", { name: "Rules" });
    await within(table).findByText("Kubernetes API of staging");
    fireEvent.click(screen.getByRole("button", { name: "View rule Engineering to Kubernetes API of staging" }));
    expect(await screen.findByText(/group to Kubernetes API/)).toBeTruthy();
    expect(screen.getByText("Kubernetes API · TCP 443")).toBeTruthy();
    expect(document.body.textContent).not.toMatch(/k8s_api/);
    fireEvent.click(screen.getByRole("button", { name: "View impact" }));
    expect(await screen.findByText("TCP · port 443")).toBeTruthy();
    expect(screen.getByText("None while API access is off")).toBeTruthy();
    expect(screen.getByText("This rule opens a network path to the cluster's Kubernetes API. Each person's own cluster credential still decides what they may do.")).toBeTruthy();
    expect(screen.getByText("API access is off for this cluster. The rule is kept and allows nothing until API access is turned on again.")).toBeTruthy();
  });
});

describe("Test access — a cluster's Kubernetes API (K8N-3)", () => {
  async function runTest() {
    fireEvent.click(await screen.findByRole("button", { name: "Test access" }));
    // The Kubernetes API is tested for a person's device; an agent is never granted it.
    const person = screen.queryByRole("button", { name: "A person's device" });
    if (person) fireEvent.click(person);
    fireEvent.change(screen.getByPlaceholderText("10.20.0.15"), { target: { value: FQDN } });
    fireEvent.click(screen.getByRole("button", { name: "Run test" }));
    return screen.findByTestId("test-access-result");
  }

  it("renders the server's note as it was sent when the connection is allowed", async () => {
    diagnostic = { device_id: "dev-1", destination: FQDN, protocol: "tcp", port: 443, overall: "allowed", first_blocker: null, note: NOTE,
      checks: [{ status: "pass", code: "k8s_api_destination", message: "Destination is the Kubernetes API of cluster prod." }, { status: "pass", code: "k8s_api_endpoint_ready", message: "The cluster's gateway forwards to the cluster's API server." }] };
    page();
    const result = await runTest();
    expect(within(result).getByText("Allowed by current Tunnex intent")).toBeTruthy();
    expect(within(result).getByTestId("test-access-note").textContent).toBe(NOTE);
    expect(within(result).queryByTestId("test-access-advice")).toBeNull();
  });

  it("shows no note when the server sends none", async () => {
    diagnostic = { device_id: "dev-1", destination: "10.0.0.9", protocol: "tcp", port: 443, overall: "allowed", checks: [{ status: "pass", code: "device_active", message: "Device is active." }] };
    page();
    const result = await runTest();
    expect(within(result).queryByTestId("test-access-note")).toBeNull();
  });

  it("explains API access being off and links to the Kubernetes page", async () => {
    diagnostic = { device_id: "dev-1", destination: FQDN, protocol: "tcp", port: 443, overall: "denied", first_blocker: "k8s_api_not_enabled",
      checks: [{ status: "fail", code: "k8s_api_not_enabled", message: "API access is off for cluster prod.", facts: { cluster: "prod", name: FQDN } }] };
    page();
    const result = await runTest();
    const advice = within(result).getByTestId("test-access-advice");
    expect(advice.textContent).toMatch(/API access is off for that cluster, so its Kubernetes API has no address in the tunnel\. Turn it on on the cluster's page\./);
    expect(within(advice).getByRole("link", { name: "Open Kubernetes" }).getAttribute("href")).toBe("/kubernetes");
    expect(within(result).getByText("First blocker: k8s_api_not_enabled")).toBeTruthy();
  });

  it("reads the gateway's reason from the blocking check's own facts", async () => {
    diagnostic = { device_id: "dev-1", destination: FQDN, protocol: "tcp", port: 443, overall: "denied", first_blocker: "k8s_api_endpoint_unavailable",
      checks: [
        { status: "pass", code: "k8s_api_destination", message: "Destination is the Kubernetes API of cluster prod.", facts: { cluster: "prod" } },
        { status: "fail", code: "k8s_api_endpoint_unavailable", message: "The cluster's gateway runs on the cluster's only control-plane node.", facts: { cluster: "prod", gateway: "gw-prod", reason: "endpoints_on_gateway_node" } },
      ] };
    page();
    const result = await runTest();
    expect(within(result).getByTestId("test-access-advice").textContent).toMatch(/The gateway runs on the cluster's only control-plane node; it must run on a worker node\./);
  });

  it("says when the gateway has not reported its path to the API server", async () => {
    diagnostic = { device_id: "dev-1", destination: FQDN, protocol: "tcp", port: 443, overall: "inconclusive", first_blocker: "k8s_api_endpoint_not_observed",
      checks: [{ status: "inconclusive", code: "k8s_api_endpoint_not_observed", message: "The cluster's gateway has not reported whether it can forward to the API server yet.", facts: { cluster: "prod" } }] };
    page();
    const result = await runTest();
    expect(within(result).getByText("Inconclusive from current evidence")).toBeTruthy();
    expect(within(result).getByTestId("test-access-advice").textContent).toMatch(/The cluster's gateway has not reported whether it can reach the API server, so this step cannot be confirmed\. An older gateway never reports it\./);
  });
});

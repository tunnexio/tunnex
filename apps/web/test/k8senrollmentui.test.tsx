import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within, act } from "@testing-library/react";
import {
  ProviderFirstEnrollmentModal,
  ProviderMetadataCorrectionModal,
} from "../src/components/K8sEnrollment";
import type { Node, Site } from "../src/lib/api";
import type { EnrollmentDraft } from "../src/lib/k8senrollment";

afterEach(cleanup);

const SITE = { id: "site-1", name: "Production VPC" } as Site;
const CONNECTOR = {
  id: "node-1",
  name: "prod-k8s-connector",
  status: "active",
  site_id: SITE.id,
  endpoint: "connector.internal:51820",
} as Node;

const renderModal = (overrides: Partial<React.ComponentProps<typeof ProviderFirstEnrollmentModal>> = {}) => {
  const props: React.ComponentProps<typeof ProviderFirstEnrollmentModal> = {
    sites: [SITE],
    nodes: [CONNECTOR],
    onDismiss: () => {},
    onSubmit: async () => ({ ok: true }),
    onDone: () => {},
    ...overrides,
  };
  return render(<ProviderFirstEnrollmentModal {...props} />);
};

function selectStep(name: "1. Provider" | "2. Connection" | "3. Network" | "4. Review") {
  fireEvent.click(within(screen.getByRole("navigation", { name: "Enrollment steps" })).getByRole("button", { name }));
}

describe("ProviderFirstEnrollmentModal", () => {
  it("starts with an explicit provider choice and keeps continuation blocked until its platform is selected", () => {
    const submit = vi.fn();
    renderModal({ onSubmit: submit });
    expect(screen.getAllByRole("radio")).toHaveLength(4);
    expect(screen.getByRole("radio", { name: /Amazon Web Services/i })).toBeTruthy();
    expect(screen.getAllByRole("radio").every(radio => !(radio as HTMLInputElement).checked)).toBe(true);
    expect(screen.getByRole("button", { name: "1. Provider" }).getAttribute("aria-current")).toBe("step");
    expect(screen.getByRole("button", { name: "Continue" })).toHaveProperty("disabled", true);
    fireEvent.click(screen.getByRole("radio", { name: /Amazon Web Services/i }));
    expect(screen.getByRole("combobox", { name: "Kubernetes service" })).toHaveProperty("value", "");
    expect(screen.getByRole("button", { name: "Continue" })).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByRole("combobox", { name: "Kubernetes service" }), { target: { value: "eks" } });
    expect(screen.getByRole("button", { name: "Continue" })).toHaveProperty("disabled", false);
    expect(submit).not.toHaveBeenCalled();
  });

  it("does not default network facts and resets dependent choices when provider changes", () => {
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws",
        platform: "eks",
        siteId: SITE.id,
        connectorNodeId: CONNECTOR.id,
        name: "prod",
      },
    });

    selectStep("3. Network");
    expect((screen.getByLabelText("Kubernetes Service CIDR") as HTMLInputElement).value).toBe("");
    selectStep("1. Provider");
    fireEvent.click(screen.getByRole("radio", { name: /Microsoft Azure/i }));
    expect((screen.getByLabelText("Kubernetes service") as HTMLSelectElement).value).toBe("");
    selectStep("2. Connection");
    expect((screen.getByLabelText("Fronting Site") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText("In-cluster connector") as HTMLSelectElement).value).toBe("");
    expect((screen.getByLabelText("Cluster name") as HTMLInputElement).value).toBe("");
  });

  it("keeps provider services specific while the eligible connector stays provider-neutral", () => {
    renderModal();
    const cases = [
      [/Amazon Web Services/i, "eks", "Amazon Elastic Kubernetes Service (EKS)"],
      [/Microsoft Azure/i, "aks", "Azure Kubernetes Service (AKS)"],
      [/Google Cloud/i, "gke_standard", "Google Kubernetes Engine (GKE Standard)"],
      [/Self-managed/i, "kubernetes", "Kubernetes"],
    ] as const;

    for (const [provider, platform, service] of cases) {
      selectStep("1. Provider");
      fireEvent.click(screen.getByRole("radio", { name: provider }));
      const serviceSelect = screen.getByLabelText("Kubernetes service") as HTMLSelectElement;
      expect(Array.from(serviceSelect.options).map((option) => option.text)).toContain(service);
      fireEvent.change(serviceSelect, { target: { value: platform } });
      selectStep("2. Connection");
      fireEvent.change(screen.getByLabelText("Fronting Site"), { target: { value: SITE.id } });
      const connectorSelect = screen.getByLabelText("In-cluster connector") as HTMLSelectElement;
      expect(Array.from(connectorSelect.options).map((option) => option.text)).toContain("prod-k8s-connector");
    }
  });

  it("submits the complete explicit draft and makes no readiness claim", async () => {
    const submit = vi.fn(async (_draft: EnrollmentDraft) => ({ ok: true as const }));
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws",
        platform: "eks",
        siteId: SITE.id,
        connectorNodeId: CONNECTOR.id,
        name: "prod-eks",
        vipRange: "100.64.32.0/20",
        serviceCidr: "10.96.0.0/12",
        dnsZone: "k8s.example.test",
      },
      onSubmit: submit,
    });

    selectStep("4. Review");
    expect(screen.getByText(/Registration records control-plane intent/i)).toBeTruthy();
    expect(screen.queryByText(/^Active$/i)).toBeNull();
    fireEvent.click(screen.getByRole("button", { name: "Enroll cluster" }));
    await waitFor(() => expect(submit).toHaveBeenCalledTimes(1));
    expect(submit.mock.calls[0][0]).toMatchObject({ provider: "aws", platform: "eks" });
  });

  it("guides explicit connection and network choices before the only enrollment write", async () => {
    const submit = vi.fn(async (_draft: EnrollmentDraft) => ({ ok: true as const }));
    renderModal({ onSubmit: submit });
    fireEvent.click(screen.getByRole("radio", { name: /Amazon Web Services/i }));
    fireEvent.change(screen.getByLabelText("Kubernetes service"), { target: { value: "eks" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByRole("button", { name: "2. Connection" }).getAttribute("aria-current")).toBe("step");
    expect(screen.getByLabelText("Fronting Site")).toHaveProperty("value", "");
    expect(screen.getByLabelText("In-cluster connector")).toHaveProperty("value", "");
    expect(screen.getByRole("button", { name: "Continue" })).toHaveProperty("disabled", true);
    fireEvent.change(screen.getByLabelText("Fronting Site"), { target: { value: SITE.id } });
    fireEvent.change(screen.getByLabelText("In-cluster connector"), { target: { value: CONNECTOR.id } });
    fireEvent.change(screen.getByLabelText("Cluster name"), { target: { value: "prod-eks" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByRole("button", { name: "3. Network" }).getAttribute("aria-current")).toBe("step");
    expect(screen.getByLabelText("Synthetic VIP range")).toHaveProperty("value", "");
    expect(screen.getByLabelText("Kubernetes Service CIDR")).toHaveProperty("value", "");
    expect(screen.getByLabelText("DNS zone")).toHaveProperty("value", "");
    fireEvent.change(screen.getByLabelText("Synthetic VIP range"), { target: { value: "100.64.32.0/20" } });
    fireEvent.change(screen.getByLabelText("Kubernetes Service CIDR"), { target: { value: "10.96.0.0/12" } });
    fireEvent.change(screen.getByLabelText("DNS zone"), { target: { value: "k8s.example.test" } });
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    expect(screen.getByRole("button", { name: "4. Review" }).getAttribute("aria-current")).toBe("step");
    expect(submit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Back" }));
    expect(screen.getByLabelText("DNS zone")).toHaveProperty("value", "k8s.example.test");
    expect(submit).not.toHaveBeenCalled();
    fireEvent.click(screen.getByRole("button", { name: "Continue" }));
    fireEvent.click(screen.getByRole("button", { name: "Enroll cluster" }));
    await waitFor(() => expect(submit).toHaveBeenCalledWith({ provider: "aws", platform: "eks", siteId: SITE.id, connectorNodeId: CONNECTOR.id, name: "prod-eks", vipRange: "100.64.32.0/20", serviceCidr: "10.96.0.0/12", dnsZone: "k8s.example.test" }));
    expect(submit).toHaveBeenCalledTimes(1);
  });

  it.each([
    { ...CONNECTOR, status: "revoked" },
    { ...CONNECTOR, site_id: "other-site" },
    { ...CONNECTOR, endpoint: "" },
  ] as Node[])("blocks a stale explicit connector choice that is no longer eligible ($status/$site_id/$endpoint)", connector => {
    const submit = vi.fn();
    renderModal({ nodes: [connector], onSubmit: submit, initialDraft: { provider: "aws", platform: "eks", siteId: SITE.id, connectorNodeId: CONNECTOR.id, name: "prod-eks", vipRange: "100.64.32.0/20", serviceCidr: "10.96.0.0/12", dnsZone: "k8s.example.test" } });
    selectStep("4. Review");
    const enroll = screen.getByRole("button", { name: "Enroll cluster" });
    expect(enroll).toHaveProperty("disabled", true);
    fireEvent.click(enroll);
    expect(submit).not.toHaveBeenCalled();
  });

  it("exposes accessible DNS validation and blocks malformed enrollment", () => {
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: {
        provider: "aws", platform: "eks", siteId: SITE.id,
        connectorNodeId: CONNECTOR.id, name: "Prod EKS",
        vipRange: "100.64.32.0/20", serviceCidr: "10.96.0.0/12",
        dnsZone: "K8S Example",
      },
    });
    selectStep("2. Connection");
    expect(screen.getByLabelText("Cluster name").getAttribute("aria-invalid")).toBe("true");
    selectStep("3. Network");
    expect(screen.getByLabelText("DNS zone").getAttribute("aria-invalid")).toBe("true");
    expect(screen.getAllByRole("alert").map((node) => node.textContent).join(" ")).toMatch(/lowercase DNS/);
    expect(screen.getByRole("button", { name: "Continue" })).toHaveProperty("disabled", true);
    selectStep("4. Review");
    expect((screen.getByRole("button", { name: "Enroll cluster" }) as HTMLButtonElement).disabled).toBe(true);
  });

  it("does not collapse failed Site and Node reads into empty inventories", () => {
    renderModal({ sites: null, nodes: null, sitesError: "sites failed", nodesError: "nodes failed", initialDraft: { provider: "aws", platform: "eks" } });
    selectStep("2. Connection");
    expect(screen.getAllByRole("alert").map(alert => alert.textContent).join(" ")).toContain("Site inventory unavailable. Close and refresh to retry.");
    expect(screen.getAllByRole("alert").map(alert => alert.textContent).join(" ")).toContain("Connector inventory unavailable. Close and refresh to retry.");
    expect(screen.getByRole("combobox", { name: "Fronting Site" })).toHaveProperty("disabled", true);
    expect(screen.getByRole("combobox", { name: "In-cluster connector" })).toHaveProperty("disabled", true);
    expect(screen.queryByText(/No active endpoint-bearing connector/)).toBeNull();
  });

  it("ignores Escape dismissal while enrollment is in flight", async () => {
    let finish!: (value: { ok: true }) => void;
    const dismiss = vi.fn();
    renderModal({
      initialAdvancedOpen: true,
      initialDraft: { provider: "aws", platform: "eks", siteId: SITE.id, connectorNodeId: CONNECTOR.id, name: "prod", vipRange: "100.64.0.0/24", serviceCidr: "10.96.0.0/12", dnsZone: "k8s.example" },
      onDismiss: dismiss,
      onSubmit: () => new Promise((resolve) => { finish = resolve; }),
    });
    selectStep("4. Review");
    fireEvent.click(screen.getByRole("button", { name: "Enroll cluster" }));
    fireEvent.keyDown(screen.getByRole("dialog"), { key: "Escape" });
    expect(dismiss).not.toHaveBeenCalled();
    await act(async () => { finish({ ok: true }); });
  });
});

describe("ProviderMetadataCorrectionModal", () => {
  it("does not infer unknown legacy metadata and saves only an exact supported pair", async () => {
    const submit = vi.fn(async () => ({ ok: true as const }));
    render(
      <ProviderMetadataCorrectionModal
        clusterName="legacy-prod"
        initialProvider="unknown"
        initialPlatform="unknown"
        onDismiss={() => {}}
        onSubmit={submit}
        onDone={() => {}}
      />,
    );

    expect(screen.getByText(/No provider or platform was inferred/i)).toBeTruthy();
    const save = screen.getByRole("button", { name: "Save provider metadata" }) as HTMLButtonElement;
    expect(save.disabled).toBe(true);
    fireEvent.click(screen.getByRole("radio", { name: /Microsoft Azure/i }));
    expect((screen.getByLabelText("Kubernetes service") as HTMLSelectElement).value).toBe("");
    fireEvent.change(screen.getByLabelText("Kubernetes service"), { target: { value: "aks" } });
    fireEvent.click(save);
    await waitFor(() => expect(submit).toHaveBeenCalledWith("azure", "aks"));
  });
});

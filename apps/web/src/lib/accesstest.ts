// "Test access" can be opened from the place a person is already looking: a device row, a denied
// event. The link carries who and what to test; the dialog on Access Policies reads it.

export type AccessTestRequest = {
  kind: "device" | "agent";
  id: string;
  destination?: string;
  protocol?: "tcp" | "udp";
  port?: number;
};

export function accessTestLink(request: AccessTestRequest): string {
  const params = new URLSearchParams({ test: `${request.kind}:${request.id}` });
  if (request.destination) params.set("dst", request.destination);
  if (request.protocol) params.set("proto", request.protocol);
  if (request.port) params.set("port", String(request.port));
  return `/access?${params.toString()}`;
}

/** Reads a link made by accessTestLink. Anything malformed is ignored rather than half-applied. */
export function parseAccessTest(search: string): AccessTestRequest | null {
  const params = new URLSearchParams(search);
  const match = /^(device|agent):([0-9a-zA-Z-]{1,64})$/.exec(params.get("test") ?? "");
  if (!match) return null;
  const request: AccessTestRequest = { kind: match[1] as "device" | "agent", id: match[2]! };
  const destination = params.get("dst")?.trim();
  if (destination && destination.length <= 253) request.destination = destination;
  const protocol = params.get("proto");
  if (protocol === "tcp" || protocol === "udp") request.protocol = protocol;
  const port = Number(params.get("port"));
  if (Number.isInteger(port) && port >= 1 && port <= 65535) request.port = port;
  return request;
}

/**
 * What a blocker means to an administrator, and where it is fixed. Unknown codes get no advice.
 * `facts` are the blocking check's own evidence; a few blockers read one of them (the gateway's reason).
 */
export function blockerAdvice(code: string, facts?: Record<string, string> | null): { text: string; action?: { label: string; to: string } } | null {
  switch (code) {
    case "no_matching_grant":
      return { text: "No access rule allows this person or device to reach this destination on this port.", action: { label: "Open access rules", to: "/access" } };
    case "device_not_active":
    case "agent_not_active":
      return { text: "This device is not active, so nothing it sends is accepted.", action: { label: "Open devices", to: "/devices" } };
    case "posture_blocked":
      return { text: "Device posture is blocking this device until it meets the posture policy.", action: { label: "Open device posture", to: "/devices/posture" } };
    case "gateway_not_reporting":
      return { text: "The gateway this device connects through is not reporting. Traffic cannot pass until it is back.", action: { label: "Open gateways", to: "/gateways" } };
    case "route_not_configured":
      return { text: "The device's gateway has no route to this destination. The network that owns it may not be linked, or its range is not approved.", action: { label: "Open networks", to: "/sites" } };
    case "device_dns_not_observed":
    case "agent_dns_not_observed":
    case "route_destination_unresolved":
    case "policy_destination_unresolved":
      return { text: "This name is not one the control plane can turn into an address. Enter the destination's IP address and run the test again." };
    case "applied_policy_mismatch":
      return { text: "The gateway is not enforcing the current rules yet. Its health shows why.", action: { label: "Open gateways", to: "/gateways" } };
    case "applied_policy_not_observed":
      return { text: "The gateway has not reported which rules it is enforcing, so the last step cannot be confirmed.", action: { label: "Open gateways", to: "/gateways" } };
    case "compiled_policy_unavailable":
      return { text: "The rules for this device's gateway could not be read. Try again in a moment." };
    case "runtime_not_ready":
    case "runtime_not_enabled":
    case "runtime_status_unavailable":
      return { text: "The agent's managed runtime has not applied its current configuration.", action: { label: "Open agents", to: "/agents" } };
    case "route_intent_unavailable":
      return { text: "The agent's route configuration could not be read. Try again in a moment." };
    // K8N-3: the destination is a cluster's Kubernetes API.
    case "k8s_api_not_enabled":
      return { text: "API access is off for that cluster, so its Kubernetes API has no address in the tunnel. Turn it on on the cluster's page.", action: { label: "Open Kubernetes", to: "/kubernetes" } };
    case "k8s_api_endpoint_unavailable":
      return facts?.reason === "endpoints_on_gateway_node"
        ? { text: "The cluster's gateway cannot forward to the API server. The gateway runs on the cluster's only control-plane node; it must run on a worker node.", action: { label: "Open Kubernetes", to: "/kubernetes" } }
        : facts?.reason === "no_gateway"
          ? { text: "The cluster has no gateway assigned, so nothing forwards to its API server. Select a connector on the cluster's page.", action: { label: "Open Kubernetes", to: "/kubernetes" } }
          : { text: "The cluster's gateway cannot forward to the API server.", action: { label: "Open gateways", to: "/gateways" } };
    case "k8s_api_endpoint_not_observed":
      return { text: "The cluster's gateway has not reported whether it can reach the API server, so this step cannot be confirmed. An older gateway never reports it.", action: { label: "Open gateways", to: "/gateways" } };
  }
  return null;
}

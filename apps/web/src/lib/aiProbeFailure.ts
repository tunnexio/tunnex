type Notice = { title: string; description: string };
const failed = "Connection test failed";

export function aiProbeFailure(httpStatus?: number, failure?: unknown): Notice {
  // The API envelope and the upstream response are different HTTP exchanges.
  if (httpStatus && httpStatus >= 400) {
    const description = httpStatus === 429 ? "Too many connection tests. Wait a minute and retry."
      : httpStatus === 401 ? "Your Tunnex session has expired. Sign in and retry."
      : httpStatus === 403 ? "Tunnex denied this test. Check your AI management permissions."
      : httpStatus === 409 ? "Saved credentials changed or are still applying. Refresh and retry."
      : httpStatus === 400 ? "Tunnex rejected the test configuration. Check the selected model, endpoint and credentials."
      : "The Tunnex test service is unavailable. Check the gateway and private test bridge, then retry.";
    return { title: `${failed} · Tunnex HTTP ${httpStatus}`, description };
  }
  const f = failure && typeof failure === "object" ? failure as Record<string, unknown> : {};
  const source = f.source === "provider" ? "Provider" : f.source === "proxy" ? "Network proxy" : f.source === "gateway" ? "Test gateway" : undefined;
  if (source && f.kind === "http_error" && Number.isInteger(f.http_status) && Number(f.http_status) >= 400 && Number(f.http_status) <= 599) {
    const code = Number(f.http_status);
    const description = f.source === "gateway" ? "The test gateway rejected this request. Check its configuration and service health."
      : f.source === "proxy" ? "The network proxy rejected the connection. Check its destination policy and connectivity to the private endpoint."
      : code === 401 ? "Authentication failed. Check the saved or entered provider API key."
      : code === 403 ? "Access denied by the provider. Check resource permissions, firewall rules and private endpoint network access."
      : code === 404 ? "The provider could not find this endpoint or deployment. Check the API URL and exact model name."
      : code === 429 ? "The provider rate limit or quota was exceeded. Check quota and retry later."
      : code >= 500 ? "The provider returned a server error. Retry later or check its service health."
      : "The provider rejected the request. Check the deployment, selected mode and endpoint configuration.";
    return { title: `${failed} · ${source} HTTP ${code}`, description };
  }
  if (source && f.http_status == null && f.kind === "network_error") return {
    title: `${failed} · Network unreachable`,
    description: "No HTTP response was received. Check DNS, TLS, firewall and gateway/proxy access to the private endpoint.",
  };
  if (source && f.http_status == null && f.kind === "timeout") return {
    title: `${failed} · Timeout`,
    description: "No complete response was received before the test deadline. Check private network connectivity and provider availability.",
  };
  if (source && f.kind === "configuration_error") return { title: `${failed} · Configuration error`, description: "The test bridge rejected this configuration. Check the endpoint, model, mode and installation network settings." };
  if (source && f.kind === "invalid_response") return { title: `${failed} · Incomplete or invalid response`, description: "The response was interrupted or did not match the expected format. Check endpoint connectivity, API protocol and the selected model mode." };
  if (!httpStatus) return { title: `${failed} · Network error`, description: "No response from Tunnex. Check your connection to the gateway and retry." };
  return { title: failed, description: "The test service did not provide a failure code. Check the model, endpoint and credentials, then retry." };
}

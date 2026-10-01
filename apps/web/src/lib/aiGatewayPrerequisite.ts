import type { components } from "@tunnex/shared";

export function aiGatewayPrerequisite(settings: components["schemas"]["AIGatewaySettings"]): string {
  if (settings.available) return "";
  if (settings.unavailable_reason === "https_required") {
    return `${settings.engine_installed ? "The private AI backend is installed. " : ""}Configure HTTPS, or ask your installation administrator to allow HTTP for an endpoint restricted to your private or VPN network, before adding provider credentials or enabling AI access.`;
  }
  return "Ask your installation administrator to configure the private AI backend before enabling access.";
}

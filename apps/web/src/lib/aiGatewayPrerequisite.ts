import type { components } from "@tunnex/shared";

type Settings = components["schemas"]["AIGatewaySettings"];
export type AIGatewayStatus = components["schemas"]["AIGatewayStatus"];
export type AIGatewayOffReason = NonNullable<AIGatewayStatus["reason"]>;
export type AIGatewayViewer = { canManage: boolean; serverAdmin: boolean };

const reasons: readonly AIGatewayOffReason[] = ["not_enabled", "transport_required", "no_provider", "engine_not_installed"];

/**
 * The one reason the gateway is not usable, or `{ on: true }`.
 *
 * The server's `status` is authoritative. A server that does not send it yet still tells us enough to
 * name three of the four reasons; it cannot tell us that no provider credential exists.
 */
export function aiGatewayStatus(settings: Settings): AIGatewayStatus {
  const sent = settings.status;
  if (sent && typeof sent.on === "boolean") {
    if (sent.on) return { on: true, reason: null, fix: null };
    if (sent.reason && reasons.includes(sent.reason)) return sent;
  }
  if (!settings.available) return settings.unavailable_reason === "https_required"
    ? { on: false, reason: "transport_required", fix: { kind: "choose_transport", href: "/settings?section=ai-transport", requires_server_admin: true } }
    : { on: false, reason: "engine_not_installed", fix: { kind: "install_engine", requires_server_admin: true } };
  if (!settings.enabled) return { on: false, reason: "not_enabled", fix: { kind: "enable" } };
  return { on: true, reason: null, fix: null };
}

/** What is missing, in one sentence, and who can fix it when the reader cannot. */
export function aiGatewayOffCopy(reason: AIGatewayOffReason, viewer: AIGatewayViewer): { title: string; body: string } {
  switch (reason) {
    case "not_enabled": return {
      title: "AI Gateway is turned off",
      body: viewer.canManage
        ? "No request can reach a model until AI Gateway is turned on for this organization."
        : "No request can reach a model until AI Gateway is turned on for this organization. Ask an organization owner or administrator to turn it on.",
    };
    case "transport_required": return {
      title: "AI Gateway needs a transport choice first",
      body: viewer.serverAdmin
        ? "This server is reached over plain HTTP, and AI Gateway does not use plain HTTP until a server administrator allows it. Choose the transport now, or set up HTTPS for this server."
        : "This server is reached over plain HTTP, and AI Gateway does not use plain HTTP until a server administrator allows it. Ask a server administrator to open Settings, then AI Gateway transport, and choose how AI Gateway is reached.",
    };
    case "no_provider": return {
      title: "No provider credential yet",
      body: viewer.canManage
        ? "AI Gateway is on, but it has no provider credential (for example an OpenAI or Anthropic API key), so no model can answer. Add one to continue."
        : "AI Gateway is on, but it has no provider credential (for example an OpenAI or Anthropic API key), so no model can answer. Ask an organization owner or administrator to add one under AI Gateway, LLM credentials.",
    };
    case "engine_not_installed": return {
      title: "The AI engine is not installed on this server",
      body: viewer.serverAdmin
        ? "AI Gateway runs on an AI engine that is installed with Tunnex Server, and this server does not have it. Nothing on this page can install it: upgrade Tunnex Server on the server itself (the upgrade installs the AI engine), then reload this page."
        : "AI Gateway runs on an AI engine that is installed with Tunnex Server, and this server does not have it. Only a server administrator can fix this: ask them to upgrade Tunnex Server on the server itself (the upgrade installs the AI engine).",
    };
  }
}

/** One sentence for a settings row: empty when nothing is missing. */
export function aiGatewayPrerequisite(settings: Settings, viewer: AIGatewayViewer = { canManage: true, serverAdmin: false }): string {
  const status = aiGatewayStatus(settings);
  return status.on || !status.reason ? "" : aiGatewayOffCopy(status.reason, viewer).body;
}

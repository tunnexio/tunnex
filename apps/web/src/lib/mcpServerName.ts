/** An MCP server as an administrator named it when connecting it: the name, and the address name its clients use. */
export type NamedMCPServer = { endpoint: string; profile_name: string; server_name: string };

/**
 * The name a person reads for the server at `endpoint`: the one an administrator gave it. The name the MCP
 * server reports about itself is used only when no connected server has that address (for example a call
 * recorded before the server was disconnected).
 */
export function mcpServerName(servers: readonly Partial<NamedMCPServer>[] | undefined, endpoint: string | null | undefined, reported?: string | null): string {
  const address = (endpoint ?? "").trim();
  const match = address ? servers?.find((server) => (server.endpoint ?? "").trim() === address) : undefined;
  return match?.profile_name || match?.server_name || reported || address;
}

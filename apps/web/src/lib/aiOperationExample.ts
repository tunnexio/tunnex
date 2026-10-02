const quote = (value: string) => "'" + value.replace(/'/g, "'\\''") + "'";

/** Only advertise operations implemented by the VPN identity relay. */
export function aiOperationSpec(model: string, mode: string) {
  if (mode !== "chat") return null;
  return { route: "chat/completions", body: { model, messages: [{ role: "user", content: "Hello" }], max_tokens: 256 } };
}

/** base is the user's authoritative vpn_base_url, never the browser origin. */
export function aiOperationExample(base: string, model: string, mode: string): string | null {
  const operation = aiOperationSpec(model, mode);
  if (!operation) return null;
  return [
    `curl --fail-with-body ${quote(base + "/" + operation.route)} \\`,
    "  -H 'Content-Type: application/json' \\",
    `  --data-raw ${quote(JSON.stringify(operation.body))}`,
  ].join("\n");
}

# AI model connection details

User approved, 2026-09-11:

- Show the exact SDK base URL, organization name/ID, model ID, and copy actions
  alongside saved models and in My models.
- Offer a simple `/ai/v1` URL for the single-organization case.
- Require an explicit organization URL when organization selection is ambiguous.
- Preserve verified VPN identity, model grants, and tenant isolation. Dummy SDK
  keys do not authorize requests outside the verified VPN ingress.
- Explain which configured VPN gateway is applicable. Do not imply that all
  enrolled gateways support AI ingress: the current deployment configures one.

Pending user clarification: does single-organization mean one live organization
on the whole control plane, or one active membership for the connected user?
The alias resolver and its UI recommendation must use the same definition.
No alias implementation or deployment before that decision. Explicit scoped
connection details and copy controls can be built independently.

Current production ingress supports chat completions only. Do not generate
dummy-key examples for unsupported model modes or claim TURN relay proof.

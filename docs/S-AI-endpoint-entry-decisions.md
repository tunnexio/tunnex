# Provider API endpoint entry

User requests the missing model API endpoint input so a connection can be tested.
This fixes the existing onboarding surface within the approved custom/SageMaker
endpoint and authenticated-egress contract; it does not change server routing.

- Show an editable API base URL for new Custom and SageMaker connections, with
  approved endpoint shortcuts. Selecting a provider remains possible before
  installation configuration so the required URL/setup is visible.
- Accept a base URL or its /v1 form; resolve it to the exact matching approved
  endpoint returned by the server. HTTP/HTTPS only, no userinfo/query/fragment.
  Display the actual chat request URL; never silently redirect a native provider
  key to another origin. Native providers retain their existing standard routes;
  users choose Custom for an alternate OpenAI-compatible API URL.
- An unapproved or invalid URL displays a specific explanation and cannot enable
  Test Connect or Save. Server allowlist/CIDR/CONNECT checks remain authoritative.
- Endpoint edits clear credentials and invalidate prior test success. Both the
  probe and creation submit the same approved URL. Existing connection endpoints
  stay immutable, including saved-credential reuse.
- SageMaker's editable URL is the approved private LiteLLM bridge API, not an AWS
  InvokeEndpoint URL. Region, endpoint name and IAM binding remain installation
  settings; a gateway key cannot authenticate AWS SigV4 directly.

Validation: typed URL test/save payload, normalization, unavailable setup,
unapproved URL refusal, edit invalidation and immutable existing connections;
render the actual local form and test with the existing synthetic endpoint.

## Endpoint visibility and direct credential creation

The user's latest screenshots identify two unreachable onboarding controls.
Keep Upstream API Base visible before provider selection, with an explicit prompt
to select a provider. For native providers, display the real fixed origin and
provide a direct Use custom endpoint action for new credentials. That action
explicitly selects Custom and clears the previous key, models and test result;
only the existing installation-approved OpenAI-compatible path accepts an
alternate URL. Saved endpoints stay immutable.

Add Credentials is a direct action in LLM Credentials, opening the existing
credential editor as a creation drawer with provider, endpoint, key and exact
model scope. It uses the existing create and Test Connect endpoints, returns to
LLM Credentials after save, and clears unsent secrets on dismissal/navigation.
State clearly that at least one model is required: this slice exposes current
model-scoped credential creation, not an independent empty-scope secret vault.
No schema, storage, routing or authorization change is included.

Validation covers the initial endpoint field, explicit custom transition, direct
credential test/create payloads, return destination, and draft disposal.

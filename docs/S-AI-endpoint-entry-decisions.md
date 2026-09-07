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

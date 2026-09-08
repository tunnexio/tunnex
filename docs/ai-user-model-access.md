# Give a user group access to an AI model

Users call models with their Tunnex login. Provider API keys remain in the private
gateway. A saved model becomes usable after an AI administrator grants it to a
user group and enables organization AI access.

## Delegate AI administration

An organization owner or administrator opens **Users & Roles**, expands a user's
roles, selects the required checkboxes, and clicks **Save roles**. Multiple roles
can be assigned together, for example `member` and `ai-admin`. Unchecking one role
preserves the other selected roles.

| Role | AI permissions |
| --- | --- |
| `ai-admin` | Manage models, credentials, gateway configuration, and group model grants. |
| `ai-view` | Read AI configuration, models, grants, and usage. No edits or credential tests. |
| `member` | Use models granted to the user's groups. |

AI roles do not grant VPN, organization, user, or role administration. Role
permissions combine within the organization. Only owners can change ownership,
and the last owner cannot be removed. Every role, including owner and `ai-admin`,
still needs a group model grant to perform inference.

## Grant the Engineering group a model

1. In **Access Policies → Groups**, use an existing people or directory group.
   An administrator with group-management permission can create a people group
   named Engineering and add its four users. Directory-group membership remains
   managed by its directory. This is a human user group, separate from managed
   agent groups.
2. In **AI agents → AI gateway → Models & endpoints**, save and test the model
   with its provider credentials. Its connection must be enabled and applied.
3. In **Configuration**, choose **Enable AI gateway** if organization access is
   off. The private gateway must already be configured for the installation.
4. In **Group access**, select Engineering and the configured model, then click
   **Grant model access**. Wait for its state to become `applied`; pending or
   failed provisioning does not allow requests.
5. Each member signs in to Tunnex and opens **AI gateway → Use model**. The page
   lists that user's available models, shows the exact API endpoint, and provides
   terminal commands. For chat models, **Call model** runs a request in the browser
   and shows the HTTP response status in a toast.

An AI administrator grants access to existing groups without receiving broader
group-management permission. Existing edition rules for creating and managing
groups continue to apply.

## Call a model

For chat models the endpoint is:

```text
POST https://YOUR-TUNNEX-SERVER/api/v1/organizations/ORG_ID/ai-gateway/inference/v1/chat/completions
```

Use the exact gateway model ID shown in **Use model**, including its provider or
connection prefix. It can differ from the upstream deployment name.

```sh
tunnex login --server https://YOUR-TUNNEX-SERVER
tunnex ai models --org ORG_ID
tunnex ai chat --org ORG_ID --model 'EXACT_GATEWAY_MODEL_ID' --prompt 'Hello'
```

These commands use the saved Tunnex login credential. They never require the
Azure, OpenAI, or other provider's API key. Browser calls use the signed-in session
and CSRF protection. Other API clients use a Tunnex login bearer credential in
`Authorization: Bearer ...`; the endpoint is authenticated, not anonymous.

The inference base is
`/api/v1/organizations/ORG_ID/ai-gateway/inference/v1`. The configured model's
mode determines the operation:

| Mode | Path after the inference base |
| --- | --- |
| Chat | `/chat/completions` |
| Completion | `/completions` |
| Embedding | `/embeddings` |
| Audio speech | `/audio/speech` |
| Audio transcription | `/audio/transcriptions` |
| Image generation | `/images/generations` |
| Video generation | `/videos` |
| Rerank | `/rerank` |

Use the request format for the selected mode and a model that supports it. The
browser playground and `tunnex ai chat` provide chat calls; other modes use the API.
Video follow-up requests remain bound to their creating user. Anthropic Messages
uses `/api/v1/organizations/ORG_ID/ai-gateway/inference/anthropic/v1/messages`.

## Revoke access and troubleshoot

**Revoke access**, removing a user from the group, disabling the provider, or
disabling organization AI access blocks subsequent requests. An already accepted
request may finish. Deleting a group withdraws its active grants while retaining
the usage and key-accounting history.

- No model listed: check group membership, an applied grant, provider readiness,
  and organization AI access, then use **Refresh my models**.
- HTTP 401: sign in again.
- HTTP 403: ask the AI administrator to verify the current group grant. An AI
  administration role alone does not grant inference.
- Pending grant: refresh its state; the background worker retries provisioning.
- Usage: **Usage & cost → Spend by user group** attributes observed human requests
  to their authorized group. Provider estimates may be incomplete.

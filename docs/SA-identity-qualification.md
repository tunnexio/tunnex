# Server Access local identity qualification

On 2026-10-05 the owned `tunnex-sa0-browser-1005` topology passed the following identity checks. These are local integrated results, not production IdP, cloud, browser fleet, capacity or HA certification. No baseline API/gateway restart, production configuration edit, commit or publication was performed.

## Signed SSO and browser SSH

`TestServerAccessOwnedSSOIdentityFixture` hosts a controlled RSA-signed OpenID provider and uses the production SSO start/callback handlers. It verifies state, nonce, PKCE and RS256 through normal requests, shared Redis sessions and the existing verified member identity. The temporary provider configuration was restored exactly when the fixture stopped.

`qualify-sso-identity.py --admission` passed seven signed-token variants. Fresh `amr=[pwd,mfa]` with current `auth_time` permits terminal admission. Absent MFA, two-hour-old authentication and future authentication still allow ordinary identity login but terminal admission returns `403 mfa_required`. Wrong nonce, wrong audience and invalid signature create no authenticated parent session and return the generic SSO failure landing.

A real Chrome tab followed the provider form and production callback, then connected through the baseline Community API and enrolled gateway to the native SSH PTY. The terminal returned `SA9_SSO_BROWSER_OK héllo`, `uid=1000(fixture) gid=1000(fixture) groups=1000(fixture)` and `stty size` output `22 152`; the recording indicator was ON. The terminal was ended normally and the temporary individual permission was revoked. Screenshot: `/private/tmp/tunnex-sa0-spike/sa9-sso-browser-terminal.png`.

This proves existing configured SSO login and verified IdP MFA can authorize Community browser SSH. It does not change the repository's commercial gate for SSO configuration/JIT administration.

## Real enrollment and mTLS tenancy

`TestServerAccessOwnedIdentityEnrollmentFixture` exposes only normal enrollment/node administration using the existing installation CA and session authentication. Its in-memory signed Scale test entitlement allows additional owned test gateways without changing the baseline Community entitlement. Generated RSA CSRs were redeemed through real join tokens; issued client certificates then connected to the baseline mTLS listener with CA and `tunnex-control` hostname verification enabled.

`qualify-enrolled-identity.py` passed:

- Both issued identities authenticate and receive an empty, correctly scoped desired state.
- A different gateway in the primary organization receives `403 gateway_binding_mismatch` for material, lease and status; terminal channel CONNECT also refuses its binding.
- An enrolled gateway in a different organization receives `404 server_access_not_found` for the same primary session operations and terminal channel.
- Both identities receive `403 invalid_channel_purpose` for `app_access_http_v1` on the terminal channel.
- The ordinary primary member receives `404 org_not_found` for the foreign organization's workspace.
- Normal node revocation makes each previously valid issued certificate return HTTP 401 on the actual baseline mTLS desired-state route.

The targeted session was a previously ended primary terminal. Gateway/organization binding is checked before status/material parsing, so these checks prove credential audience refusal without opening or interfering with a live PTY. They do not claim another successful gateway connection or cross-organization product administration entitlement.

## Preserved local evidence and cleanup

The temporary gateway certificates were revoked, generated join tokens consumed, fixture memberships removed and generated private key/certificate directories erased. The two standalone HTTP identity fixtures are stopped. Three empty fixture organizations remain deliberately: deleting them would invoke `audit_logs.org_id ON DELETE SET NULL`, which the repository's immutable audit trigger refuses. Their immutable enrollment/revocation audit records are preserved; no audit trigger was bypassed.

| Organization ID | Name |
| --- | --- |
| `b2891d06-c082-4800-a418-f987e52ef3e9` | SA9 owned identity b2891d06-c082-4800-a418-f987e52ef3e9 |
| `7e52582a-b12e-459d-8bd8-d167a727c4ef` | SA9 owned identity 7e52582a-b12e-459d-8bd8-d167a727c4ef |
| `0f310c80-342e-47ee-9c11-e9862c9f58c6` | SA9 owned identity 0f310c80-342e-47ee-9c11-e9862c9f58c6 |

Only these exact ID/name pairs are accepted as additional audit markers by the enrollment fixture ownership guard. Future runs create another uniquely named inert audit organization; review its ID rather than relaxing ownership to a name prefix. The guarded scripts depend on private owned fixture credentials outside Git and never print tokens, cookies, private keys or provider secrets.

Artifact evidence is in ignored `.runtime/sso-identity-results.json` and `.runtime/enrolled-identity-results.json`. The baseline build evidence at qualification recorded API SHA256 `d9507c4c61c95be2ba7d6875e0bebad4c08abecca16e24ea6defd229aa177832` and gateway SHA256 `8c0e60f6d81632b30cf4c1ccfb0f2b177a024f636cea028e052ff99dd71cfe8b`. Later builds require renewed qualification for changed identity behavior.

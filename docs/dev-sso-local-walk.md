# Walking SSO against a real IdP on a laptop

How to click "Continue with Microsoft" on a local stack and land in the app, with **no organization
field anywhere in the flow**. Development only.

## What is already running

| Piece | Where | Notes |
| --- | --- | --- |
| API | `tunnex-api-1` (compose) | reachable on the host via the socat forwarder below |
| Postgres / Redis | compose | seeded (`make seed`, `make seed-enterprise`) |
| Host → API forwarder | `tunnex-apifwd` | publishes the API's `:8080` on the host |
| Web | Vite dev server on `:5180` | proxies `/api` → `localhost:8080` |

`nginx` and the `web` image are NOT running. The `web` image build is broken for an unrelated
reason: the repo has no `.dockerignore`, so `COPY apps/web/ apps/web/` overwrites the container's
`node_modules` with the host's partial one and the build loses `tsc`. The Vite dev server sidesteps
it entirely.

If the forwarder is gone (`docker ps | grep apifwd`), recreate it:

```bash
docker run -d --rm --name tunnex-apifwd --network tunnex_default -p 8080:8080 \
  alpine/socat tcp-listen:8080,fork,reuseaddr tcp-connect:api:8080
```

If the dev server is gone:

```bash
cd apps/web && node_modules/.bin/vite --port 5180 --strictPort
```

## ⛔ APP_BASE_URL must equal the origin you browse

`.env` now reads `APP_BASE_URL=http://localhost:5180` (it was `http://localhost`, which pointed at
the nginx that is not running). This one value decides **three** things that must agree, or the
round-trip breaks in a way the error message will not explain:

1. the `redirect_uri` the API sends to the IdP,
2. the URI the IdP validates against its own registration,
3. where the callback drops the browser afterwards.

Changing it requires recreating the API: `docker compose up -d --no-deps api`.

## 1. Register the app in Entra

Azure Portal → **Microsoft Entra ID** → **App registrations** → **New registration**.

- **Supported account types:** *Accounts in this organizational directory only* (single tenant).
  ⚠ Choosing a multi-tenant or personal-accounts option means **any** Microsoft account can complete
  the callback — see the JIT note at the bottom before picking one.
- **Redirect URI:** platform **Web**, value exactly:

  ```
  http://localhost:5180/api/v1/auth/sso/microsoft/callback
  ```

From **Overview**, copy the **Application (client) ID** and the **Directory (tenant) ID**.
From **Certificates & secrets** → **New client secret**, copy the secret **Value** (not the Secret
ID — the Value is shown once and never again).

## 2. Write the config into the local stack

The shipped way to configure SSO is `PUT /api/v1/organizations/{orgId}/sso/{provider}`, but
`requireSSOAdmin` gates it on the SSO entitlement and a laptop stack runs Community — that endpoint
answers `403 edition_required`. `cmd/dev-sso-config` writes the identical row, sealing the secret
under the master key exactly as `sso.ConfigService.Set` does. It skips the admin-config gate and
**nothing else**: the redirect, PKCE, nonce, state and callback all run shipped code.

```bash
TUNNEX_SSO_ORG_SLUG=demo \
TUNNEX_SSO_PROVIDER=microsoft \
TUNNEX_SSO_CLIENT_ID='<application-client-id>' \
TUNNEX_SSO_TENANT_ID='<directory-tenant-id>' \
TUNNEX_SSO_CLIENT_SECRET='<secret-value>' \
make dev-sso-config
```

The secret travels by environment, never by flag — a flag lands in shell history and in the process
table where any local user can read it with `ps`. The command echoes the `redirect_uri` it expects;
if that string is not character-for-character what you registered in Entra, stop and fix it now.

## 3. Give your Entra identity a local account

**This step is only needed because the stack is unlicensed, and skipping it produces a confusing
403 at the very last hop.** On callback, `DecideLink` sends an email it has never seen to
`LinkCreate`, which calls `mayOnboard()` — false on Community — so a brand-new SSO identity is
refused with `edition_required`. An email that already exists **and is verified** takes `LinkAttach`
instead, which has no licence gate.

Substitute your real Entra sign-in address:

```bash
docker compose exec -T postgres psql -U tunnex -d tunnex -v ON_ERROR_STOP=1 <<'SQL'
\set email 'you@yourcompany.com'
WITH u AS (
  INSERT INTO users (email, name, email_verified_at)
  VALUES (:'email', 'SSO Walk', now())
  ON CONFLICT (email) WHERE deleted_at IS NULL
  DO UPDATE SET email_verified_at = COALESCE(users.email_verified_at, now())
  RETURNING id
)
INSERT INTO memberships (org_id, user_id, role)
SELECT '01900000-0000-7000-8000-000000000001', u.id, 'member' FROM u
ON CONFLICT (org_id, user_id) DO NOTHING;
SQL
```

The membership row is not strictly required — `ensureMembership` would create one — but adding it
keeps the walk's subject separate from the JIT path you are not trying to test here.

## 4. Walk it

Open <http://localhost:5180/login>.

1. There is **no company / organization field**. That is the change.
2. Click **Continue with Microsoft** → straight to `login.microsoftonline.com`.
3. Authenticate → back to `/api/v1/auth/sso/microsoft/callback` → session cookie set → land in the app.

### Verifying the org was derived, not typed

```bash
curl -s "http://localhost:5180/api/v1/auth/sso/microsoft/start" | head -c 200
```

No query parameters at all, and a real Entra authorize URL comes back. The server resolved the sole
org with `microsoft` enabled.

## The three fail-closed cases

| Case | How to produce it | Expected |
| --- | --- | --- |
| Nobody configured it | `curl .../auth/sso/microsoft/start` before step 2 | `404 sso_not_configured` |
| Exactly one org | after step 2 | `200` + authorize URL |
| Two or more orgs | see below | `400 sso_org_ambiguous` — refuses to guess |

Arming and disarming the ambiguous case (`demo-sandbox` is the second seeded org):

```bash
# arm — copies the demo org's config onto a second org
docker compose exec -T postgres psql -U tunnex -d tunnex -c \
  "INSERT INTO sso_configs (org_id, provider, client_id, client_secret_sealed, secret_fingerprint, tenant_id, enabled)
   SELECT '01900000-0000-7000-8000-000000000021', provider, client_id, client_secret_sealed, secret_fingerprint, tenant_id, true
   FROM sso_configs WHERE provider='microsoft'
   ON CONFLICT (org_id, provider) DO UPDATE SET enabled = true;"

# disarm
docker compose exec -T postgres psql -U tunnex -d tunnex -c \
  "DELETE FROM sso_configs WHERE org_id='01900000-0000-7000-8000-000000000021';"
```

While armed, the login page reveals the organization field with "Press Enter to continue" — the
escape hatch for the one case a human genuinely has to disambiguate. Type `demo-sandbox`, press
Enter, and the flow proceeds against that org's credentials.

## ⚠ Read before pointing this at a shared tenant

Dropping the org field widens an exposure that already existed. `resolveUser` → `LinkCreate` mints a
user for an unknown email and `ensureMembership` grants it **`member`** in the org it authenticated
against, gated only by the licence. `domain_claims` exists in the schema but is wired to invites
only — never to SSO. Microsoft configs pin `TenantID`; **the Google path has no `hd` equivalent**.

Previously an attacker had to guess the org slug — a weak barrier, since `org_not_found` already
enumerated it. Now `GET /auth/sso/google/start` with no parameters returns a working authorize URL.
The real boundary was always whether the IdP app is single-tenant/internal or external. Keep the
Entra registration **single tenant** for this walk.

## Putting it back

```bash
docker rm -f tunnex-apifwd
docker compose exec -T postgres psql -U tunnex -d tunnex -c \
  "DELETE FROM sso_configs WHERE provider='microsoft';"
# .env: restore APP_BASE_URL=http://localhost   (a .env.bak was written beside it)
docker compose up -d --no-deps api
```

# Secondary native SSO console

This nonshipping adapter uses only the exact owned project/checkout and the
`APP_ACCESS_SSO_CONSOLE_FIXTURE=1` gate. It serves the existing read-only web bundle
on `sso-console.127.0.0.1.sslip.io:15190` and forwards `/api/` to the normal
secondary CP fixture at `aa8-sso-cp-fixture:15189`. Its aliases include
`app-sso-console-fixture` and `aa9-sso-console` for the fixture's trusted-peer
configuration. Unknown Host is refused. TLS remains TLS1.3 and forwarding has no
environment proxy.

The seven-day, single-SAN leaf lives under private `.runtime/aa9-sso-console` and
was signed by the already-existing development CA using its signing tool. The CA
key was not read by the agent, no CA serial file was written, and no global trust
installation was performed. The main application/console leaves and private
gateway/authority enrollment CA are separate and remain unchanged.

The optional app-proxy console override exists only in the owned `_test` fixture.
It accepts exactly `https://sso-console.127.0.0.1.sslip.io:15190`; default remains
the original console15180. The guarded proxy runner passes that fixture-only
environment value. Reverting requires stopping the exact owned proxy, restoring
the retained final baseline binary, and rerunning with the override unset.
Compare the private rollback manifest's original certificate/credential hashes.
Stop the secondary adapter through its owned wrapper after proof collection as
coordinated by the parent; do not remove primary identity or trust files.

Normal browser SSO proof is owned by the authority lane. The fake identity
provider supplies deterministic owned claims, so rendered qualification is local
fixture evidence rather than proof of Google or another external provider.

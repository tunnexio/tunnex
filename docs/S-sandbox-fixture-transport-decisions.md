# Private fixture API transport

The source API's ordinary router currently serves HTTP while its separate agent
channel serves mTLS. The approved isolated fixture needs HTTPS bootstrap without
adding another control container. Add optional operator certificate/key file
configuration to the existing standard net/http public server. Both must be
supplied together; a partial pair fails startup before bootstrap. Default
existing deployments keep their current reverse-proxy profile. Fixture HTTPS
uses private container8443 and the normal agent channel private9443. Generate
fixture certificates only under task state; validate them with an explicit
client CA and IP SAN. No TLS verification bypass, host trust-store write,
existing listener change or hosted inference component.

A qualification availability override must be limited to the new private fixture
DB and one explicit fixture organization. It is not a deployment readiness flag.
Require a fixture database name prefix and exact fixture org; reject mismatches
before startup. Limit create/bootstrap to that org and one sandbox. Existing CP
and ordinary deployments keep the absent/closed availability default. This lets
normal source enrollment/router be exercised privately without making an
unfinished product available to existing users.

Fixture setup uses a separate task command, never a production bootstrap path.
It accepts private JSON on stdin, refuses non-qualification database names and
any existing application schema, migrates the fresh database, and seeds exactly
two organizations/creators with one-sandbox quotas, one immutable 128MiB image
template and two inert instruction revisions. A new task-only CA and gateway
credentials are issued through the existing single-use join-token service and
stored exclusively as new mode0600 fixture files. Public identifiers are the
only stdout output. No existing CP credential file or CA is copied. Partial
setup refuses automatic reseeding; explicit recovery is required.

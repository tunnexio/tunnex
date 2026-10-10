# Normal API enrollment

`enroll-local.py` operates only on `http://127.0.0.1:48083`, the explicit `azure-s2s-local` organization and the `browser-owner@azure-s2s.local` local role fixture. It does not contact Azure or seed gateway capabilities/status. Runtime credentials and the join token remain under a private `.runtime` directory.

1. Run `python3 tests/azure-s2s-local/enroll-local.py prepare --private-root /absolute/owned-lab/.runtime` after local owner/admin/member fixtures exist. This creates the owned Site, enables the org IPsec opt-in through revision CAS, and issues a normal gateway join token only when the named gateway and private token file are absent.
2. Start the reviewed native gateway with `TUNNEX_NODE_NAME=azure-local-native-gateway` and `.runtime/gateway.env`. Use the lead-owned Azure Compose project. Keep its state volume and original CP access intact.
3. Run the script with `bind` and the same private root after actual enrollment. It binds the active gateway and approves local prefix `10.241.10.0/24` through normal owner APIs. Actual daemon capabilities must arrive from the gateway's normal policy report.

An existing token is never printed or silently replaced. If it has expired, investigate the owned enrollment state before deliberately issuing a replacement. The script does not install a licence or alter accounts. API entitlement failures remain explicit blockers.

For the separately owned Azure cloud CP, generate credentials **on that machine** with `prepare-accounts.py --private-root /opt/azure-s2s-lab/.runtime`; do not transfer the Mac's `ui-accounts.json`. The reviewed `ui-fixture-linux-amd64` helper reads only `AZURE_LOCAL_FIXTURE_DSN` and `AZURE_LOCAL_FIXTURE_ACCOUNTS` from its private execution environment, checks the database/user ownership and refuses account resets. It creates explicit local test identities, not gateway capabilities or status.

Use the same normal API helper against the peer's localhost48083 CP with `--site-name 'Azure owned cloud qualification site' --node-name azure-owned-cloud-gateway --local-prefix 10.232.1.0/24` for both prepare and bind. The lead transfers reviewed files and operates the owned cloud host through the authorized Azure bastion; these helpers never run Azure commands.

`qualify-http.py` tests disabled configurations through the owner/admin/member HTTP sessions, including nonsecret readback, unknown health, shared-key maintenance, stale CAS and finalized cleanup. Its synthetic public endpoint fixtures are never enabled. Pass the independently verified running CP source as `--api-source`; the helper cannot infer binary provenance. Its private evidence file contains only key-free results and owned identities. This qualifies API behavior, not Azure tunnel traffic or cloud topology.

# Normal API enrollment

`enroll-local.py` operates only on `http://127.0.0.1:48083`, the explicit `azure-s2s-local` organization and the `browser-owner@azure-s2s.local` local role fixture. It does not contact Azure or seed gateway capabilities/status. Runtime credentials and the join token remain under a private `.runtime` directory.

1. Run `python3 tests/azure-s2s-local/enroll-local.py prepare --private-root /absolute/owned-lab/.runtime` after local owner/admin/member fixtures exist. This creates the owned Site, enables the org IPsec opt-in through revision CAS, and issues a normal gateway join token only when the named gateway and private token file are absent.
2. Start the reviewed native gateway with `TUNNEX_NODE_NAME=azure-local-native-gateway` and `.runtime/gateway.env`. Use the lead-owned Azure Compose project. Keep its state volume and original CP access intact.
3. Run the script with `bind` and the same private root after actual enrollment. It binds the active gateway and approves local prefix `10.241.10.0/24` through normal owner APIs. Actual daemon capabilities must arrive from the gateway's normal policy report.

An existing token is never printed or silently replaced. If it has expired, investigate the owned enrollment state before deliberately issuing a replacement. The script does not install a licence or alter accounts. API entitlement failures remain explicit blockers.

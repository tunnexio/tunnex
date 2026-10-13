# Local IPsec/BGP development control plane and gateway

Run `sh tests/ipsec-bgp-local/prepare.sh`, then `sh tests/ipsec-bgp-local/run.sh up -d --pull missing`, then `sh tests/ipsec-bgp-local/verify.sh` from this feature checkout. Preparation compiles current API and gateway source and builds the production node runtime from explicitly staged source inputs. Only public image/source/package dependencies are downloaded. No AWS resources, remote deployment or Git push is involved.

The local Colima Unix socket is explicit. A dedicated project and external volumes/network use exact resource and checkout ownership guards. Existing recorded resources must retain identity. The API bootstraps its own organization and one gateway grant; gateway enrollment and subsequent control use the real API and mTLS. Both database migration cleanliness and active gateway identity/certificate/heartbeat are asserted.

API: http://127.0.0.1:18283; mTLS: loopback 18646; gateway readiness: http://127.0.0.1:19293/readyz. Gateway NET_ADMIN/NET_RAW and TUN are restricted to its disposable container namespace. WireGuard and firewall are real. AI setup is disabled.

Private credentials, bootstrap logs, runtime binaries and build evidence stay in ignored `.runtime/`. Never publish these files or raw first-boot logs. `.runtime/build.txt` captures source HEAD/branch, exact Go1.26.8, native architecture, immutable image and separate image-internal versus mounted serving binary/source digests. The local gateway actually executes `/binaries/tunnex-node`; its production image also independently contains `/usr/local/bin/tunnex-node`. Preparation compiles `.next` files with the validated cached toolchain and publishes by atomic rename only after image/source checks pass. This starts the existing static-capable product gateway; BGP runtime and dual-peer packet qualification are subsequent stories. IPsec/BGP capability must be checked separately from gateway readiness.

The existing Site-to-site UI is unchanged by this fixture. For a Vite preview use an isolated dependency installation and `TUNNEX_DEV_API=http://127.0.0.1:18283`.

## Disposable database qualification

`python3 tests/ipsec-bgp-local/test-database.py --run 'Test(BGP|AWSStatic|Connections)'` compiles the current API package's Linux test binary and runs it inside a fresh container on this fixture's owned network. The admin endpoint names the PostgreSQL maintenance database; integration tests create and clean up their own disposable child databases. The helper never gives tests the serving database URL. `--package ./db` and `--package ./internal/testpostgres` are also supported. Private evidence captures results and asserts serving database schema, migration state and stable identities unchanged; routine gateway telemetry is intentionally excluded. PostgreSQL's randomized dump restriction-key metadata is normalized before hashing, leaving actual schema content intact.

After tests pass, `sh tests/ipsec-bgp-local/rebuild.sh` compiles current API/node binaries and restarts only this project's API and gateway. Run `verify.sh` after readiness returns. This preserves fixture volumes and real enrollment. This helper retains the captured runtime image; packaging changes require a new `prepare.sh` build and gateway recreation on the resulting immutable image.

## Browser fixtures

`python3 tests/ipsec-bgp-local/prepare-ui.py` creates two new synthetic accounts, `bgp-owner@example.test` and `bgp-member@example.test`, using the product's Argon2id password library. Both use normal native login and sessions. The helper refuses to reset an existing mismatched fixture, grants no CP admin, and checks the entire bootstrap/other-user row digest remains unchanged. Passwords are stored only in ignored mode-0600 `.runtime/ui-accounts.env`.

The owner uses normal authenticated APIs with the shipped client's CSRF header to create `BGP UI local site`, bind the real owned gateway, advertise/approve `10.10.0.0/24`, and enable IPsec settings. The member's normal session can inspect the site. IDs and nonsecret acceptance evidence are in `.runtime/ui-proof.json`. This synthetic UI topology is separate from the AWS workload qualification.

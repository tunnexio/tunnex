# Optional cross-gateway client connectivity

Status: implemented on `feature/gateway-update`, with isolated PostgreSQL integration tests, 20 real Linux traffic cases, and the authorized AWS sandbox functional checks below passing. The sandbox control plane and both gateways run the feature build.

## Requested behavior

Clients connected to different gateways in the same organization can communicate when an administrator enables an optional setting. The setting defaults to disabled. Existing unrelated local work and stashes remain untouched.

The subject set includes human devices and enrolled non-human agent devices, as both sources and destinations. Cover human-to-human, human-to-agent, agent-to-human, and agent-to-agent flows. Use authoritative active network identities rather than human-only device listing queries. Enrollment alone grants no access; agent lifecycle, suspension, revocation, and credential rotation remain authoritative.

## Verified implementation boundaries

- `apps/api/internal/nodes/service.go`: ordinary device peers are loaded for their assigned node. Site-link topology carries remote site subnets, with primary-only pool routing on spokes. It does not supply a general client-address ownership graph between arbitrary gateways.
- `apps/api/internal/devices/config.go`: split-tunnel clients already route the organization IPv4 pool into their tunnel. IPv6 requires the client's existing IPv6 tunnel configuration.
- `apps/api/internal/policy/compiler.go`: mode off produces mesh acceptance; enforcing mode resolves explicit device grants. Cross-gateway transport must reconcile both source and destination enforcement placement.
- `apps/node/internal/nodepolicy/nodepolicy.go`: the node mirrors the control-plane artifact and gates unsupported policy versions. Any new enforcement field needs mirrored semantics and version refusal coverage.

## Implemented narrow scope

Organization-scoped, admin-only, persisted opt-in with an audit event. No cross-organization reachability. Remote client prefixes must have a unique current gateway owner, preserving local peer ownership and existing site/Kubernetes routes. Disabled, revoked, reassigned, and deleted clients must withdraw routes and permissions through reconciliation. A missing or invalid setting must not enable the feature.

Topology design must handle site-less gateways, same-site gateways, reachable endpoints, NAT constraints, and HA ownership explicitly. Do not claim connectivity where no viable carrier exists. Do not assign the entire organization pool to multiple remote WireGuard peers.

## Accepted permission semantics

Enabling the setting provides cross-gateway transport while preserving the existing Zero Trust mode and rule semantics. In enforcing mode, only explicitly authorized flows are allowed. The setting must not switch enforcing mode to mesh or synthesize blanket grants. Mode-off behavior remains governed by the existing mesh policy once cross-gateway transport is enabled.

## Acceptance proof before completion

1. Default and explicit disabled setting produce no new cross-gateway access.
2. Only an authorized organization administrator can change the setting; tenant boundaries are enforced.
3. Enabled state creates deterministic source and return paths for two clients on different gateways, without stealing local client prefixes.
4. Enforcement behavior matches the chosen permission semantics on both gateways.
5. Disabling, revoking, and moving clients withdraw stale access and routes, including established flows where required.
6. Existing site, Kubernetes, HA, and same-gateway behavior remains covered.
7. Test supported client transports and IPv4/IPv6 explicitly; record any unsupported combination in the UI and result.
8. Actual two-gateway traffic proof is required for a live-connectivity claim; pure projection tests alone are insufficient.
9. Exercise all four human/agent source-destination combinations, including default-deny, explicit allow, suspension/revocation, and reassignment; human-only list filters must not silently exclude agents from topology.

Implementation sequence: settle permission semantics, write failing regression coverage, implement persisted setting and API/UI, project ownership routes and enforcement, run focused tests, then verify the rendered UI and available traffic harness. No live host or database changes without authorization.

## Security and reconciliation details

- Grants follow the existing human/agent identity and rule evaluator. The source gateway, destination gateway, and intermediate relay enforce the same permitted tuple.
- IPv4 resource and FQDN grants retain their exact address scope. Group identity grants can expand to the same active identity's allocated IPv6 address; an IPv6 address grant remains explicit. FQDN generation provenance travels to all enforcement gateways for withdrawal.
- Revoked memberships are filtered from both the cross-gateway graph and the existing local WireGuard/OpenVPN peer and policy subject queries. Active user/device status, agent suspension, health blocks, membership removal, and reassignment remain authoritative.
- Carrier peers remain warm with empty AllowedIPs when a gateway temporarily has no clients. Empty AllowedIPs authorize no source or destination address; retaining the session lets an unadvertised spoke accept a returning client without waiting for WireGuard rekey.
- Desired state, health reporting, and desync tracking finalize the same graph, including gateways without a site. Matching applied artifacts must not produce false policy-desync reports.

## Verification

- Full API Go suite passed with database environment variables unset. Feature-specific database tests were then run against fresh, labelled, tmpfs-only PostgreSQL 16 containers; unrelated database suites were not run.
- Database proof covers default-off migration 0166 and down/up, tenant isolation, transactional audit rollback, concurrent setter audit ordering, human/agent lifecycle and membership revocation, and served-versus-reported policy hashes for site-less gateways. Final passing project: `tunnexgatewaydb84ccb9cee6`.
- Node policy, OpenVPN, reconcile, and Linux egress tests passed. The live fixture additionally uses real Linux WireGuard, OpenVPN, routes, nftables and conntrack with production reconciliation code.
- All four human/agent source-destination combinations passed in each row below. Checks include default-off, enforcing default-deny, explicit TCP allowance, a listening but forbidden port, denied reverse direction, established-flow grant withdrawal, disable/re-enable, device revocation, and missing-carrier denial.

| Transport | Topology | Cases | Local evidence project |
| --- | --- | ---: | --- |
| WireGuard → WireGuard | Two gateways and unadvertised spokes via a relay | 8 | `tunnexgatewaywire4f7e156b1b` |
| OpenVPN → OpenVPN | Two gateways | 4 | `tunnexgatewaywire252bd261f7` |
| OpenVPN → WireGuard | Two gateways | 4 | `tunnexgatewaywirea18f7a7033` |
| WireGuard → OpenVPN | Two gateways | 4 | `tunnexgatewaywire07d5febac4` |

- WireGuard cases also passed IPv6 allowance/forbidden-port checks and client move-and-return between gateways. OpenVPN and mixed cases were qualified over IPv4; live movement was qualified for WireGuard.
- Web typecheck and focused settings suites passed (46 tests, 2 existing expected failures). The actual component was rendered with mocked saves and inspected off, on, failed-save, and read-only.
- Final publication checks passed: full API Go suite (database variables unset), node policy/reconcile/OpenVPN packages, CLI API package compilation, web typecheck, production build, and all 145 web test files (1,787 passed, 2 existing expected failures).
- Default-off mutation was caught by regression tests. Retained-membership revocation, address/FQDN scope, and site-less health regressions were observed failing before their fixes.
- Reproducible harnesses and commands: [cross-gateway qualification](../deploy/testing/cross-gateway/README.md). Public local evidence is under ignored `.gateway-update-proof/`. Fixture containers and networks were removed after each run.

## Rollout constraints

- Upgrade participating gateways before enabling the setting: cross-gateway artifacts require protocol v10. Default-disabled artifacts retain their content-derived older versions.
- WireGuard receives exact IPv4 and already allocated IPv6 host prefixes; OpenVPN remains IPv4-only. IPv6 needs an existing client tunnel route. No standalone client application change was necessary or added to this repository.
- At least one configured, reachable WireGuard endpoint is needed as carrier. Selection is deterministic and follows existing HA ownership where configured. No new endpoint probing or site-less relay failover controller is introduced.
- The live relay fixture removes advertised spoke endpoints and verifies outbound-established WireGuard sessions. It does not emulate an internet NAT appliance. Tests use synthetic enrolled identities and transport endpoints, not the native client UI or a fully deployed control-plane enrollment flow.
- Live grant withdrawal was verified while gateway reconciliation was running. This does not extend the existing generic conntrack recovery contract for grants removed while a gateway agent is stopped.
- The AWS sandbox rollout was explicitly authorized after local qualification. General production rollout remains separate from this sandbox proof.

## AWS sandbox verification — 2026-10-03

The participating gateways were in different VPCs and ran the updated gateway binary with policy protocol v10 support. Tests used VPN addresses. Packet headers captured on both gateways confirmed the agent-to-agent and human-to-agent paths; sharing a VPC between test endpoints did not bypass the gateway path.

| Flow | Evidence | Result |
| --- | --- | --- |
| Human → human, both directions | User verified WireGuard ping and IP webcam access, including cross-gateway enable/disable | Passed |
| Agent → human on the other gateway | Live ping and webcam HTTP response, status 200 | Passed |
| Agent → agent, both directions | Live ping and HTTP; policy-free baseline denied; feature off blocked both directions and re-enable restored access | Passed |
| Human → agent on the other gateway | A fresh temporary human WireGuard profile initiated ping (3/3) and HTTP (200 with expected body); both gateways observed matching traffic; removing the temporary rule blocked new ping/HTTP requests | Passed |
| Authorized human AI access through either gateway | Two temporary human profiles belonging to the granted group each received HTTP 200 and the expected model reply | Passed |

The final human-to-agent test ran the human profile in an isolated network namespace on the bastion. It verifies the human identity and gateway data path, not a native desktop-client UI. Its temporary user-level rule was explicitly approved, then deleted immediately after the successful test. The listener was still active when policy denial was verified and was subsequently stopped. Both enrolled agent services remain active.

The AI requests used each user's own gateway AI relay to reach the central model. This proves authorized access from either gateway; it does not prove an AI request traverses the gateway-to-gateway client mesh. An AI group-denial test and AI behavior with the cross-gateway client option disabled were not exercised here.

The temporary AI and human-to-agent profiles were revoked and removed. Their namespace tunnels, private configuration files, and temporary HTTP servers were removed or stopped. Existing enrolled devices and unrelated access rules were preserved. Earlier agent-to-agent grants retained their original expiry; expired human-to-human test grants were not renewed.

Local evidence files are ignored under `.gateway-update-proof/`: `agent-human-live-20261003.json`, `agent-agent-live-20261003.json`, `human-agent-live-20261003.json`, `human-agent-gateway-captures-20261003.json`, and `ai-multi-gateway-live-20261003.json`. They are not included in the published source.

These are functional qualification results. AWS gateway restart, failover, scale/load, native-client gateway selection, and video playback/frame inspection were not covered by this live test run.

## CI schema compatibility repair

The first PR run exposed a historical-schema dependency: IPsec range validation read the complete generated organization row, which now requires migration 0166's column, while the IPsec migration tests intentionally use schemas 0160–0162. Range validation now reads only `pool_cidr`, retaining the organization and soft-delete filters. Dedicated historical IPsec tests remain pinned; tests invoking current application writers migrate their disposable fixture to the current schema before using complete organization projections.

The original provider-create failure was reproduced locally before the fix. The initial focused database run reported 97 top-level passes with no failures or skips, including IPsec, affected HTTP tests, and a pool-read regression. However, the next CI run exposed a flaw in that regression: `pool.Config().ConnString()` retained the original admin DSN after the fixture copied its pgx configuration. The regression downgraded the shared CI database to schema 0160, while its own database stayed current. Its claimed historical coverage was therefore invalid, and later tenancy tests failed. The earlier database-free API run and focused fixture run did not expose this shared-database side effect.

Historical fixtures now use `testpostgres.NewAtVersion`, which migrates only the generated, owned database URL before opening its pool. The pool-read regression asserts the actual historical schema version, and a separate nested-fixture regression verifies that creating and cleaning up the historical child preserves its parent's current schema. Existing IPsec and node migration fixtures construct their pools from explicit child URLs and do not use the copied-config pattern.

The corrected fixture passed the full API build and serial test sequence in both open and enterprise editions using `deploy/test-api-edition.sh` with `API_TEST_SHARD=all` and an explicit test database endpoint. Each edition passed all 74 test-bearing packages, including `subnetsrc`, `testpostgres`, and the previously failing `tenancy` package. The shared database remained at version 166 with `dirty=false` after each run. These were local Go runs against owned PostgreSQL 16 containers, not a claim about the next remote CI result. An initial enterprise attempt exhausted the temporary fixture's storage after reusing the open run's PostgreSQL instance; the complete enterprise rerun passed on a fresh fixture with bounded WAL. All owned test containers and networks were removed. Local logs remain ignored under `.gateway-update-proof/ci-shared-open.log`, `ci-shared-enterprise.log`, and `ci-enterprise-qualify.log`.

The first AI qualification failure came from the IPsec HTTP tests; its native model suite had passed. A separate visual job initially failed while downloading pnpm with a connection reset and passed on the next run without a code change.

# Azure Site-to-site UI qualification

## Local implementation

The existing connection chooser, two-step IPsec form, stored configuration summary, status tables, theme and responsive workspace are reused. Four Azure profiles preserve routing/topology explicitly. Active-standby drafts carry transport version 1 and one tunnel; active-active drafts use two tunnels. Azure BGP uses one customer APIPA /32 shared across both active-active interfaces and distinct Azure peer addresses. Active-active static and BGP configurations share one Azure connection PSK. Static inside addresses are labelled Tunnex runtime allocations, rather than Azure assignments.

Bounded 64 KiB Tunnex Azure JSON file import checks the profile, topology, complete gateway contract, approved local network ranges and common validation API before prefilling component state. It does not save or enable a connection. Native Azure exports are unsupported. PSKs stay in masked component fields, are not logged, and disappear on cancel/authority changes. Stored readback and settings-review export select explicit nonsecret fields. Azure key maintenance uses one shared input and submits the same new key to all verified tunnel IDs, only while disabled and with the current desired revision.

## Local verification

- Focused IPsec/workspace/health/site/security/rotation tests passed, including four Azure creation contracts, one-peer truthful health, unsupported-capability gates, bounded import, secret-free review export and shared Azure rotation.
- Shared AWS/GCP/Azure receipt checker regressions: 21 passed. These are synthetic offline checker fixtures and do not certify any cloud.
- Full TypeScript check and Vite production build passed with provider generated schema and isolated frozen-lockfile dependencies on host Node 24.19.0. The repository requests Node >=24.21.0 <25. Exact Node 24.21.0 Docker install and compiler attempts exited 137 without compiler diagnostics, including a bounded-heap retry. No exact-engine pass is asserted.

## Actual browser evidence, 2026-10-10

The owner signed in through the normal UI on isolated UI 45173, proxying owned API 48083. The real normally enrolled gateway and approved 10.241.10.0/24 appeared in the form. The owner created `Azure browser owner static` as disabled and opened its persisted Azure contract: VpnGw1AZ, route-based IKEv2, explicit custom policy, active-active topology, NAT/policy-based selectors disabled. Both tunnel rows remained Unknown; no applied configuration or fixture status was treated as Up. The test endpoint addresses were synthetic and the connection was never enabled, so this is local UI/API proof only.

The public settings-review link content was inspected through its DOM href: two peers, no PSK field and no draft secret. Waiting for a real IAB download event timed out after 10 seconds; actual download delivery remained unverified at that point.

At a 390 x 844 viewport, document width was 390 and modal width 366. The existing modal scrolled vertically, its Cancel and Next controls remained reachable, and no horizontal document overflow occurred. Screenshots are kept outside Git at `/private/tmp/azure-s2s-ui/evidence-ui/`.

During continuation, API 48083 briefly became unavailable. The UI showed unavailable/Unknown status and blocked import without gateway/range readiness. After the lead restored the CP, the owner selected the real approved network and normally enrolled gateway again; the form visibly reported “Gateway supports storing this configuration.”

The subsequent owned JSON file-chooser operation did not finish before interruption. A fresh observation reported the selected IAB browser unavailable; browser inventory exposed only the Chrome extension, and recreating an IAB tab also reported unavailable. No imported draft was saved or enabled. Actual import, admin/member browser acceptance and download delivery remain unverified because the selected browser surface was unavailable. API role qualification reported by the provider is separate evidence and does not substitute for these browser paths.

The authorized Chrome fallback subsequently completed normal admin and member login. Both roles opened the owner's stored static Azure contract and saw two Unknown tunnel rows. Admin had Create connection; member had no Create connection and its row action menu contained only Connection details, with no enable, rotation or deletion action. Actual download event and the supported file-link download alternative each timed out after 10 seconds in Chrome; delivery remains unverified. The admin selected the real gateway in a new Azure draft and correctly saw “This gateway does not support IPsec yet” at that report revision. A second file-chooser attempt also hung despite bounded timeouts and was interrupted. No imported draft was saved or enabled. Import remains blocked on browser tooling; later gateway capability fixes require a fresh browser qualification and are not inferred from API evidence.

## Forwarded actual cloud read-only browser acceptance

After the lead's genuine peer reboot, the private forwarded cloud UI at `http://localhost:45174` completed normal owner, admin and member sign-in against the actual cloud CP. All roles read the existing `Azure owned live active-active BGP` configuration: VpnGw1AZ, route-based IKEv2/custom policy, active-active topology, shared customer APIPA /32, NAT/selectors disabled. The inventory showed Cleanup pending and both IPsec/BGP tunnel rows were Unknown with no installed route, consistent with the runtime being stopped; historical cloud success was not shown as current Up.

Owner Settings → Licence & plan → Manage showed Community, No key installed and a disabled Install licence control with an empty key. Admin received View details with only Close and no key input. Member settings fell back to Authentication with no licence tab. Member had no Create connection control and the existing connection action menu contained only Connection details. No licence installation, trial acquisition, tunnel enablement or cloud configuration change was performed.

At the owner details viewport 390 x 844, actual document width remained 390. Screenshots `cloud-owner-community-licence.png`, `cloud-owner-details-mobile.png` and `cloud-member-details.png` are outside Git in the same evidence directory. The owned session logged out and its tab closed. The served cloud bundle predated the selector-label correction (it displayed AWS / Google Cloud despite functional Azure readback); final-source rebuilding remains required for that presentation fix. Read-only cloud acceptance does not complete import/download proof, live readiness, licence entitlement or application qualification.


## Exact-engine build follow-up

The web tree `b43750ee815f620a9383aca20e6f37c27e306c2c` is unchanged from earlier focused UI qualification and matches integrated source `e221`/the current Azure checkout. On 2026-10-10, the official Node `v24.21.0` Darwin ARM64 tarball was staged in a private temporary directory, with SHA256 `bed7eea5325e1108f32ce5228ddd6a5f0f08a499ee42aa7442aea583702f6057` verified against the official HTTPS `SHASUMS256.txt`. Its exact runtime executed `pnpm --filter @tunnex/web build` (`tsc -b && vite build`) successfully against this web tree and the current generated shared API schema. Vite completed in 5.07 seconds; its existing chunk-size advisory remains. The transient shared schema was restored after qualification and the checkout remains clean for tracked web/shared files.

This supersedes the earlier unresolved exact-engine build gate. The runtime and logs remain under `/private/tmp/azure-node2421-qualification`, mode 0700; no global installation or cloud UI deployment occurred. The corrected Azure navigation bundle is now locally built, but updating the served cloud bundle remains pending. Actual browser import and download delivery remain tooling-unverified.

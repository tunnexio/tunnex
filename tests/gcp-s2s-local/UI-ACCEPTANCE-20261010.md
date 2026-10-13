# GCP UI local browser acceptance — 2026-10-10

This receipt records owned local browser/API acceptance. It is not Google Cloud deployment or tunnel/DNS traffic proof. HA and Classic connections were saved **disabled** throughout these checks. No Enable action, application grant, or FQDN enforcement opt-in was performed.

## Source and environment

- Final UI source: `978bc7f76b95ca89f486bf8a58bdb6f2c047dd6a`, branch `gcp-s2s-ui`.
- Earlier DNS race fix: `6da17606`; integration base `0cf8dda1`, merged in UI as `0f276531`.
- Preview: `http://127.0.0.1:35173`; local CP API `http://127.0.0.1:38083`, mTLS `38446`, PostgreSQL `35440`.
- Compose CP project: `tunnexgcps2slocal1010`; genuine gateway container: `tunnexgcps2sgateway1010-gateway-1`.
- Organization ID: `01a124e7-60c7-78ca-aa85-d3a5025d9764`.
- Gateway ID: `01a124ff-7247-7f8d-8cf0-0fae3a59e695`; name `gcp-local-native-gateway`.
- Site ID: `01a12500-95ae-7728-b901-54f20df98cc1`; name `GCP local native Site`.
- Gateway was enrolled through normal join-token authority. Root reported genuine gateway sources moving from `c3c6b897` to `dd3256ed` and subsequently `625ff213` during local qualification; no synthetic database capability writes were used.
- Running CP schema was 224; root reported builds from `9a2bc6db` and later `c80ce265` as source changed during qualification. Per-flow timestamp/binary receipts were not persisted, so this document does not retrospectively assign an exact CP binary to each browser action. Do not infer CP binary provenance from the UI SHA.
- Existing role fixtures were used through normal login. Credentials and test PSKs are omitted. No browser password storage was requested.

## Actual browser checks

| Actor / path | Observed result | Scope |
| --- | --- | --- |
| Owner → Networks → Site → Ranges → Advertise subnet → Range approvals | Advertised and approved owned `10.70.0.0/24` | Routing approval, no application access grant |
| Owner → Create connection → Cloud VPN → Google Cloud → HA | Disabled save/readback; BGP, two actual tunnels, interface 0/1, approved remote `10.71.0.0/24` | Profile/configuration acceptance; public IP fields were inert test placeholders |
| Owner → Classic selector | Static routing, one actual tunnel, no BGP/inside fields; disabled save/readback for remote `10.72.0.0/24` | No invented second tunnel |
| Owner → Rotate keys | Actual Classic single-slot and HA two-slot changes accepted; draft secrets cleared, connections remained disabled | Key maintenance, no activation |
| Owner → Two normal browser clients → Rotate keys | Concurrent newer revision accepted; older HA and Classic submissions rejected; secret fields cleared/disabled and Save disabled | Actual server revision conflict, no mocked browser response |
| Admin → HA rotation | Existing real slot key change accepted, disabled state preserved | Actual admin mutation authority |
| Admin → Delete Classic review + concurrent normal-client rotation | Old deletion rejected. After UI fix, Delete remained disabled with close/refresh guidance | Actual stale deletion conflict; core connection preserved |
| Owner → Resources → FQDN → DNS configuration | Disabled connections absent from IPsec transport picker; activation unavailable | Honest IPsec binding refusal |
| Owner → DNS direct gateway profile | Google Cloud-labelled local test profile saved as version 1, state Configured; enforcement Off | Stored configuration, no Cloud DNS resolver reachability claim |
| Admin → DNS edit | Same endpoint configured separately for UDP/TCP port 53, version 2; Configured, enforcement Off | Existing resolver/profile API reuse |
| Member → Populated HA/Classic inventory/details | Readback available; no Create, Enable, Rotate or Delete; Classic menu contained details only | Real role UI/API read path |
| Member → Resources → FQDN / DNS | Explicit `fqdn_resource:view` permission refusal | Existing owner/admin-only DNS permission preserved |
| Mobile HA readback, 390×844 | Document width 390; no horizontal page overflow; desktop viewport restored | Local visual acceptance |

Core HA/Classic configurations and DNS version 2 remain available for inspection. Tunnel/IPsec/BGP evidence remained Unknown or no data; no Up state was fabricated. No actual Google Cloud endpoints, Cloud Router adjacency, Cloud DNS answers, or application packets were qualified by this browser run. Delivered-tunnel cleanup and enabled IPsec DNS binding require separate authorized runtime/lab evidence.

## Reproduced gaps and focused verification

- DNS: cancelled/reopened draft response for revision 4 overwrote a newer revision 5. The regression failed before the fix and passed after generation/selection guards. Transport changes, cancellation and profile removal invalidate obsolete revision callbacks.
- IPsec intent/deletion: stale or uncertain action errors instructed close/refresh but left the retry button active. Both failing regressions now pass; errored dialogs freeze retries without weakening server revision checks.
- Explicit HA/Classic rotation 409 regressions verify exact desired revision, cleared secrets, disabled retry and absence of an Enable write.
- Final DNS/rotation focused run: 2 files, 32 tests passed; TypeScript typecheck passed.
- Final intent/deletion/rotation/security focused run: 3 files, 78 tests passed; TypeScript typecheck and `git diff --check` passed.
- Before the additional rotation conflict cases, the combined DNS/workspace/rotation/health run passed 4 files, 138 tests.
- Runtime: Node 24.21.0; locked existing dependencies. These are component/API mocks where stated, separate from the actual browser checks above.

## Setup and troubleshooting wording audit

Current existing components retain the shared workspace. HA setup explicitly requires two endpoints on Google Cloud interfaces 0/1 with Cloud Router BGP and states that one local gateway provides neither host redundancy nor an availability SLA. Classic setup/troubleshooting specifies one route-based static tunnel, exact local/remote routes, cloud return routes and no BGP inside addresses. BGP peer state, installed routes, IPsec state and application reachability remain separate. DNS setup specifies same-region inbound server-policy addresses and conditional forwarding, UDP/TCP 53, approved ranges and return routes. No unsupported SLA or automatic access claim was found; no wording-only rewrite was needed.

## Screenshot integrity

Screenshots are local temporary artifacts, not committed binaries. Hashes identify the captured evidence; they do not prove cloud operation. All captured screenshots exclude test PSK values and login passwords.

| Local file | SHA-256 |
| --- | --- |
| `/private/tmp/gcp-ui-local-range-approved.png` | `d121ce9097df2d1d95541d3618f68381e688405cffc6d536e641157c0e15398c` |
| `/private/tmp/gcp-ui-ha-saved-unknown.png` | `1003804ef91c701953c2e1d83c35e6dd0e983a0cf01b3a73fd544497b2b7d021` |
| `/private/tmp/gcp-ui-classic-saved-unknown.png` | `3da599c4c542720b53e58555b760e65e271bbb24162c9fc561d84199ec303cd6` |
| `/private/tmp/gcp-ui-classic-rotation-success.png` | `6e165610f7eca25377195328c428d1debd46fdb139bf86c37754515a97d787e7` |
| `/private/tmp/gcp-ui-classic-real-cas-rejection.png` | `0a1a32c14640ccb81a54c684eccd3208463eafe2481594f3bf4b4a1524554f42` |
| `/private/tmp/gcp-ui-ha-real-cas-rejection.png` | `4be85dc492f6f4bca619dc2cc9499df7aa121dc1f47f88a83fc1534798548b1f` |
| `/private/tmp/gcp-ui-dns-disabled-connection-refusal.png` | `88d1d093ff53c4619ab7c86bd84ec80d3cd95910090e16d89ffc358569f62dd2` |
| `/private/tmp/gcp-ui-dns-configured-enforcement-off.png` | `8f853d39fc9c96f2e88e841ef65f00556957fe1e6f83e6a08fd9d55a40f90d49` |
| `/private/tmp/gcp-ui-admin-dns-version2.png` | `ba4425352c0ecfc9a4b1cae0a6432d0d351922c11cfd4fdc2b5982449338cd01` |
| `/private/tmp/gcp-ui-admin-ha-rotation-success.png` | `44d39b90543e008c9cfe155f1166c1e2de7390893424b98a8b6f85bb72d92d48` |
| `/private/tmp/gcp-ui-member-classic-readonly.png` | `552f291fdc0ed29fa54c2b121e5293fa487bddd4db266d0f5aac63a82341928b` |
| `/private/tmp/gcp-ui-member-dns-denied.png` | `83362070d929d3ad7d2f17e9f89e54475dd2fa6ff7976b36bc1eb6a5e3adc729` |
| `/private/tmp/gcp-ui-delete-cas-fixed.png` | `4acbc6e5a93ca96847dfd0134f248eac497e4ac517e7f60f35052b9234597b86` |
| `/private/tmp/gcp-ui-ha-populated-mobile.png` | `67d97cf7ef495bc2127b43af566b71129c557206beba6d40238f0643a0d14791` |

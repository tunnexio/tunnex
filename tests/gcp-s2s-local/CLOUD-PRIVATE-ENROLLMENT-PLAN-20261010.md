# GCP private enrollment preparation (not executed)

Parent review and final source/image freeze are required before enrollment or deployment. The existing cloud gateway is not enrolled. Both loopback-only SSH hops are live; ordinary API health returned200 and unauthenticated mTLS correctly required a certificate. The cloud ens4 /32 address versus routed /24 ownership question remains under runtime review; this plan does not waive native qualification.

## Normal join token and private delivery

After the licensed deployment-wide live-gateway slot is available, normal verified owner POST `/api/v1/organizations/{org}/nodes/join-token` with `X-Tunnex-CSRF: 1` and JSON `node_name` for the exact owned cloud gateway plus `enrols_kind: gateway`. Read the response privately into exclusive mode0600 storage; never print join_token. Deliver its bytes over SSH stdin to an exclusive root0600 file within a root0700 owned directory on the gateway, through the designated bastion and pinned gateway host alias. Refuse symlinks/existing files and preserve source artifacts. Do not place token bytes in CLI argv, shell history, logs or Git.

The node requires `TUNNEX_JOIN_TOKEN` in its private startup environment. Use a root0600 environment file consumed by the approved host-network container startup, with API_URL `http://127.0.0.1:38083`, AGENT_URL `https://127.0.0.1:38446`, AGENT_SERVERNAME `tunnex-control`, exact NODE_NAME, dedicated root0700 NODE_STATE_DIR and AGENT_HEALTH_ADDR `127.0.0.1:9091`. Enrollment normally creates stored mTLS identity; keep cert/key and enrolled CA inside the gateway. Later startup can use stored identity without resending the single-use token. Do not expose startup environment through inspect/logs.

## Site and pending history

Use normal Site binding for the new active gateway to existing approved70 Site. Migration0037 supports multiple gateway members; leave the revoked old member and cleanup-pending old Classic connection unchanged. Do not unbind the old gateway, synthesize cleanup or approve another overlapping70 Site. Normal eligibility must be queried for the new node after binding. Gateway enrollment limits count the entire deployment, not merely this organization.

## GCP configuration and PSK boundary

Load only the original owned tunnel-creation PSKs privately on the designated bastion. Validate exact ledger tunnel names, region, profile cardinality and peer address before constructing normal API create input. HA has exactly2 interfaces/tunnels with BGP /30 peer pairs; Classic has exactly1 route-based static tunnel and empty inside fields. Both use local approved70 and separate remote80/81 ranges. Save disabled first, then inspect secret-free readback/check/eligibility before normal enable. Do not generate replacement keys against existing cloud tunnels or export gateway authenticated material.

The existing `gcp-ha-peer-prepare.py --creation-request` path is for external emulator preparation, not a cloud enrollment or authority bypass: it validates canonical key-free manifest versus original creation identity/configuration and refuses rotated secret revisions. It must not be reused blindly for Classic fixed2-slot runtime wire, whose inactive slot must remain exactlyzero. Public saved configuration returns no PSKs.

No deployment, enrollment, Site binding, token issuance, configuration creation or cloud mutation has been performed by this plan. Private bastion PSK path/schema must be confirmed before preparing an executable payload loader.

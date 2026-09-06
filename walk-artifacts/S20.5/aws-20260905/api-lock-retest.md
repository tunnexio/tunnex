# API-only HA lock correction retest

API source `1da06bf521d8ca6dc8c7587f0a18052a0a77b7b6`, immutable private
ECR image digest `sha256:0c33825f3bb23f6e47e51da1cd88feeb3e3a06d98661bf85b5df70df791ab795`.
User explicitly approved this API-only workflow. Verified AWS account
735391218823 / aws-cli / ap-south-1, same ECR prefix. Linux/amd64 image
revision label matches source; published digest matches local image.

Four-connection PostgreSQL lock-inversion regression RED before fix;
both-edition focused PostgreSQL suite GREEN after fix, including achieved
maintenance and generation-during-prefetch refusal with no new authority.
Both native edition builds and scoped race tests PASS. Independent review:
no concrete P1/P2 findings. This is not full final gates or story-end review;
exact source SHA had zero GitHub check runs at publication.

Effective Compose comparison proves only API image reference changes. C7
gateway/node/chart/web/nginx components and existing bundle metadata remain;
host manager remains the explicitly restored C5 component. This mixed-version
targeted retest is not a unified final candidate. Original deployment env,
all stores, credentials, license, and other services are preserved.

Normal API-only deployment started. No remedial restart, session termination,
database setting increase, or row mutation used to mask the deadlock. Fresh
lease-renewal, HTTP/DNS, and failover results remain pending at this entry.

## Live result

Only API container changed, to `86d6642223a2`, healthy. All six other CP
container IDs match the pre-deploy snapshot. Database-backed HA status
returned 200 promptly. PostgreSQL no longer shows the idle-in-transaction
blocker: repeated samples show four idle application sessions and the
diagnostic query active, with no lock waits. A3 restored `10.99.0.0/24` on
the edge WireGuard peer and restored its two-backend DNAT rule automatically.

At 01:27:30 UTC, latest ownership delivery was 01:27:12, expiry 01:28:00.
At 01:32:08 UTC, latest delivery was 01:31:32, expiry 01:32:30. This proves
renewal continued across multiple 30-second lease periods, not merely one
healthy startup. No extra API restart or DB intervention occurred.

Local IP HTTP and FQDN requests still time out. A bounded read-only conntrack
diagnostic was copied to `/tmp/s205-conntrack-read-uznmaa` in existing A3/edge
pods; it only dumps connections matching the test VIP, without payloads or
network mutations. Binary/source remain in the task-local scratch directory.

Edge conntrack proves original `10.99.0.2:59009 → 100.96.0.3:8080`, but
reply tuple is `100.96.0.3:8080 → 10.240.10.204:16190`: source NAT to the
edge host address occurred. A3 has no corresponding conntrack entry. Live
AWS chain exemption is only `ip daddr 10.99.0.0/24 oifname wg0 return`;
the Service VIP `100.96.0.3` misses it and reaches the terminal AWS SNAT.
Thus the API deadlock correction holds, but gateway-to-gateway Service
transit needs a separately verified CNI exemption correction. Do not broaden
WireGuard AllowedIPs or manually repair iptables to conceal it. End-to-end
and failover acceptance remain BLOCKED; no PR or merge.

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

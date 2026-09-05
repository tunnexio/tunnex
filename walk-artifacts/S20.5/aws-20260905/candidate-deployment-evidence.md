# S20.5 — private candidate publication and retained CP deployment

2026-09-05 checkpoint. Source: `d2c9cba653d400e2dab3d7b038796efeee1f028c`.
Private candidate version: `0.0.0-walk.shad2c9cba653d400e2dab3d7b038796efe`.
This record contains selected nonsecret publication receipts and the executing
operator's verified CP readbacks, not credentials or private runtime paths.

## Six-image publication completed

After the earlier upload refusal, the user explicitly approved this exact
six-image payload, including the enterprise API, to the task's private ECR
repositories. Fresh account/principal and immutable repository checks passed;
the candidate tags were absent before upload. All six push and ECR readback
exit codes were zero. Receipt verification time: `2026-09-05 12:55:34 UTC`.

Account `735391218823`, region `ap-south-1`, principal
`arn:aws:iam::735391218823:user/aws-cli`. Each repository below is under
`735391218823.dkr.ecr.ap-south-1.amazonaws.com/tunnex-s205-aws-20260905a/`.
All images were built from the same clean detached source and contain the
linux/amd64 platform. These are the ECR OCI image-index digests, not config or
platform-manifest digests; deploy with the repository name plus `@sha256:…`.

| Repository suffix | Published immutable digest |
|---|---|
| api | `sha256:d6602984cc7af9be86461715685c0ef8b9f19a7a026fc52e49ecca1cd84eca61` |
| web | `sha256:51563b8c503a41ae840a70c6f010773936f45d2ef964aff1c1dfb7105891df7b` |
| nginx | `sha256:9cdc987e635ec0b99bf5400fbbad83542ed5cd1e660281b85c7fa7a556296065` |
| migrate | `sha256:0279b55fa58ab4b6eea0ceddda3a057c05acf2a9bc948051eb3aa3cdefa8c832` |
| node-agent | `sha256:5e525c7046bbdf9b2835be5bce86ad9ee31ebfc0fd92188f73d533b8dfa60f42` |
| operator | `sha256:6e6c57ad66f8353b1790f2cdb62971c03059cde6cd56a1f2ea751ac1c4a4b997` |

The API used the enterprise build tag. Node/operator embed the candidate
version; the API/web/Nginx/migrate Dockerfiles do not consume that VERSION
argument. A matching registry tag alone is not an embedded-version proof.
An enterprise build alone is not a license-validity proof.

## Retained licensed dev CP upgraded

The user's explicit approval and committed plan/override `6081525` preceded
the upgrade. The public origin remains `https://cp.13.206.39.40.sslip.io` on
retained instance `i-019a97f67dd40ce13`. Only the API, web and Nginx services
were replaced with the exact digests above; the other four old container IDs
and existing stores were preserved.

| Replaced service | New container ID |
|---|---|
| API | `ba5bbab715a0` |
| web | `accfb0aff878` |
| Nginx | `a07f01f4e900` |

The executing operator verified:

- Normal migration completed: schema readback `136|f` (version 136, not dirty).
- Ordinary trusted TLS health succeeds at the unchanged public origin.
- Metadata reports enterprise edition, protocol 9, and authoritative gateway
  control URL `https://cp.13.206.39.40.sslip.io:8443`.
- Fresh normal authentication using unchanged credentials reports a valid
  Scale license, expiry `2029-07-22T11:13:56Z`, with unlimited ceilings.
- The existing `Tunnex AWS Engineering Demo` organization, slug
  `tunnex-aws-engineering`, remains accessible; no new organization was needed.
- The exact-hash native CLI authenticated through its normal device-code flow:
  one code was approved through the session API, then the CLI exchanged it and
  saved its own credential with mode 0600. Its private output is not committed.
  Authentication created no join or gateway object and is not an enrollment leg.

No license key, authentication material, bootstrap credential or database
contents were exported into this evidence. No new administrator bootstrap,
database reset, public DNS/certificate change or Caddy change was performed.
License availability does not opt the organization into HA enforcement.

The three new CP ingress rules allow TCP 8443 only from task worker public
addresses: `sgr-020be57f37e2409a7` (65.2.179.105/32),
`sgr-069b8d936ee880ac0` (13.234.118.111/32), and
`sgr-0cecb71669a57de2f` (13.206.207.103/32).
Unused TCP 18443 rules `sgr-023d51eeb14da6ff1`,
`sgr-09bf285cd3f1ef98c`, and `sgr-0bb51e217dcd3ba65` remain retained.
All five isolated-project containers were stopped; their files and stores
remain. This checkpoint authorizes no additional cleanup.

## Remaining boundary

The four Tunnex charts (`tunnex-host-posture`, `tunnex-gateway`,
`tunnex-operator-crds`, `tunnex-operator`) initially remained blocked pending
separate exact-payload/destination approval; no alternate transfer bypassed
that boundary. The user has now explicitly approved the four uploads.
Publication is in progress; digest readback and pull proof remain pending at
this checkpoint. Local chart preparation and the six-image upload do not
satisfy complete candidate admission or Leg 0.

Product acceptance remains **0/11**. No Tunnex gateway, UDP NLB, gateway PVC,
client connection or live CNI cleanup/recovery leg has been proven. Controller
readiness and CP health do not substitute for those proofs. Exact-final CI is
not green; earlier API-gate failures and held decisions are not closed here.
No PR, merge, public release or final PLAN pointer is created by this record.

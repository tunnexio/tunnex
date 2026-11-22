# K8L-10 — the control plane on Kubernetes (`tunnex-cp` chart)

Story branch: `story/kubernetes-launch-fixes`. The chart existed but had never been installed from
its defaults, and is not part of a release.

## What was wrong

1. **It could not pull.** `image.tag` and `nodeAgentImage` were pinned to `0.2.0`, a version that was
   never published (the latest release is v0.1.44).
2. **No way to choose the first administrator.** The API reads `TUNNEX_ADMIN_EMAIL`; the chart did
   not set it, so the account was always `admin@<host>`.
3. **The first password is easy to lose for good.** It is printed once in the API pod's log and
   stored only as a hash. On Kubernetes that pod is replaced by any upgrade, drain or restart, and
   the log goes with it. Nothing in the install notes said to read it, and the product has no way
   to print it again.

## Decision

1. An empty `image.tag` means the chart's `appVersion`, which release packaging sets to the Tunnex
   release. `nodeAgentImage` empty means the gateway image of that same release, so the control
   plane and the gateways it installs match by default.
2. New value `admin.email`, passed as `TUNNEX_ADMIN_EMAIL`.
3. The install notes open with "sign in now": the one command that prints the first-run banner, and
   the plain statement that a replaced pod means a lost password.

## Not done here, and why

- **Publishing the chart with releases.** It means editing the release workflow in six places and,
  on the first publish, the new registry package is private until an owner makes it public; the
  workflow's own "anonymously pullable" check would then fail the release. Do it as its own change
  with an owner at hand, not folded into this branch.
- **A way to recover a lost first password** (for example a one-shot command that mints a new
  one). Worth doing; it is an API change, not a chart change.
- **Bundled PostgreSQL and Redis.** The chart deliberately takes yours.

## Live walk, 2026-11-22, k3s 1.37

A throwaway namespace with its own PostgreSQL 16 and Redis 7, generated secrets, chart packaged from
this branch as 0.1.44 / v0.1.44.

| Check | Result |
| --- | --- |
| `helm install --wait` with only the required values | All pods Running in about 20 seconds: api 1, web 2, edge 2 |
| Images | `ghcr.io/tunnexio/tunnex-{api,web,nginx,migrate}:v0.1.44`; all exist |
| Schema | migration hook ran; version 236, not dirty |
| Dashboard through the edge Service | 200, HTML |
| API | `/healthz` ok; sign-in with a wrong password answers 401 |
| Gateway port 8443 | TLS, certificate `CN=tunnex-control` from the Tunnex Agent CA |
| `helm upgrade` with the same values | revision 2, deployed |
| API pod deleted | new pod healthy; still one user, no second bootstrap |
| `admin.email=owner@...` | the first-run banner names that address |
| The command in the install notes | prints the banner (the first version of the command stopped two lines early; fixed) |

Not walked: sign-in and a gateway enrolling against this control plane. Both need a public HTTPS
name for it, which the throwaway install did not have. Ingress, the load-balanced gateway port and
more than one API replica are likewise unproven here.

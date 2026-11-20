# SSI-0 — decisions for the site-to-site improvements epic

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Base: main `f47924f1`.

## Dispositions

On 2026-11-20 the Founder was shown D1 to D7 with a recommendation for each and replied with a
go-ahead to build the epic locally, story by story, with nothing pushed until the whole epic is
proven on a local stack. No item was ruled individually. The recommendations are therefore taken
as **accepted by that go-ahead**, and any of them can be reopened before the branch is pushed.

| # | Decision | Disposition |
| --- | --- | --- |
| D1 | Public ranges through a site | Refused. No override ships in SSI-1; an override with its own permission is **deferred to SSI-1b**, trigger: a customer needs a public destination routed through a gateway. |
| D2 | Widest admissible range | The range must sit inside one of `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10`. A range that contains or straddles one of them is too wide. |
| D3 | Site links with enforcement off | Migrate with explicit, visible grants; new orgs start closed. |
| D4 | Second gateway on a site | Supported; the hub's peers are deduplicated. |
| D5 | Default routing mode | `gateway_address` for new links; existing links stay `preserve_source`. |
| D6 | Probe permission | A named permission. |
| D7 | Guided flow ownership | Built here against the SCX-2 contract if that contract is ruled first. |

## Working rules for this epic

- Everything stays local: commits on `story/site-to-site-improvements`, no push and no pull request
  until the Founder says so.
- Each story records its red test, its fix and its local proof in `docs/SSI-<n>-decisions.md`.
- A unit test substitutes for a wire proof and never satisfies it. SSI-10 is the wire proof.

## Red matrix

One reproduction per finding, written as the first slice of the owning story.

| Finding | Reproduction | Story |
| --- | --- | --- |
| F1 | Advertising `128.0.0.0/1`, `8.8.8.0/24`, `169.254.0.0/16` and `10.0.0.0/7` is accepted today. | SSI-1 |
| F11 | A failed bind in `RouteLAN` leaves a site row behind. | SSI-1 |
| F3 | A site → resource rule across two sites compiles a grant for the source gateway only. | SSI-2 |
| F4 | Choosing a source group in Add rule sets the destination to the same group. | SSI-3 |
| F2 | Two linked sites, enforcement off, no rule: forward rules accept all traffic between the ranges. | SSI-4 |
| F5 | Site create, advertise, bind and unbind leave no audit row. | SSI-5 |
| F6, F7 | A range removal does not push; `RouteLAN` leaves no persisted hub set. | SSI-6 |
| F8, F9, F10 | A remote route that collides with a host bridge is installed; a second bind doubles the hub peer; a peered range raises `site_subnet_unreachable`. | SSI-7 |

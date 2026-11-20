# SSI-3 — the rule builder never proposes a broad destination

Epic: [EPIC-site-to-site-improvements.md](EPIC-site-to-site-improvements.md). Finding F4.

## What was wrong

A new rule opened with the first item of each list already chosen as its destination. In an
organization with groups that is "<first group> → <first group>, every port and protocol", two
clicks from saved. Seen on the demo control plane on 2026-11-20.

## Decisions

| Item | Decision |
| --- | --- |
| New rule | Opens with no destination. Review stays disabled until one is chosen; the existing gate already required a destination. |
| Edit | Unchanged: the rule's own destination is shown. |
| Source | Unchanged in this story. A source alone grants nothing. |
| Earlier decision reversed | `defaultDstKind` exists so a new rule never opens on a kind with **no options**. That stays. What changes is the chosen **item**: the options are there and the picker shows its placeholder. |

## Tests

| Test | Proves |
| --- | --- |
| `policyview.test.ts` › `initialDestinationId` | A new rule has no destination; an edited rule keeps its own. |
| `accesswiring.test.tsx` › agent grant | Review is disabled and the Destination field is empty until a destination is picked; the rule then posts the chosen resource. |

`accesswiring.test.tsx` previously asserted the old behaviour (Review enabled on open) and was
updated with this change.

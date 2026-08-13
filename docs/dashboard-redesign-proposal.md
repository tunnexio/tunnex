# The dashboard has 18 boxes and no hierarchy — a proposal

Founder: *"we have used so much card in the dashboard that it feels overwhelming, I can't see that
anymore."* Proposal only. Nothing built.

---

## 1. THE MEASUREMENT, BEFORE THE OPINION

| | count | chrome each |
| --- | --- | --- |
| Stat cards | **7** | border + translucent fill + 24px blur + shadow |
| Panels | **11** | the same, plus 16px padding on four sides |
| **Total bordered containers** | **18** | **identical treatment on all 18** |

⛔ **THE PROBLEM IS NOT THE NUMBER OF CARDS. IT IS THAT ALL 18 HAVE THE SAME VISUAL WEIGHT.**

`GLASS` is a good material. It is applied to *everything*, so it distinguishes *nothing* — and a
material that marks everything has stopped being emphasis and become background noise the eye must
filter. There is no entry point: "Needs Attention" is panel 10 of 11 and looks exactly like
"Kubernetes".

> ## **A BORDER IS THE MOST EXPENSIVE WAY TO SAY "THESE THINGS ARE DIFFERENT" AND THE LEAST
> ## INFORMATIVE — it says only *different*, never *how*, and never *which matters*.**

Three costs, compounding:

- **Enclosure ≠ grouping.** 11 borders assert 11 separate things, so a single status view reads as a
  wall of unrelated widgets.
- **Double containment.** The page is already a bounded region. A box inside a box repeats what the
  layout already said.
- **Chrome displaces content.** 16px × 4 sides × 11 panels, plus 18 borders and 18 blur layers.

⚠ **AND THE BLUR IS NOT FREE.** `backdrop-blur-[24px]` on 18 stacked elements is 18 compositing
layers. Whatever the aesthetic argument, it has a frame-rate one.

---

## 2. THE PRINCIPLE

> ## **SEPARATE BY SPACE AND TYPOGRAPHY. SPEND MATERIAL ONLY WHERE IT EARNS ATTENTION.**

What replaces a card, in order of preference:

1. **Whitespace** — a gap larger than the block's own line-height already reads as a boundary. Free,
   silent, and it never competes with content.
2. **A section label** — small, uppercase, muted. Says **what** the group is, which a border cannot.
3. **A hairline rule** — one 1px low-contrast line, where a boundary must be explicit. Roughly a
   tenth the visual cost of a full box.
4. **A card** — reserved for the one or two things that must be looked at first.

⛔ **SCARCITY IS WHAT MAKES MATERIAL READ AS EMPHASIS.** Keep `GLASS` exactly as designed; spend it
on 1–2 elements instead of 18. That is not a compromise of the aesthetic — it is the condition under
which the aesthetic works at all.

---

## 3. THE PROPOSED SHAPE

```
Overview                                          Demo Organization · healthy
──────────────────────────────────────────────────────────────────────────────

  7          11          6          2          14         3          1
  MEMBERS    DEVICES     GATEWAYS   SITES      RULES      AGENTS     K8S
                                                                              ← no boxes: figures
                                                                                and labels, spaced

┌────────────────────────────────────────────────────────────────────────────┐
│  NEEDS ATTENTION · 3                                                       │  ← THE ONLY CARD.
│  gw-eu-west   site link down          17h        →                         │    Glass, full width.
│  gw-ap-south  site link down          17h        →                         │    Collapses to one
│  5 credentials refused — no owner                →                         │    honest line at zero.
└────────────────────────────────────────────────────────────────────────────┘

GATEWAY HEALTH                          RECENT ACTIVITY
gw-us-east      site link down          device.created    Ada Auditor    3d
gw-eu-west      site link down          policy.rule_…     Demo Owner     3d
tunnex-gw       healthy          HUB    node.enrolled     Demo Owner     4d
────────────────────────────────────    ────────────────────────────────────
DEVICE POSTURE                          KUBERNETES
…                                       …
```

**Four rules:**

1. **Stats become a figure row.** Seven boxes → seven figures with labels beneath, separated by
   space. It should read like a line of instrument readings, not a bento.
2. **Exactly one card: "Needs attention", promoted to the top and full width.** It is the only thing
   on the page that asks for a decision, and it currently sits tenth wearing the same clothes as
   everything else. ⚠ At zero it must render **one line** — *"Nothing needs attention"* — never an
   empty card, which is the emptiness-that-repeats-a-count defect already fixed on Gateways.
3. **Everything else: a labelled section in a two-column flow.** No border, no fill, no blur. A
   hairline between vertically adjacent sections; nothing between columns — the gutter is the
   separator.
4. **Content is untouched.** Every panel keeps its rows, its honest empty states, its badges. This
   is a chrome change, and the moment it starts deleting information it has stopped being one.

---

## 4. WHAT MAKES IT CHECKABLE RATHER THAN A MATTER OF TASTE

⛔ **"LESS OVERWHELMING" IS UNFALSIFIABLE UNLESS IT IS COUNTED.** Three measurements, before and
after:

| metric | now | target |
| --- | --- | --- |
| bordered/filled containers | 18 | **1** |
| `backdrop-blur` layers | 18 | **1** |
| px of vertical space spent on padding + borders | ~460 | **< 120** |

⚠ And one guard, because this is where a tidy-up turns into a regression:

> **CHROME MAY GO. INFORMATION MAY NOT.** Every count, badge, honest-empty state and warn-kind on
> the page today must still be on it after. A dashboard that got calmer by saying less has not
> solved the problem — it has hidden it, which is the reassuring-empty defect at page scale.

A test can assert the second half: each section's accessible name still resolves, and the
warn-kind strings still render.

---

## 5. WHAT I NEED FROM THE FOUNDER

1. **Is one card the right budget**, or two — e.g. "Needs attention" plus "Get started" for a fresh
   org, which is the only other thing that is ever the primary action?
2. **Hairline between sections, or space alone?** Space alone is cleaner and slightly harder to scan
   on a dense column; the hairline is one low-contrast pixel.
3. **Do the seven stats stay seven?** Members / Devices / Gateways / Sites / Rules / Agents / K8s is
   a lot of equally-weighted figures. Three or four primary and the rest on their own pages would
   read faster — but that is a content decision, not a chrome one, and it is the founder's.

⛔ **Not built. This is the shape; the ruling is the founder's.**

# These images are not a statement that the design is right.

> ## A BASELINE DETECTS CHANGE. IT DOES NOT CERTIFY CORRECTNESS.
> ## THAT DISTINCTION ONLY HOLDS IF WHAT IS WRONG INSIDE ONE IS WRITTEN DOWN.

A green visual check means **nothing moved that nobody asked to move**. It does not mean the picture is good,
and it does not mean the picture is free of defects — a defect that was present when the baseline was
harvested is now *the expected output*, and the suite will defend it.

So: **whenever a baseline is committed with a known defect visible in it, the defect is registered in the
same commit**, and this file names it. A frozen defect that is written down is honest. A frozen defect that
is not is a test actively protecting a bug.

## What is in here

| file | subject |
|---|---|
| `gallery-1440-chromium-linux.png` | the visual gallery at 1440 |
| `gallery-390-chromium-linux.png` | the visual gallery at 390 |

**Two, and only two** — the exact count is asserted by `../baselinecensus.spec.ts`, so neither an addition
nor a silent deletion can pass unremarked.

**These are generated on `chromium` / `linux`, in CI, which is where they are compared.** A locally-harvested
baseline diffs on font rasterisation alone. Harvest from the failing run's `visual-diff` artifact, and land
them as a **`.png`-only commit** — a commit where the image and the code it measures move together has no
answer to *"did the picture change because the code did?"*

## Why the gallery and not the screens

The gallery renders **fixtures**. A screen renders a **live control plane**: panels resolving in whatever
order the API answers, rows stamped at seed time. **A visual suite's subject should be the surface whose
output is determined by code, not by data.**

It is also where the defects actually were: all three real ones this instrument has found originated in
**shared code** — a spacing config, a shared scale, a shared primitive. None originated in a screen.

## The three pre-existing `main` defects this instrument found

Each had been live since **S14.2**, on **every screen**, invisible to `tsc`, to 424 component tests, to the
codegen drift guard, and to `e2e`.

1. **A 65px horizontal overflow at 390** — the shell header's flex children defaulting to `min-width:auto`.
   Found by a **geometric assertion**. Fixed on this branch.
2. **The drawer `Menu` button sits on top of the page `<h1>`** — `absolute left-4 top-4` in
   `AppShell.tsx`, positioned over the page body rather than reserving space in it.
   Found by **a human reading a harvested image**. **NOT fixed** — registered, trigger = the next
   shell-touching section.
3. **The control-plane health indicator renders twice on Overview** — the shell footer since S4.x, and
   S14.4's System Health panel. Found by a **strict-mode locator violation**. **NOT fixed** — it is a
   product decision, and a visual suite must never be where one gets made quietly.

**⚠ NOTE ON #2, stated because the weakening is real.** It *was* committed into an `overview-390` baseline —
frozen, visible, and written down. That baseline has since been **dropped** (the Overview surface is
data-determined and flaked at 621px across runs of identical code). **So #2 is now registered in prose only,
and no artifact holds it.** If the shell fix lands without someone re-reading that registration, nothing
here will notice.

## What each instrument has actually paid

| instrument | findings |
|---|---|
| geometric assertions (`scrollWidth` vs `clientWidth`) | 1 |
| a human reading an image | 1 |
| strict-mode locator violations | 1 |
| **full-page pixel diff of a live screen** | **0, in six rounds** |

**Scope a suite to what has paid, not to what looks comprehensive.**

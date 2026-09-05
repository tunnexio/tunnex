# CLI installation presentation

Scope: local review of the macOS/POSIX and Windows one-command onboarding UI.

- Locked: retain the Tunnex white/red wordmark and existing tagline; add a compact
  step rail, consistent status indentation, and a clear completion handoff.
- Locked: animate only real pending work in capable interactive terminals; preserve
  readable output with NO_COLOR, TERM=dumb, redirected output, or loader disabled.
- Locked: add --ui-preview (PowerShell -UiPreview), a clearly labeled, offline
  demonstration using the same presentation helpers. Exit before host inspection,
  downloads, credentials, package installation, or Docker operations.
- Locked: retain existing installation, verification, prompts, and approval ordering.
- Deferred: publication and real installation until the user reviews the local UI.

Validation: existing host/bootstrap and provenance contracts, Windows launcher
contracts, and offline preview checks. These substitute for a live install; the
real macOS/Windows box walk is triggered by approval of the local design.

Local review revision: user rejected the repetitive first preview. Replace the
repeated route labels with a five-position active-step indicator; align status
rows and plan panels beneath a framed wordmark; use a separate preview completion
card. Preserve the white/red brand and cyan activity accents. This is a visual
revision within the existing presentation scope.

Wordmark refinement: use the website's `src/assets/tunnex-wordmark-light.svg`
geometry sampled at 66 x 10 pixels into five half-block terminal rows. Preserve
its detached E bars and white TUNN / burgundy EX split. Truecolor terminals use
#B03A45 through #6E1520; other terminals use palette fallbacks. Terminal cell
resolution is an approximation, not an SVG-perfect reproduction. Add bounded
60 ms row reveals and 35 ms step-marker transitions only with interactive output
and animation enabled. Existing no-motion controls remain authoritative.

EX legibility revision: user screenshot showed disconnected X diagonals and
uneven E bars at terminal resolution. Hand-align the EX cells with three equal
slanted E bars and a symmetric X; retain the website-derived TUNN. Slow the row
reveal to 120 ms and add a bounded decorative cyan sweep beneath the wordmark.
The sweep is not installation progress and skips noninteractive/no-motion output.

Renderer correction after repeated visual rejection: the screenshots show gaps
between terminal block glyphs across every letter, including straight stems.
Further EX glyph edits cannot fix that mechanism. Replace the glyph renderer
with ANSI background-colored space cells derived from the website geometry;
backgrounds fill the complete terminal cell, independent of glyph metrics. Use a
plain TUNNEX wordmark for monochrome/redirected output. Validate the rendered
result in an actual terminal before presenting the next revision.

User disposition: simplify EX to conventional connected letters. Join the E
with a continuous left stem; draw a symmetric X. Keep the solid-cell renderer,
TUNN geometry, colors, and animations. This supersedes the detached E requirement.

Size-only disposition: user approves the remaining presentation and requests
the original compact wordmark footprint. Use 25 columns across three rows in
both scripts, preserving connected EX, brand colors, and existing animations.
Solid character stems retain background cells; partial edge cells provide the
original compact letter shapes.

Final user correction: restore the original installer wordmark characters and
spacing exactly; retain only the approved burgundy EX coloring. Remove the
background-cell rendering from the wordmark. All other approved UI and animation
work remains. This supersedes the earlier solid-cell and connected-stroke rules.

Header copy disposition: remove "Self-hosted Zero Trust VPN"; place the unchanged
"Connect Everything. Trust Nothing." slogan immediately below the wordmark,
with matching two-space left indentation and no intervening blank line.

Windows parity disposition: user approved the final macOS presentation and asks
Windows to match. The Windows launcher already delegates actual product setup
to install.sh after Windows prerequisites. Match native preparation status and
step styling; expand -UiPreview into the same five-stage demonstration using
PowerShell-only presentation helpers, so review needs neither Git Bash nor Docker.
Keep prerequisite behavior and canonical-installer handoff unchanged. Compare
rendered preview headings, wordmark/slogan spacing, plan values, and completion
copy between both entrypoints. Native Windows visual acceptance remains pending.

import logoUrl from "./assets/tunnex-logo.svg";
import wordmarkUrl from "./assets/tunnex-wordmark.svg";

// Brand is DATA, deliberately isolated to this one module (plus the color tokens
// in tailwind.config.js). Dropping the real logo/brand kit is then a ~2-file
// swap: replace <Logo> here and the palette there — no component touches brand
// details directly. The placeholder identity is intentionally restrained: a plain
// wordmark on a dark, security-product palette, not a decorative mark.

export const PRODUCT_NAME = "tunnex";
export const PRODUCT_TAGLINE = "self-hosted VPN & Zero Trust";

/**
 * Logo renders the real mark + wordmark.
 *
 * ⛔ BOTH DIMENSIONS ARE DERIVED FROM THE ASSETS' TRUE RATIOS, and that is the whole point of this
 * component. Two ratio bugs shipped before it existed:
 *
 *   · the mark is **577x551 — NOT SQUARE** — and was rendered `h-7 w-7`, squashing it horizontally
 *   · the wordmark is **792x120 (6.6:1)** and was given a HEIGHT ONLY. Height alone does not hold a
 *     ratio once the image is a flex child that may grow or shrink, so it stretched — visibly, on
 *     the widest thing on the page.
 *
 * > **A SIZE EXPRESSED AS ONE DIMENSION IS A HOPE ABOUT THE OTHER.** Give both, computed from the
 * > intrinsic size, and the layout cannot deform the artwork whatever the container does.
 *
 * `shrink-0` and `object-contain` are belt-and-braces for the same reason: a flex row is entitled
 * to compress its children, and an image is not obliged to keep its aspect when it does.
 */
const MARK_RATIO = 577 / 551; // 1.047 — wider than tall, and not by enough to notice until it is wrong
const WORDMARK_RATIO = 792 / 120; // 6.6

export function Logo({
  className = "",
  size = 28,
  markOnly = false,
  wordmarkOnly = false,
}: {
  className?: string;
  /** Height of the MARK in px; the wordmark is scaled to sit with it. */
  size?: number;
  /** ⛔ The two halves are separately clickable in the sidebar — the mark TOGGLES, the wordmark
   *  NAVIGATES — so each must be renderable alone without re-deriving its geometry. */
  markOnly?: boolean;
  wordmarkOnly?: boolean;
}) {
  const wordHeight = Math.round(size * 0.54);
  return (
    <span className={`flex select-none items-center gap-2.5 ${className}`}>
      {!wordmarkOnly && (
        <img
          src={logoUrl}
          alt=""
          aria-hidden
          draggable={false}
          width={Math.round(size * MARK_RATIO)}
          height={size}
          // ⛔ NO CORNER CROP ON THE MARK. `rounded-lg` clipped an 8px radius off a 22px image, and
          // the mark's shape reaches its own corners — so the identity was being trimmed at every
          // size, most visibly the smallest. A logo is the one asset that must never be cropped to
          // fit its box; scale it or give it room.
          className="shrink-0 object-contain"
        />
      )}
      {!markOnly && (
        <img
          src={wordmarkUrl}
          alt={PRODUCT_NAME}
          draggable={false}
          width={Math.round(wordHeight * WORDMARK_RATIO)}
          height={wordHeight}
          className="shrink-0 object-contain"
        />
      )}
    </span>
  );
}

/**
 * The tagline, once.
 *
 * ⛔ THE DESIGN'S OWN TYPOGRAPHY: 8.5px / 1.6 line-height / .04em tracking, set directly under the
 * wordmark, broken across two lines. Those numbers are the handoff's, not a guess.
 *
 * ⚠ ONE DEFINITION BECAUSE THE SECOND COPY WAS ABOUT TO BE TYPED. It lived inline in `AppShell`;
 * adding it to the desktop client meant either importing it or retyping it, and a slogan retyped is
 * a slogan that will eventually differ from itself in one place nobody checks.
 */
export const TAGLINE = ["Connect Everything.", "Trust Nothing."] as const;

export function Tagline({ className = "" }: { className?: string }) {
  return (
    <span
      className={`block text-[8.5px] leading-[1.6] tracking-[.04em] text-ink-secondary ${className}`}
    >
      {TAGLINE[0]}
      <br />
      {TAGLINE[1]}
    </span>
  );
}

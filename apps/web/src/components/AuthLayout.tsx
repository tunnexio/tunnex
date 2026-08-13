import type { ReactNode } from "react";
import { Logo, PRODUCT_TAGLINE } from "../brand";
import { HealthStatus } from "./HealthStatus";
import { AuthMesh } from "./AuthMesh";
import { TRUST_BADGES } from "../lib/authhero";
import { HERO_HEADLINE, HERO_SUBHEAD } from "../lib/authhero";

/**
 * AuthLayout — the pre-auth frame.
 *
 * ⛔ THE PROPORTIONS ARE THE FIRST THING THE PREVIOUS BUILD GOT WRONG. It put a 300px illustration
 * BESIDE the form in a two-up grid, which reads as a decorated form. The design is a FULL-BLEED
 * HERO with the form as a narrow rail on the right — the mesh is the page and the form sits on it.
 * Getting that backwards is why the first version looked like a thumbnail of the design even where
 * the individual pieces matched.
 *
 * Below `lg` the hero is dropped entirely rather than squeezed: a mesh at phone width is six
 * overlapping labels, and the form is the only thing that matters there.
 */
export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    /* ⛔ THE LOGIN PAGE MUST NOT SCROLL. `min-h-full` lets the content set the height, so the hero
       column grew past the viewport and the whole page scrolled — on the one screen where there is
       nothing below the fold to find. `h-dvh` + `overflow-hidden` fixes the frame to the viewport
       and makes the mesh shrink into whatever is left, which is what a hero should do.
       `dvh` rather than `vh` because mobile browsers' chrome changes vh mid-scroll. */
    <div className="flex h-dvh flex-col overflow-hidden">
      <main className="relative flex min-h-0 flex-1 flex-col lg:flex-row">
        {/* ── HERO ─────────────────────────────────────────────────────────────────────────── */}
        <div
          className="relative hidden min-w-0 flex-1 flex-col overflow-hidden px-10 py-8 lg:flex"
          style={{
            // The handoff's own backdrop, verbatim — an off-centre radial, not a flat panel.
            background:
              "radial-gradient(130% 120% at 12% -5%,#1C1C1C 0%,#141414 48%,#0D0D0D 100%)",
          }}
        >
          <Logo size={36} />

          <h1 className="mt-7 max-w-xl text-[34px] font-semibold leading-[1.1] tracking-tight text-white">
            {HERO_HEADLINE}
          </h1>
          <p className="mt-2 max-w-lg text-sm text-slate-400">{HERO_SUBHEAD}</p>

          {/* The mesh takes the room it is given — it IS the page, not an inset picture. */}
          <div className="relative mt-2 min-h-0 flex-1">
            <AuthMesh />
          </div>

          {/* ⛔ THREE STAT BLOCKS, the design's shape — with only claims we can evidence. The
              wireframe's middle block was "SOC 2 / Type II certified" and the third "SSO + SCIM /
              enterprise ready"; both were CUT and are gated on what would make them true. The
              LAYOUT is the design's; the CLAIMS are ours to stand behind. */}
          <dl className="mt-6 flex flex-wrap gap-x-14 gap-y-4">
            {TRUST_BADGES.map((b) => (
              <div key={b.text}>
                <dt className="text-[13px] font-semibold text-white">
                  {b.headline}
                </dt>
                <dd className="mt-0.5 font-mono text-[11px] text-slate-500">
                  {b.detail}
                </dd>
              </div>
            ))}
          </dl>
        </div>

        {/* ── FORM RAIL ────────────────────────────────────────────────────────────────────── */}
        {/* The rail is the ONE thing allowed to scroll, and only if a short viewport forces it —
            a 2FA step with a recovery warning is taller than a bare sign-in. */}
        <div className="flex w-full min-h-0 flex-col justify-center overflow-y-auto border-white/5 px-6 py-8 lg:w-[420px] lg:shrink-0 lg:border-l">
          {/* The mark repeats here only where the hero is hidden — otherwise it is duplicated. */}
          <Logo size={30} className="mb-6 lg:hidden" />
          <div className="mx-auto w-full max-w-sm">{children}</div>
        </div>
      </main>
      <footer className="flex items-center justify-between px-6 py-4 text-xs text-slate-600">
        <HealthStatus />
        <span>{PRODUCT_TAGLINE}</span>
      </footer>
    </div>
  );
}

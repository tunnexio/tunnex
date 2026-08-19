import type { ReactNode } from "react";
import { Logo } from "../brand";
import { HealthStatus } from "./HealthStatus";
import { HERO_HEADLINE } from "../lib/authhero";

export function AuthLayout({ children }: { children: ReactNode }) {
  return (
    <div className="flex min-h-dvh flex-col items-center justify-center bg-[#050507] px-4 py-12 text-slate-100 selection:bg-rose-500/30 selection:text-white">
      {/* ── TOP CENTERED BRAND HEADER ────────────────────────────────────────── */}
      <header className="flex flex-col items-center mb-6 text-center">
        <Logo size={46} />
        <p className="mt-2 text-xs text-slate-400 font-normal tracking-tight text-center max-w-[220px] leading-snug">
          {HERO_HEADLINE}
        </p>
      </header>

      {/* ── CENTERED CARD CONTAINER ──────────────────────────────────────────── */}
      <main className="w-full max-w-[440px] rounded-2xl border border-white/[0.08] bg-[#121215]/95 p-8 shadow-2xl shadow-black/80 backdrop-blur-xl">
        {children}
      </main>

      {/* ⛔ RESTORED. The redesign dropped this, and the login page is the ONE screen where control-plane
          health is most worth knowing: someone whose sign-in is failing needs to be told the control plane
          is down rather than concluding their password is wrong. It also drives the /healthz call the
          SPA→API correlation chain is proven through (e2e health.spec), so removing it silently removed a
          proof as well as a signal. */}
      <footer className="mt-6">
        <HealthStatus />
      </footer>
    </div>
  );
}

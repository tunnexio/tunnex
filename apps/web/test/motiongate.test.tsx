import { describe, expect, it, afterEach } from "vitest";
import { render, screen, cleanup } from "@testing-library/react";
import { Donut } from "../src/components/viz";
import {
  motionAllowed,
  readsReducedMotionPreference,
  REDUCED_MOTION_QUERY,
} from "../src/lib/motion";
import {
  MotionProvider,
  useMotionPreference,
} from "../src/components/MotionProvider";

// S14.3 SLICE B — `prefers-reduced-motion` AS A GATE, PROVEN TO REJECT.
//
// ⚠ WHY NONE OF THIS RENDERS A COMPONENT AND ASKS jsdom: jsdom DOES NOT IMPLEMENT `window.matchMedia`. A test
// that asked the platform would throw — or, if someone stubbed it carelessly, silently no-op and PASS AT EVERY
// SETTING, certifying an accessibility property nobody checked. That is the detector's FIFTH prospective
// catch, found before this gate was written rather than after it silently passed (docs/laws.md).

afterEach(cleanup);

describe("motionAllowed — the whole decision, both directions", () => {
  it("reduced preference FORBIDS motion", () =>
    expect(motionAllowed(true)).toBe(false));
  it("no preference ALLOWS motion", () =>
    expect(motionAllowed(false)).toBe(true));
});

describe("readsReducedMotionPreference — FAILS TOWARDS LESS MOTION", () => {
  // The asymmetry is the reason: not animating for someone who would have enjoyed it costs nothing; animating
  // for someone who cannot tolerate it makes a person feel ill. So every uncertain path returns `true`.
  it("returns REDUCED when the platform has no matchMedia at all", () => {
    const orig = window.matchMedia;
    // @ts-expect-error — deliberately removing the API to model an environment that lacks it
    delete window.matchMedia;
    expect(readsReducedMotionPreference()).toBe(true);
    window.matchMedia = orig;
  });

  it("returns REDUCED when matchMedia THROWS", () => {
    const orig = window.matchMedia;
    /* No suppression directive here: a function returning `never` IS assignable to MediaQueryList's
       signature, so the one that used to sit on this line was UNUSED and tsc rejected it (TS2578).
       And a second lesson from writing that explanation: naming the directive in a `//` comment MAKES ONE —
       tsc reads the token, not the sentence around it. Hence the block comment. A stale suppression is itself
       a standing claim that a type error exists, and it goes stale in silence. */
    window.matchMedia = () => {
      throw new Error("nope");
    };
    expect(readsReducedMotionPreference()).toBe(true);
    window.matchMedia = orig;
  });

  it("passes the EXACT query string — a typo would fail OPEN", () => {
    // `matchMedia` returns `matches: false` for a query it cannot parse, which reads as "no preference" and
    // animates for someone who asked not to be. So the literal is named once and asserted here.
    const seen: string[] = [];
    const orig = window.matchMedia;
    // @ts-expect-error — recording stub
    window.matchMedia = (q: string) => {
      seen.push(q);
      return { matches: true, addEventListener() {}, removeEventListener() {} };
    };
    expect(readsReducedMotionPreference()).toBe(true);
    expect(seen).toEqual([REDUCED_MOTION_QUERY]);
    expect(REDUCED_MOTION_QUERY).toBe("(prefers-reduced-motion: reduce)");
    window.matchMedia = orig;
  });
});

function Probe() {
  const reduced = useMotionPreference();
  return (
    <span data-testid="probe">
      {motionAllowed(reduced) ? "animating" : "still"}
    </span>
  );
}

describe("the preference reaches components, injected rather than measured", () => {
  it("reduced=true renders the STILL branch", () => {
    render(
      <MotionProvider value={true}>
        <Probe />
      </MotionProvider>,
    );
    expect(screen.getByTestId("probe").textContent).toBe("still");
  });

  it("reduced=false renders the ANIMATING branch", () => {
    render(
      <MotionProvider value={false}>
        <Probe />
      </MotionProvider>,
    );
    expect(screen.getByTestId("probe").textContent).toBe("animating");
  });

  it("NO PROVIDER defaults to reduced — the safe direction, not the pretty one", () => {
    render(<Probe />);
    expect(screen.getByTestId("probe").textContent).toBe("still");
  });
});

// ⚠ THE CSS HALF IS ASSERTED IN `tokens.test.ts`, NOT HERE, AND THE REASON IS A MEASURED ENVIRONMENT
// DIFFERENCE. `vitest.config.ts` runs `test/**/*.test.tsx` under **jsdom** and everything else under **node**.
// Under jsdom `import.meta.url` is an `http://localhost/...` URL, so `fileURLToPath` throws
// "The URL must be of scheme file" — the artifact cannot be read from a .tsx test at all.
//
// So the unconditional `@media (prefers-reduced-motion: reduce)` assertion lives in the node-environment
// `tokens.test.ts`, beside the coverage census that already reads the same file. Duplicating it here would
// have meant either a second path-resolution scheme or a weaker assertion, and one gate asserted once in the
// environment that can actually see the artifact beats two half-assertions.

// ── THE EPIC'S FIRST OPT-IN ANIMATION ON A SHARED PRIMITIVE (S14.8) ─────────────────────────────────────
//
// ⛔ THIS TEST EXISTS BECAUSE I CLAIMED IT ALREADY DID. Reporting the Donut's reduced-motion path as "covered
// by the motion gate's tests", I had not checked: `grep -c Donut` over this file returned ZERO. The gate's
// tests covered the pure decision and a generic component, and NOTHING asserted that the Donut emits no
// animation under the preference.
//
//   A GUARD THAT HAS ONLY EVER PASSED IS INDISTINGUISHABLE FROM ONE THAT DOES NOTHING —
//   AND A GUARD THAT DOES NOT EXIST IS INDISTINGUISHABLE FROM BOTH, IF NOBODY GREPS FOR IT.
//
// `prefers-reduced-motion` is a GATE, not a courtesy (founder-ruled): vestibular disorders make large or fast
// motion physically unpleasant, so this is an accessibility obligation and is asserted, not reviewed.
describe("Donut — the reduced-motion path emits NO animation", () => {
  const slices = [
    { label: "a", value: 2, tone: "ok" as const },
    { label: "b", value: 1, tone: "neutral" as const },
  ];

  function animateEls(reduced: boolean) {
    const { container } = render(
      <Donut
        label="proportion"
        source={{ endpoint: "GET /test" }}
        failed={false}
        slices={slices}
        animate={motionAllowed(reduced)}
      />,
    );
    return container.querySelectorAll("animate");
  }

  it("⛔ reduced=true emits ZERO <animate> elements", () => {
    // Not "fewer", not "shorter" — NONE. A gate that reduces motion instead of removing it is still motion
    // for someone who asked for none.
    expect(animateEls(true)).toHaveLength(0);
  });

  it("reduced=false DOES emit them — one per slice", () => {
    // ⛔ MECHANISM ⑨: the assertion above passes trivially against a Donut that never animates at all. The
    // gate is only load-bearing if the OTHER side is observed in the same file, so a change that silently
    // disabled the animation everywhere would fail HERE rather than pass as "accessible".
    expect(animateEls(false)).toHaveLength(slices.length);
  });
});

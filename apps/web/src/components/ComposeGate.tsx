import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  capabilityFor,
  layoutIntent,
  readOnlyByWidthMessage,
  type LayoutCapability,
} from "../lib/layout";

// S14.2 — THE COMPOSITION GATE. ONE component, ONE hook, expressed ONCE.
//
// Screens declare WHAT they compose; they never ask HOW WIDE the window is. A screen that reads a breakpoint
// directly is the per-screen duplication this exists to prevent, and it is the form the drift would take.

const CapabilityContext = createContext<LayoutCapability | null>(null);

/**
 * Measures the viewport ONCE at the edge of the app and hands down a CAPABILITY. This is the only place in the
 * product that is allowed to know a pixel width.
 *
 * The value is INJECTABLE (via `value`) so tests can exercise every capability without asking jsdom to lay
 * anything out — jsdom has no layout engine, so a test that measured would measure nothing.
 */
export function LayoutCapabilityProvider({
  children,
  value,
}: {
  children: ReactNode;
  value?: LayoutCapability;
}) {
  const [measured, setMeasured] = useState<LayoutCapability>(() =>
    capabilityFor(
      layoutIntent(typeof window === "undefined" ? 1440 : window.innerWidth),
    ),
  );

  useEffect(() => {
    if (value) return; // injected: never measure
    const onResize = () =>
      setMeasured(capabilityFor(layoutIntent(window.innerWidth)));
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [value]);

  return (
    <CapabilityContext.Provider value={value ?? measured}>
      {children}
    </CapabilityContext.Provider>
  );
}

export function useLayoutCapability(): LayoutCapability {
  const ctx = useContext(CapabilityContext);
  // A sensible default rather than a throw: the shell is not the only mount point (tests, the Electron
  // renderer), and a missing provider must not make a screen unrenderable.
  return ctx ?? capabilityFor("operate");
}

/**
 * ⛔ WHY THIS RENDERS NOTHING RATHER THAN HIDING SOMETHING.
 *
 * If the rule builder were merely hidden by CSS below `compose`, it would STILL BE IN THE DOM — focusable,
 * announced to a screen reader, and submittable. A control that GRANTS ACCESS, present to a keyboard and gone
 * only to a sighted mouse user, is the exact failure this epic already ruled on twice: INVISIBLE IS NOT ABSENT,
 * a security-adjacent surface failing open (docs/laws.md).
 *
 * So the editor is not rendered at all. The honest line replaces it — never a blank space where an editor was,
 * and never a degraded editor.
 *
 * PERMISSION IS A RENDER DECISION. WIDTH NEVER IS — which is why this gate produces ABSENCE, and why the
 * responsive contract asserts that absence BY ROLE: `queryByRole` finds a hidden element, so a `display:none`
 * implementation FAILS that assertion instead of passing it.
 */
export function ComposeGate({
  surface,
  children,
}: {
  surface: string;
  children: ReactNode;
}) {
  const { canCompose } = useLayoutCapability();
  if (canCompose) return <>{children}</>;
  return (
    <p
      role="note"
      className="rounded-md border border-white/5 bg-ink-800 px-3 py-2 text-xs text-slate-400"
    >
      {readOnlyByWidthMessage(surface)}
    </p>
  );
}

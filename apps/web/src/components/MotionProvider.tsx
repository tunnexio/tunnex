import {
  createContext,
  useContext,
  useEffect,
  useState,
  type ReactNode,
} from "react";
import {
  REDUCED_MOTION_QUERY,
  readsReducedMotionPreference,
} from "../lib/motion";

// S14.3 SLICE B — the preference, read ONCE at the app edge.
//
// Same shape as S14.2's LayoutCapabilityProvider, and for the same measured reason: jsdom does not implement
// `window.matchMedia`, so a component that asked the platform itself would be untestable — and a carelessly
// stubbed matchMedia would make the gate pass at every setting, which is worse than untestable. The value is
// INJECTABLE so tests exercise both directions without asking jsdom a question jsdom cannot answer.

const MotionContext = createContext<boolean | null>(null);

export function MotionProvider({
  children,
  value,
}: {
  children: ReactNode;
  value?: boolean;
}) {
  const [reduced, setReduced] = useState<boolean>(() =>
    readsReducedMotionPreference(),
  );

  useEffect(() => {
    if (value !== undefined) return; // injected: never read the platform
    if (
      typeof window === "undefined" ||
      typeof window.matchMedia !== "function"
    )
      return;
    const mq = window.matchMedia(REDUCED_MOTION_QUERY);
    const onChange = () => setReduced(mq.matches);
    // The preference can change while the app is open (an OS setting, a system-wide toggle). Honouring it only
    // at mount would leave someone who turns it ON mid-session still being animated at.
    mq.addEventListener?.("change", onChange);
    return () => mq.removeEventListener?.("change", onChange);
  }, [value]);

  return (
    <MotionContext.Provider value={value ?? reduced}>
      {children}
    </MotionContext.Provider>
  );
}

/**
 * Does the user prefer REDUCED motion? (`true` means reduce.)
 *
 * Defaults to `true` with no provider — FAIL TOWARDS LESS MOTION. The cost of not animating for someone who
 * would have enjoyed it is nothing; the cost of animating for someone who cannot tolerate it is a person
 * feeling ill.
 */
export function useMotionPreference(): boolean {
  return useContext(MotionContext) ?? true;
}

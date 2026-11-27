import { useEffect, useRef, useState } from "react";
import { copyText } from "../lib/clipboard";
import { Button } from "./ui";

/** A copy action that says what happened: copied, or select and copy by hand when the browser refuses. */
export function CopyButton({ text, label, size = "sm", "aria-label": ariaLabel }: { text: string; label: string; size?: "default" | "sm"; "aria-label"?: string }) {
  const [state, setState] = useState<"idle" | "copied" | "failed">("idle");
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  async function copy() {
    const ok = await copyText(text);
    setState(ok ? "copied" : "failed");
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState("idle"), ok ? 1500 : 4000);
  }
  return <Button type="button" variant="ghost" size={size} aria-label={state === "idle" ? ariaLabel : undefined} onClick={() => void copy()}>{state === "copied" ? "Copied" : state === "failed" ? "Select and copy by hand" : label}</Button>;
}

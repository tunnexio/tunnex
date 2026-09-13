import { useId, useRef, useState, type ReactNode } from "react";
import "./ai-workspace-design.css";

/** Supporting copy is available on hover, keyboard focus and tap. */
export function HelpTooltip({ children, label = "More information" }: { children: ReactNode; label?: string }) {
  const id = useId();
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  const [position, setPosition] = useState({ left: 8, top: 8 });
  function reveal() {
    const rect = trigger.current?.getBoundingClientRect();
    if (rect) setPosition({ left: Math.max(8, Math.min(rect.left, window.innerWidth - 296)), top: rect.bottom + 4 });
    setOpen(true);
  }
  return <span className="ai-help" onMouseEnter={reveal} onMouseLeave={() => setOpen(false)} onBlur={(event) => { if (!event.currentTarget.contains(event.relatedTarget)) setOpen(false); }} onKeyDown={(event) => { if (event.key === "Escape") { event.stopPropagation(); setOpen(false); } }}>
    <button ref={trigger} type="button" className="ai-help-trigger" aria-label={label} aria-describedby={open ? id : undefined} onFocus={reveal} onClick={reveal}>?</button>
    {<span hidden={!open} id={id} role="tooltip" className="ai-help-content" style={position}>{children}</span>}
  </span>;
}

export function modelDisplayName(model: string) {
  return model.replace(/^(?:custom-[a-f0-9-]{36}|openai|anthropic|gemini|openrouter|groq|mistral|cerebras|xai|deepseek)\//, "");
}

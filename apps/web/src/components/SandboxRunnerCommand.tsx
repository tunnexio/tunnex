import { useEffect, useState } from "react";
import { Button, ErrorText } from "./ui";

/** Only public commands supplied by the typed enrollment/trial APIs belong here.
 * Bootstrap tokens have their own one-time ceremony and hidden terminal prompt. */
export function SandboxRunnerCommand({ command, disabled = false, kind = "install" }: { command: string; disabled?: boolean; kind?: "install" | "qualification" }) {
  const [copied, setCopied] = useState(false), [failed, setFailed] = useState(false);
  useEffect(() => { setCopied(false); setFailed(false); }, [command]);
  async function copy() {
    if (disabled) return;
    try {
      if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(command);
      else {
        const input = document.createElement("textarea");
        input.value = command; input.style.position = "fixed"; input.style.opacity = "0";
        document.body.appendChild(input); input.select();
        try { if (!document.execCommand("copy")) throw new Error("copy unavailable"); }
        finally { input.remove(); }
      }
      setCopied(true); setFailed(false);
    } catch { setFailed(true); }
  }
  return <div className="sb-runner-command"><div className="sb-command"><div><span>RUN ON THE SELECTED LINUX GATEWAY HOST</span><Button type="button" size="sm" variant="ghost" disabled={disabled} onClick={() => void copy()}>Copy {kind} command</Button></div><pre aria-label={kind === "install" ? "Public runner install command" : "Public qualification command"}>{command}</pre></div>{copied && <p role="status" className="sb-help">{kind === "install" ? "Install command copied. Paste the token only when the terminal asks for it." : "Qualification command copied. Run it on the same installed host and review its machine administrator prompts."}</p>}{failed && <ErrorText>Copy failed. Select and copy the command above.</ErrorText>}</div>;
}

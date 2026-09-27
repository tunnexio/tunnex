import { useState } from "react";
import { Icon } from "./Icon";
import type { IconName } from "./Icon";

export function RoutingPath({ kind = "approved", destination = "Network", range }: { range?: string; kind?: "approved" | "pending" | "pool" | "vip"; destination?: string }) {
  const [step, setStep] = useState<number | null>(null);
  const reserved = kind === "pool" || kind === "vip";
  const nodes: { icon: IconName; label: string; hint: string }[] = reserved ? [
    { icon: "boxes", label: "Reserved space", hint: "Keep this address space separate from your network ranges." },
    { icon: kind === "pool" ? "laptop" : "network", label: kind === "pool" ? "Devices" : "Kubernetes", hint: kind === "pool" ? "Addresses from this pool are assigned to devices." : "These addresses are reserved for Kubernetes services." },
  ] : [
    { icon: "laptop", label: "Device", hint: "A published route tells the device where to send matching traffic." },
    { icon: kind === "pending" ? "clock-3" : "route", label: kind === "pending" ? "Approval needed" : "Gateway", hint: kind === "pending" ? "This range is withheld until an administrator approves it." : "The site's gateway carries traffic toward the destination network." },
    { icon: "network", label: destination, hint: "A range groups destination IP addresses. Access policies still control who can connect." },
  ];
  return <figure className="route-visual" data-kind={kind} aria-label={reserved ? "Reserved address assignment" : "Illustrated route, not live traffic"}>
    <div className="route-visual-nodes">
      {nodes.map((node, index) => <div className="route-visual-step" key={node.label}>
        {index > 0 && <span className="route-visual-wire" aria-hidden="true"><Icon name={kind === "pending" && index === 2 ? "ban" : "chevron-right"} size={14} /></span>}
        <button type="button" aria-pressed={step === index} onClick={() => setStep(step === index ? null : index)}>
          <span className="route-visual-icon"><Icon name={node.icon} size={22} /></span><span>{node.label}</span>{range && index===nodes.length-1 && <small className="route-visual-range">{range}</small>}
        </button>
      </div>)}
    </div>
    <figcaption aria-live="polite">{step === null ? reserved ? "Reserved allocation · not a route" : kind === "pending" ? "Not published · awaiting approval" : "Configured route · live reachability not verified" : nodes[step].hint}</figcaption>
  </figure>;
}

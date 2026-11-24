// Copy-ready firewall rules that let one gateway reach one TCP port (SA-UX-2 item 1, App Access AA-2).
// Shared presentation only: Server Access and App Access each pass their own gateway and destination.

/** The gateway's address as Tunnex knows it: the host part of its reported endpoint, when that is an IP. */
export function gatewayAddress(endpoint: string | null | undefined): string {
  const value = (endpoint ?? "").trim();
  if (!value) return "";
  const host = value.startsWith("[") ? value.slice(1, value.indexOf("]")) : value.replace(/:\d+$/, "");
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(host) ? host : "";
}

export function firewallRules({ source, host, port }: { source: string; host: string; port: number }) {
  const src = source || "GATEWAY_IP";
  const dst = host || "SERVER_IP";
  const name = `allow-tunnex-gateway-${port}`;
  return [
    { label: "Google Cloud firewall rule", text: `gcloud compute firewall-rules create ${name} --network=NETWORK --direction=INGRESS --action=ALLOW --rules=tcp:${port} --source-ranges=${src}/32 --target-tags=TARGET_TAG` },
    { label: "AWS security group", text: `aws ec2 authorize-security-group-ingress --group-id SECURITY_GROUP_ID --protocol tcp --port ${port} --cidr ${src}/32` },
    { label: "Azure network security group", text: `az network nsg rule create --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --name ${name} --priority 300 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes ${src}/32 --destination-address-prefixes ${dst} --destination-port-ranges ${port}` },
    { label: "ufw (on the server)", text: `sudo ufw allow proto tcp from ${src} to any port ${port}` },
    { label: "firewalld (on the server)", text: `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="${src}/32" port port="${port}" protocol="tcp" accept' && sudo firewall-cmd --reload` },
  ];
}

export function FirewallHelp({ gatewayName, gatewayIp, host, port, summary = "Can't reach the server?", open }: { gatewayName: string; gatewayIp: string; host: string; port: number; summary?: string; open?: boolean }) {
  const rules = firewallRules({ source: gatewayIp, host, port });
  return <details className="text-sm text-ink-secondary" open={open} aria-label={summary}>
    <summary className="cursor-pointer text-ink-body">{summary}</summary>
    <div className="mt-2 space-y-2">
      <p className="max-w-prose">Allow TCP from the gateway <strong>{gatewayName}</strong>{gatewayIp ? <> ({gatewayIp})</> : null} to <strong>{host}</strong> on TCP port <strong>{port}</strong>. {gatewayIp ? "This is the gateway's address as Tunnex knows it; if the gateway and the destination share a private network, or traffic passes through NAT, use the address the destination actually sees (often the gateway's private IP)." : "Replace GATEWAY_IP with the gateway's address as the destination sees it (often its private IP)."} Replace the other upper-case values with your own.</p>
      {rules.map(rule => <div key={rule.label}><p className="text-xs">{rule.label}</p><pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-white/5 p-2 text-xs">{rule.text}</pre></div>)}
    </div>
  </details>;
}

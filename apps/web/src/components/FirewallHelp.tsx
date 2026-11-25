// Copy-ready firewall rules that let one gateway reach one TCP port (SA-UX-2 item 1, App Access AA-2).
// Shared presentation only: Server Access and App Access each pass their own gateway and destination.
//
// The source address is deliberately NOT pre-filled. Tunnex knows only the gateway's public WireGuard endpoint, but a
// gateway reaches a private server from its own LAN address, which Tunnex does not record. A pre-filled public address
// would produce a rule that still blocks; the gateway itself can say which source address it uses.

export const gatewaySourcePlaceholder = "GATEWAY_PRIVATE_IP";

export function firewallRules({ host, port }: { host: string; port: number }) {
  const src = gatewaySourcePlaceholder;
  const dst = host || "SERVER_IP";
  const name = `allow-tunnex-gateway-${port}`;
  return [
    { label: "Google Cloud firewall rule", text: `gcloud compute firewall-rules create ${name} --network=NETWORK --direction=INGRESS --action=ALLOW --rules=tcp:${port} --source-ranges=${src}/32 --target-tags=TARGET_TAG` },
    { label: "AWS security group", text: `aws ec2 authorize-security-group-ingress --group-id SECURITY_GROUP_ID --protocol tcp --port ${port} --cidr ${src}/32` },
    { label: "Azure network security group", text: `az network nsg rule create --resource-group RESOURCE_GROUP --nsg-name NSG_NAME --name ${name} --priority 300 --direction Inbound --access Allow --protocol Tcp --source-address-prefixes ${src}/32 --destination-address-prefixes ${dst} --destination-port-ranges ${port}` },
    { label: "ufw (on the destination)", text: `sudo ufw allow proto tcp from ${src} to any port ${port}` },
    { label: "firewalld (on the destination)", text: `sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="${src}/32" port port="${port}" protocol="tcp" accept' && sudo firewall-cmd --reload` },
  ];
}

export function FirewallHelp({ gatewayName, host, port, summary = "Can't reach the server?", open }: { gatewayName: string; host: string; port: number; summary?: string; open?: boolean }) {
  const rules = firewallRules({ host, port });
  const target = host || "SERVER_IP";
  return <details className="text-sm text-ink-secondary" open={open} aria-label={summary}>
    <summary className="cursor-pointer text-ink-body">{summary}</summary>
    <div className="mt-2 space-y-2">
      <p className="max-w-prose">Allow TCP from the gateway <strong>{gatewayName}</strong> to <strong>{target}</strong> on TCP port <strong>{port}</strong>. To find the address the destination sees, run this on the gateway host and use the address after <code>src</code> in place of {gatewaySourcePlaceholder}:</p>
      <pre className="overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-white/5 p-2 text-xs">{`ip -4 route get ${target}`}</pre>
      <p className="max-w-prose text-xs">If the destination is reached over the internet or through NAT, use the gateway's public outbound address instead. Replace the other upper-case values with your own.</p>
      {rules.map(rule => <div key={rule.label}><p className="text-xs">{rule.label}</p><pre className="mt-1 overflow-x-auto whitespace-pre-wrap break-all rounded-lg bg-white/5 p-2 text-xs">{rule.text}</pre></div>)}
    </div>
  </details>;
}

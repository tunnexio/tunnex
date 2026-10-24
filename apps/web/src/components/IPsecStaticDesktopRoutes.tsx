import { Link } from "react-router-dom";

export function IPsecStaticDesktopRoutes() {
  return <div className="space-y-2 rounded-inset border border-line p-3 text-xs text-ink-tertiary">
    <p className="font-medium text-ink-heading">Desktop return routes in AWS</p>
    <p>Before testing each desktop, configure its assigned VPN IPv4 address as a /32 return route. Find the address in <Link className="text-accent-400 hover:underline" to="/devices">Devices</Link>.</p>
    <ul className="list-disc space-y-1 pl-4">
      <li>VGW: add the /32 to this VPN connection's static routes and route it through the VGW in the application's VPC subnet route table.</li>
      <li>TGW: route the /32 from the application's VPC to the TGW, then through this VPN attachment in the TGW return route table.</li>
    </ul>
    <p>Allow that desktop /32 and the service port in the application's security rules. Update the routes if the desktop's assigned address or VPN attachment changes. Saving access in Tunnex does not change AWS routes.</p>
  </div>;
}

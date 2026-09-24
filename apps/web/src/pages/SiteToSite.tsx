import { Link } from "react-router-dom";
import { Card, PageHeader } from "../components/ui";

export default function SiteToSite() {
  return (
    <div className="space-y-6">
      <PageHeader
        title="Site-to-site"
        subtitle="Connect office and cloud networks so their devices can reach each other."
      />
      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <section aria-labelledby="wireguard-heading" className="space-y-4">
            <p className="text-sm text-ink-secondary">WireGuard</p>
            <h2 id="wireguard-heading" className="text-xl font-semibold">
              Connect using Tunnex
            </h2>
            <p>
              Use a Tunnex gateway at each location. Devices behind the gateways
              do not need the Tunnex client installed.
            </p>
            <ol className="list-decimal space-y-2 pl-5 text-ink-secondary">
              <li>Add each network using an existing or newly enrolled gateway.</li>
              <li>Review the site routes and allow the traffic you need.</li>
              <li>Configure return routes and test access between devices.</li>
            </ol>
            <div className="flex flex-wrap gap-4">
              <Link className="underline underline-offset-4" to="/network/setup">
                Add a network
              </Link>
              <Link className="underline underline-offset-4" to="/sites">
                Manage existing sites
              </Link>
            </div>
          </section>
        </Card>
        <Card>
          <section aria-labelledby="ipsec-heading" className="space-y-4">
            <p className="text-sm text-ink-secondary">IPsec · Not available yet</p>
            <h2 id="ipsec-heading" className="text-xl font-semibold">
              Connect an existing VPN
            </h2>
            <p>
              Planned support for connecting a local Tunnex gateway to a
              compatible cloud-managed VPN or firewall.
            </p>
            <p className="text-ink-secondary">
              This method will not require a Tunnex gateway at the remote VPN
              endpoint. IPsec connections cannot be configured in this release.
            </p>
          </section>
        </Card>
      </div>
      <Card>
        <section aria-labelledby="access-heading" className="space-y-3">
          <h2 id="access-heading" className="text-lg font-semibold">
            Choose what can communicate
          </h2>
          <p className="text-ink-secondary">
            Review your access policies and routes before connecting networks. A gateway handshake confirms the tunnel;
            test a destination device to verify the full network path.
          </p>
          <div className="flex flex-wrap gap-4">
            <Link className="underline underline-offset-4" to="/access">
              Review access policies
            </Link>
            <Link className="underline underline-offset-4" to="/routed-ranges">
              Review routed ranges
            </Link>
          </div>
        </section>
      </Card>
    </div>
  );
}

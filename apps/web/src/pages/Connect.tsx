import { Link } from "react-router-dom";
import { ClientConnection } from "../components/ClientConnection";
import { Card, PageHeader } from "../components/ui";
import { useOrg } from "../lib/useOrg";
import "../setup-guide.css";

export default function Connect() {
  const { org } = useOrg();
  return <div className="setup-guide space-y-5">
    <PageHeader title="Connect your computer" subtitle="Get the Tunnex client and make your first connection."/>
    <Card><ClientConnection organization={org?.name}/></Card>
    <Link className="setup-text-link" to="/devices">View your devices and connection status →</Link>
  </div>;
}

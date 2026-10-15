import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen } from "@testing-library/react";
import { PrivateDNSLANStatus } from "../src/components/PrivateDNSLANStatus";
import type { FQDNResolverProfile, Node } from "../src/lib/api";

afterEach(() => cleanup());
const profile: FQDNResolverProfile = { id: "profile-new", name: "Office", provider_hint: "on_premises", zone_suffixes: ["office.test"], endpoints: [], legacy_default: false, lan_listener: { address: "192.168.1.39", interface: "eth0", allowed_sources: ["192.168.1.0/24"] } };
const gateway = (ready: boolean, profileId = profile.id, age = 0): Node => ({ id: "gateway", name: "Office gateway", status: "active", agent_version: "test", enrolled_at: new Date().toISOString(), dns_lan_reported_at: new Date(Date.now() - age).toISOString(), dns_lan_listeners: [{ address: "192.168.1.39", interface: "eth0", ready, error: ready ? "" : "TCP port 53 unavailable", profile_ids: [profileId] }] });
describe("LAN DNS status", () => {
  it("requires current immutable profile identity and a fresh report before showing listening", () => {
    const { rerender } = render(<PrivateDNSLANStatus profiles={[profile]} gateway={gateway(true, "profile-old")} onRefresh={() => {}} />);
    expect(screen.getByText("Waiting for this profile version to apply")).toBeTruthy();
    rerender(<PrivateDNSLANStatus profiles={[profile]} gateway={gateway(true, profile.id, 91000)} onRefresh={() => {}} />);
    expect(screen.getByText("Awaiting a current gateway report")).toBeTruthy();
    rerender(<PrivateDNSLANStatus profiles={[profile]} gateway={gateway(true)} onRefresh={() => {}} />);
    expect(screen.getByText("Listening on UDP and TCP 53")).toBeTruthy();
    expect(screen.getByText(/Listener status confirms local sockets only/)).toBeTruthy();
  });
  it("shows a bind conflict and allows a refresh", () => {
    const refresh = vi.fn();
    render(<PrivateDNSLANStatus profiles={[profile]} gateway={gateway(false)} onRefresh={refresh} />);
    expect(screen.getByText("Unavailable: TCP port 53 unavailable")).toBeTruthy();
    fireEvent.click(screen.getByRole("button", { name: "Refresh listener status" }));
    expect(refresh).toHaveBeenCalledOnce();
  });
});

it("shows public upstreams and exact private zones and client scope", () => {
 render(<PrivateDNSLANStatus profiles={[{...profile,lan_listener:{...profile.lan_listener!,default_upstreams:["1.1.1.1","8.8.8.8"]}}]} gateway={gateway(true)} onRefresh={()=>{}} />);
 expect(screen.getByText(/Private zones: office.test. DNS clients: 192.168.1.0\/24/)).toBeTruthy();
 expect(screen.getByText("Other domains: 1.1.1.1, 8.8.8.8 · UDP/TCP 53")).toBeTruthy();
 expect(screen.getByText(/verify private and public names over UDP and TCP/)).toBeTruthy();
});

it("describes private-only siblings without requiring another forwarder for a shared full-DNS listener", () => {
 const publicProfile={...profile,id:"public-profile",name:"Cloud",zone_suffixes:["cloud.test"],lan_listener:{...profile.lan_listener!,default_upstreams:["1.1.1.1"]}};
 render(<PrivateDNSLANStatus profiles={[profile,publicProfile]} gateway={gateway(true)} onRefresh={()=>{}} />);
 expect(screen.getByText("Private zones for this profile · other-domain DNS not enabled here")).toBeTruthy();
 expect(screen.getByText("Other domains: 1.1.1.1 · UDP/TCP 53")).toBeTruthy();
 expect(screen.getByText(/If no profile does, keep your existing office DNS server/)).toBeTruthy();
 expect(screen.queryByText(/Private-only listeners require/)).toBeNull();
});

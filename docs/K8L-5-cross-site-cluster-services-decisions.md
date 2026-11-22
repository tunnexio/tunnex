# K8L-5 — one connection reaches every cluster

Story branch: `story/kubernetes-launch-fixes`. Found on 2026-11-22 with two clusters on one control
plane: k3s in the "On-prem datacenter" network and GKE Standard in the "Google Cloud" network.

## What happened

A laptop connected through the on-prem gateway opened the on-prem cluster's Service, but the GKE
cluster's Service timed out, by address and by name. The client had the route (`100.65.0.0/16`) and
the DNS zone (`gke.k8s.corp.internal`) for it, and the name resolved. There was no error anywhere.

## Cause

Two halves of the product disagreed.

- Clients are given every cluster's address range in the organisation
  (`sites.ListRoutedRanges`), whichever gateway they connect through.
- Gateways were given a cluster's Service addresses only inside the cluster's own network
  (`k8sHandoffGraph`: an edge gateway and the in-cluster gateway of the same site). The site link
  between networks carried each network's approved ranges and nothing else.

So the first gateway received a packet for `100.65.0.3` and had no peer to send it to.

A person does not pick a gateway per application. They connect once; access rules decide what they
reach. Which gateway they landed on must not decide it.

## Decision

1. A network's contribution to the site link is its approved ranges **plus the Kubernetes Service
   addresses served inside it** (each exposed Service's address and the cluster's DNS address, as
   /32s). `siteTopology.siteAdvertised` is the one place that says so; `siteLinkGraphFrom` uses it
   for routes and for peer AllowedIPs, hub and spoke alike.
2. The addresses come from the same fail-closed inputs as the in-site path: a Service whose
   in-cluster gateway is unresolved, revoked, without an endpoint, or an ineligible pool owner is not
   advertised. Nothing is advertised for a cluster with no exposed Service.
3. Exact /32s, not the cluster's whole range. A gateway never accepts traffic for an address it does
   not serve, and unexposing a Service withdraws its route on the next compile.
4. Permission is unchanged. This is reachability; the serving gateway still applies the compiled
   access rules to the device's address, as it does for a device in its own network.
5. No agent change, no schema change, no API change. With no cluster registered the compiled graph
   is byte-identical to before.

## What this does not change

- A device connected through a gateway that is not a hub member still cannot cross sites. That
  limit already applies to ordinary private ranges (A3b) and is not specific to Kubernetes.
- Where a network has a separate edge gateway and an in-cluster gateway, cross-site traffic arrives
  at the network's carrier and uses the existing in-site handoff from there.

## Proof

- Unit: `TestSiteLinkCarriesAnotherSitesClusterServices` — the device's gateway routes the other
  site's Service and DNS addresses to that site's peer; the serving gateway does not route its own
  addresses back; without a cluster the peer carries only the subnet. Existing site-link, carrier,
  hub-set and failover tests pass.
- Live, 2026-11-22, laptop connected once through the on-prem gateway:

      http://100.64.0.3/                                 200   (k3s pod 10.42.0.10)
      http://orders.shop.svc.onprem.k8s.corp.internal/   200
      http://100.65.0.3/                                 200   (GKE pod 10.172.0.15)
      http://orders.shop.svc.gke.k8s.corp.internal/      200

  Before the change the last two timed out. The on-prem gateway's peer for the GKE gateway went
  from `10.70.0.0/24` to `10.70.0.0/24 100.65.0.2/32 100.65.0.3/32`.

  This is also the first proof of the GKE Standard data path (Container-Optimized OS, kube-proxy
  iptables, `IP-MASQ`): device to gateway to pod and back.

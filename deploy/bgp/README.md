# Pinned FRR package

BGP2 installs Alpine v3.24 `frr=10.6.1-r0` after exact architecture-specific APK
SHA256 verification and Alpine signature verification. The package provides
bgpd, zebra and vtysh; the managed executable copies reside in `/opt/tunnex-bgp`.
No OpenRC package, service launch, default BGP configuration or capability
advertisement is added. Tunnex must use bgpd `--no_kernel` and separately qualify
managed zebra observations before enabling BGP. Package presence is not a
session, kernel route, forwarding or AWS acceptance proof.

`apps/node/internal/bgp.ProbePackage` checks root ownership, executable modes,
absence of symlinks throughout the executable paths, supported native ELF
architecture and exact bgpd 10.6.1 version. Version execution has a two-second
limit and 4096-byte output cap. The probe runs no daemon.

Focused qualification:

- `go test ./internal/bgp` verifies refused unsafe inputs and bounded output.
- Compile Linux arm64 and amd64 test binaries with `go test -c`.
- In the corresponding native disposable Alpine3.24.2 container, install with
  `install.sh`, copy the compiled test binary into the container filesystem and
  run `TUNNEX_BGP_PACKAGE_TEST=1 package-test -test.run TestBundledPackage -test.v`.
- The opt-in test verifies the real binary succeeds and refuses a mismatched
  version/architecture, writable native executable and symlink substitution.

Dependencies use the pinned base image's Alpine repositories; the FRR package
itself is pinned by signed APK and SHA256. This does not claim reproducible
builds or immutable hashes for all transitive dependencies.

# BGP3 transport qualification

`qualify_transport.py` requires immutable native node image and native Linux
IPsec test binary. It creates only the dedicated labeled internal network and
gateway/peer containers, refuses existing names and removes exact owned IDs.
It proves two real strongSwan broad0/0 CHILDs using independent VICI and kernel
XFRM IDs/reqids/SPIs/policies; exact inside-peer TCP179 echo succeeds through each
encrypted tunnel, with encrypted byte readback. WAN and wrong inside-source
attempts fail. There are no application grants. These are synthetic component
leases, not integrated control-plane activation or AWS acceptance.

Example: `python3 deploy/bgp/qualify_transport.py --binary <native-ipsec-test>
--image sha256:<immutable-node-image> --evidence <new-private-directory>`.
The receipt binds image, binary and harness hashes and records exact fixture
cleanup. BGP runtime controller remains fail-closed until BGP4–7 qualification.

# BGP4 supervised sessions qualification

The signed package's zebra requests SYS_ADMIN. `build_observer.sh` builds the
pinned FRR 10.6.1 source with the fully checked-in, SHA256-verified patch applied
with zero fuzz: remove that capability request and explicitly refuse namespace
VRF backend. Its private source-built libfrr is selected through the observer's
RPATH. Packaged bgpd runs with supported `-S` and immutable `-n`; vtysh remains
the signed package binary. No daemon starts during image construction.

Each managed session binds exact inside addresses and private root-owned Unix
VTY sockets; TCP VTY is disabled. The per-neighbor connected-prefix check is
bypassed only after exact UP XFRM ID, local /30 and main-table peer /32 protocol
242/slot metric readback. eBGP retains TTL1. Import/export prefix lists match only
approved exact prefixes; local export paths require UP physical connected or
explicit routed LAN reachability. No redistribution is configured.

Add `--sessions` to the transport qualification for two real encrypted sessions,
actual approved prefix exports, SYS_ADMIN absence in effective/bounding sets,
all-table kernel baseline preservation, honest peer daemon loss, and owned
supervised restart/reestablishment. `--sessions --wrong-asn` requires both peers
non-established with zero accepted prefixes. These remain synthetic component
leases; they neither advertise runtime capability nor enable CP activation.
Node crash recovery and route ownership integration belong to BGP5–7.

# BGP5 route ownership qualification

`--sessions --routes` uses UUID-derived product link names/XFRM IDs/generation
aliases and IPv4-only link setup. The native Go node helper first verifies the
peer-only kernel baseline, then reads the fixed filtered BGP RIB command and
journals exact pending prior/target route tuples before invoking the product
route writer. FRR's selected bestpath determines each prefix's slot. Readback
commits ownership; failed writes or final readback retain the potential union.
Unjournalled tuples, even matching protocol242, are refused.

A separate client and external target exercise the forwarding hook: an actual
learned route without a grant denies TCP18080, while the exact explicit grant
permits encrypted request/reply. CHILD reqids are independently read back and
are distinct from XFRM interface IDs. The component uses synthetic authority;
CP activation, failover and abrupt node crash recovery remain separate gates.

`--sessions --maximum-prefixes 64` proves the maximum approved prefix RIB using
64 qualified local exports and 64 approved remote prefixes with two paths each.
Summary output remains bounded to64KiB; filtered RIB collection has a separate
1MiB ceiling plus exact prefix/path cardinality and two-second command timeout.
MaximumPrefixes limits accepted routes per peer; the selected union is limited
by the approved remote prefix set, at most64. No rejected count is invented.

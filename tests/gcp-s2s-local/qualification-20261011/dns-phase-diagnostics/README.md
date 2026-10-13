# Source-only DNS exchange phase diagnostics

Base gateway source0249. Fixed existing RuntimeDiagnostic events measure each native proof and socket stage separately, with connection UUID, elapsed milliseconds, refused and context state only. No hostname, answers, request payload or error body is emitted. Original five-second context, source binding, full guard/native proofs, endpoint consensus and deadline refusal remain unchanged.

Actual mailbox100-row capture had matching context2/Profile459d throughout; application31 NOERROR, alias7 NOERROR/11 completed resolver_unavailable/13 expired, NX27 NXDOMAIN. These classifications are not a causal proof. Expired requests lack an accepted completion by deadline and can include undelivered or in-flight work. Diagnostics are not deployed; no traffic-recovery or scheduler-fix claim.

Standalone observational CLI was rejected as source-equivalent: DNSRuntimeTransport requires the running controller's private owner view, epoch and PermitLeaseAuthority. Creating an authority from journal/public liveness would weaken the boundary. No such adoption was added.

Default successful events remain Debug; only explicit owned-lab environment `TUNNEX_IPSEC_DNS_DIAGNOSTICS=1` promotes fixed successful DNS phases to Info. Refusals remain Warn and other successful operations remain Debug. This environment difference requires separate replacement review; it is not already configured on current gateway.

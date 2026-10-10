# GCP HA application, resolver-context and MTU checkpoint

This private staging archive preserves exact existing key-free JSON/JSONL bytes. Its manifest records original paths, SHA256 and sizes. No new packet, API or cloud action was performed to construct it. Deployed artifact source remains `9c3ab006c13b72285f43baed1805da1af273ffa7`; document HEAD changes do not change that source.

HA ordinary TCP8080/UDP9000 application traffic passed after normal grants, with exact target observations and zero capture drops. The pre-grant denial receipts are retained separately. The full ordinary graph after those grants is 9 connections, 15 resources, 14 policies and three configuration views, pinned by receipt4ac53ba6.

Normal resolver context version2 preserves Classic and adds HA with source10.70.0.2 and inbound10.80.0.2, TCP/UDP53. Resolver configuration itself supplies authenticated `DNSResolverGrants` through the existing runtime DNS profile path. Ordinary DNS53 resources/policies were not needed or created. The initially attempted DNS-deny observation after context creation correctly refused because exact host-origin authority was already present; those refusal receipts are retained. Later strict DNS allow observations passed. This corrects the superseded plan that required an additional ordinary53 grant.

Actual HA single-case A, alias CNAME and NXDOMAIN wire receipts each have `completed:true` and `accepted:true`, with separate full DNS guard observations before and after. These qualify selected-context DNS resolution. They do not prove automatic FQDN generations, FQDN-only IPsec application enforcement, continuous availability or a latency guarantee.

MTU evidence is bounded: 1200-byte UDP echoed exactly; 1354-byte DF UDP echoed exactly; 1355-byte DF UDP was refused with errno90 and observed ICMP fragmentation-needed metadata MTU1382. A 1400-byte non-DF request reached and reassembled at the target, but its reply timed out. There is no fragmented round-trip acceptance claim. Early MTU v1/v2 diagnostic failures remain separate. Public socket errorqueue inspection was corrected after actual timeout-mode versus nonblocking behavior was reproduced; no production MTU setting was changed.

Role/mobile and human two-tab CAS acceptance remain pending. Private credentials, PSKs, raw stderr and secret inputs are excluded. Source/preparation tests are not live packet proof. Further DNS fallback evidence will be appended only after actual receipt validation.

# Source-only terminal CNAME answer reuse

Integration candidate base: 372e43ac935591f287aae02b023bba8de1b43a66. Original candidate f0f858 was qualified against 0249.

This candidate avoids a terminal address query only when the same endpoint's current wire response already includes a complete, applicable CNAME chain and positive terminal records of that requested family. Names, cycles, addresses, TTLs and unrelated records are checked before reuse. Each endpoint retains its independent workflow and final consensus; no native proof, authority, deadline or cross-endpoint answer is cached.

The modeled one-hop alias fixture changes four exchanges per endpoint to three: alias A, alias AAAA, and terminal AAAA. The terminal A exchange is redundant in that fixture; AAAA remains necessary because its response has no terminal AAAA. This is a local query-count result, not a demonstrated cause of historical live mailbox expiry. Keep this candidate unintegrated until actual phase diagnostics identify the bottleneck.

Qualification:
- Original unchanged-source query-shape overlay passed (0.890s), showing four exchanges per endpoint despite terminal A already in the alias response.
- Candidate focused race tests passed (2.022s): complete/incomplete chains, endpoint isolation, disagreement, negative/unknown responses, TTL/address/cycle/branch validation.
- Full fqdnrpc suite passed (7.409s) with permission for local loopback fixtures. Initial sandbox run refused existing loopback listeners; that failure was not interpreted as a product regression.

No live DNS, cloud, API or deployment action was performed. Candidate changes are confined to fqdnrpc.go and its new causal test file; this README is qualification metadata.

ROOT supplied an actual successor60s window: 28 before-proofs completed in283–668ms, 28 socket phases in4–34ms (total243ms), 26 after-proofs in289–731ms and two ACTIVE after-proof refusals. This supports reducing an independently proven redundant exchange but does not identify those refusals as an alias query-count fault. Fixed events lack request IDs; concurrent jobs cannot be assigned uniquely. The same deadline and fresh proof-before/proof-after for every remaining exchange are preserved.

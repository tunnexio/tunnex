# Classic application expiry observation

Source-only tool pinned to the deployed 4143d866 container, image, boot,
network namespace and qualified nft reader. It does not issue policy, refresh a
lease, mutate the gateway or prove packet delivery. Only the coordinator may run
capture.py after reviewing its exact pinned inputs; any replacement invalidates
those pins and must refuse rather than silently rebaseline.

capture.py accepts only a unique private evidence filename, reserved exclusively
before SSH. It brackets the complete owned table with unchanged expected guard,
namespace and full `ip -j -d link show` inventory. No `-s` counter inventory is
requested or filtered. Private failures are retained without automatic retries.

The Go command reads that private capture on stdin with `--expect allow|deny`
and `--protocol tcp|udp`. It uses unmodified production full readback first.
Allow requires one exact Site70 → 10.81.0.10/32 original forward rule for TCP8080
or UDP9000 and all three positive Classic lease sets; an unrelated expired
member prevents full positive proof. Deny requires no matching, wider or
unclassified original forward accept and the exact permanent remote81 drops.
A structural withdrawal match can support rule absence observation but cannot
supply lease, cleanup, route or packet authority. Zero-life nonempty membership
is never treated as physical absence.

Guard revision is not a control-plane policy revision. The coordinator must
bind normal API policy/resource identity and original expiry externally; nft
rules do not encode a per-rule policy ID. Capture and output hashes preserve
observations without inventing that association.

Qualification is modeled producer/readback testing only. Neither collector nor
observer has been executed against the cloud by this agent.

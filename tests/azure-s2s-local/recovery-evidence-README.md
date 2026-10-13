Run the source-only exporter on the owned peer after recovery. It performs no cloud commands and changes no connection intent:

```sh
sudo python3 tests/azure-s2s-local/export-recovery-evidence.py \
  --private-root tests/azure-s2s-local/.runtime \
  --initial-refusal docs/evidence/azure-s2s-20261010/genuine-reboot-recovery.json \
  --read-current \
  --output tests/azure-s2s-local/.runtime/recovery-export.json
```

The output must be a new filename. Inputs are fixed private, owner-only receipt files. Packet projections contain timestamps, fixed owned source/service binding, counters, observed success gaps and source-preservation categories. They contain no bodies, credentials, journals or arbitrary response fields. Missing receipts remain missing; malformed receipts refuse export.

The initial `genuine-reboot-recovery.json` remains unchanged and is identified by its SHA-256. It records the initial `6e53e071` saved-refusal failure. Root separately observed normal cleanup revision 5 acknowledgement, enable revision 6, both tunnels up, and post-boot packets on `cbdf882f`; exact saved cleanup/enable receipt files are unavailable, so the exporter explicitly records that limitation. `postboot-reenabled-packets.json` and the failed warm restart's `anchored-active-restart-cbdf882f-packets.json` are exported separately. The warm restart summary is omitted until its schema is independently verified.

`--read-current` runs the existing normal API lifecycle **read** phase, then revalidates a typed projection of desired revision/intent, application and cleanup states, tunnel states, BGP peer counters and owned route count. It never assumes current tunnels are up. Read failure is recorded without raw errors. Current status does not establish application reachability; historical packet observations do not establish present readiness. The lifecycle reader writes its separate private read receipt as usual.

Run the exporter as root. It accepts only the exact UID 1000-owned, mode 0700 private directory without symlink ancestors. Fixed packet inputs must be root-owned mode 0600. The normal API reader runs through `sudo -u #1000`; its private setup/allocation inputs must be UID 1000-owned mode 0600. No other owners are accepted. The merged output is root-owned mode 0600. Package the unchanged initial refusal JSON alongside the helpers and pass its explicit path; a repository checkout is not required.

Optional fixed packet files now include `controlled-recovery-fd6eeaff-packets.json` and `controlled-healthy-restart-12cfccbb-packets.json`; absence is explicit. The original warm restart failure remains a separate receipt. These post-recovery runs prove observations during their own windows. The LAN namespace was reconstructed, so they do not establish continuity of a pre-restart LAN socket or zero outage.

When the fixed root-owned mode0700 `controlled-namespace-stop-2` directory exists, the exporter reads only `before.json`, `stopped.json`, and exact UUID-named `assemble-UUID` directories. It requires exactly one accepted `result.json` (`exact_gate_released`, `runtime_acceptance:not_observed`) and projects its `fresh-runtime.json` identities/hashes. It counts attempts lacking a result without reading arbitrary logs, receipts or journals. The initial transient receipt-install refusal has no saved typed receipt and remains explicitly unavailable/unclassified. Current API status is still read separately; gate release alone does not prove runtime or application recovery.

If strict export refuses, run `diagnose-recovery-export.py` with the same `--private-root`, `--initial-refusal`, and optional `--read-current` arguments under root. It emits only fixed stage/file labels and missing-field/type/refusal categories, never values or raw exceptions. Packet required-field diagnosis precedes the unchanged strict projection. Independent stages continue after a refused receipt. The optional normal read has the existing private read-receipt side effect; the diagnostic creates no export and mutates no connection intent. The reviewed probe source writes `packet_run_elapsed_seconds`, `packet_finished_at`, counters and samples; older/incomplete receipts are diagnosed, not silently converted.

Docker `StartedAt` may contain RFC3339 nanoseconds. The exporter accepts only a strict date/time with optional 1–9 fractional digits and `Z` or `±HH:MM`. It validates the calendar and timezone through a Python3.10-compatible parse string with at most six fractional digits, then emits the **original observed timestamp string**, preserving nanosecond precision. Invalid dates, offsets, missing timezone, extra precision or suffix text refuse. The finer diagnostic reports only pass/refusal for fixed boot/container/PID/hash/timestamp fields; it does not print their values. Compatibility tests verify the exact six-digit parser input and preserved nine-digit output, but local tests alone do not attribute the peer's earlier refusal.

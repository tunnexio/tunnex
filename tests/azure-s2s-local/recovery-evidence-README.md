Run the source-only exporter on the owned peer after recovery. It performs no cloud commands and changes no connection intent:

```sh
python3 tests/azure-s2s-local/export-recovery-evidence.py \
  --private-root tests/azure-s2s-local/.runtime \
  --read-current \
  --output tests/azure-s2s-local/.runtime/recovery-export.json
```

The output must be a new filename. Inputs are fixed private, owner-only receipt files. Packet projections contain timestamps, fixed owned source/service binding, counters, observed success gaps and source-preservation categories. They contain no bodies, credentials, journals or arbitrary response fields. Missing receipts remain missing; malformed receipts refuse export.

The initial `genuine-reboot-recovery.json` remains unchanged and is identified by its SHA-256. It records the initial `6e53e071` saved-refusal failure. Root separately observed normal cleanup revision 5 acknowledgement, enable revision 6, both tunnels up, and post-boot packets on `cbdf882f`; exact saved cleanup/enable receipt files are unavailable, so the exporter explicitly records that limitation. `postboot-reenabled-packets.json` and the failed warm restart's `anchored-active-restart-cbdf882f-packets.json` are exported separately. The warm restart summary is omitted until its schema is independently verified.

`--read-current` runs the existing normal API lifecycle **read** phase, then revalidates a typed projection of desired revision/intent, application and cleanup states, tunnel states, BGP peer counters and owned route count. It never assumes current tunnels are up. Read failure is recorded without raw errors. Current status does not establish application reachability; historical packet observations do not establish present readiness. The lifecycle reader writes its separate private read receipt as usual.

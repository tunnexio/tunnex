# F07 released Access Events route

- Released page: `https://internal.tunnex.app/access-events` from the exact F07 web image.
- The Agent selector contained `f07-agent-20260816T0618Z`; the table showed its real ALLOW and DENY rows with current-name labeling.
- Opening the real allow row rendered a factual timeline with:
  - source agent ID and configuration revision `1`
  - gateway ID, applied policy version `4` and hash `315c0e233f55`
  - `10.99.0.7 -> 10.99.0.200`, TCP/18080 and exact rule ID
  - `ALLOW`, `matched grant`, ingest sequence and observation time
- The page explicitly stated that gateway/rule names are current labels and were not recorded historically. It did not invent a human/workflow trigger.
- Immediate DEMO -> demo2 switch rendered only `Loading access events...`; the old F07 agent, rows, filter and open detail were absent before the new organization response. After demo2 loaded, no F07 agent fact was present. Switching back to DEMO restored the correct organization data.

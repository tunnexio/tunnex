# cac7 bounded HA timing acceptance

The owned one-peer fault run accepted on source `cac7ffd17e162841f90fa8a7299587349e62d262`. Fresh native/API/production guard and HA+Classic payload phase proofs passed before, during secondary-path use and after primary-path recovery. Actual UDP4500 drop counters were positive; exact owned fault cleanup, original target source restoration and an independent final native/full-guard checkpoint passed. The complete experiment took 76.441 seconds; the four-stream observation covered 59.132 seconds and 567 recorded samples.

| Stream | Attempts / replies | Timeouts | Transport failures | Largest observed interval between replies |
| --- | --- | --- | --- | --- |
| Retained TCP, same tuple | 187 / 187 | 2 | 0 | 8.349 s |
| Retained UDP, same socket | 187 / 183 | 4 | 0 | 10.024 s |
| Fresh TCP per attempt | 99 / 86 | 11 | 2 | 14.781 s |
| Fresh UDP per attempt | 92 / 80 | 12 | 0 | 23.027 s |

Retained TCP timeouts and later replies are separately counted; 187 replies do not imply every response arrived before its individual timeout. These are sampled reply intervals, not exact outage lengths. The records include failed attempts and transport errors, and do not establish zero loss, uninterrupted availability, asymmetric exhaustive coverage, host HA or an SLA. The owned threaded HTTP fixture was used only for this measurement, then the original 503-byte target source was restored.

The original v2 overall failure is retained separately: the strict recovery census encountered two established primary IKE/CHILD pairs and refused before canonical recovery. Its target restoration succeeded. The v3 classifier admits only that exact known recovery state as bounded metadata-only pending, with no guard or packet acceptance until canonical three-CHILD/SAD6 recovery. No historic failure is relabeled.

[Public evidence](public-evidence.json) contains only source/artifact/receipt hashes and allowlisted scalars. Raw native tables, journal, logs, tuples, private configuration and credentials remain private. GCP-7's bounded fresh/existing-flow measurement criterion is accepted for this run; the enrolled-client DNS criterion and final eleven-story signoff are separate. CI, publication and production availability are not claimed.

## Ordinary client DNS setup boundary

Verified WireGuard clients use the existing normal user/group grant path to the resolver endpoints on TCP/UDP53. A WireGuard device-pool CIDR by itself has no policy placement; the approved LAN-contained CIDR contract is unchanged. A user grant applies to eligible devices of that user, rather than providing a device-specific grant. DNS permission does not create an application grant, and these checks do not qualify FQDN-only IPsec application authorization. The enrolled-client run is still a separate pending acceptance criterion in this archive.

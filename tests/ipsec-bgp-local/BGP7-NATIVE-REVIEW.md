# BGP7 native receipt review — serving activation gate closed

This document records review criteria and scoped native evidence; it does not authorize a serving refresh, serving lifecycle stop or activation. Runtime source/tests belong to the runtime agent. Keep the existing local/cloud CP-enrolled gateway unchanged until the root explicitly releases the accepted step.

## Evidence acceptance checklist

| Review item | Required actual native evidence | Refuse acceptance when |
| --- | --- | --- |
| Source/profile binding | Immutable image, serving/test binary and harness hashes; native architecture; source manifest; exact fixture container/network IDs and namespace | Receipt belongs to an earlier source/image, emulated architecture or unrecorded namespace |
| Final journal format | Actual v7 journal containing the BGP contract3 entry, exact delivery binding and recorded process generation | Fixture still exercises an old journal or static contract2 only |
| Real private directory | Exact `bgp-<delivery UUID>-gN` directory, root0700, immutable device/inode; private0600 known config/lock/PID/socket identities | A generic temporary directory substitutes for generation ownership; symlink, group access or writable executable admitted |
| Supervisor identity | Actual original supervisor PID/startticks/executable identity, boot ID and namespace; executable0700 or0755 exactly | Liveness is inferred from a name, PID alone or a forged record |
| Children | Exactly owned zebra/bgpd PID/startticks/ELF device/inode identities at ready state; private patched observer; bounded capabilities/noSYS_ADMIN | A foreign daemon is adopted or namespace privileges widened |
| Abrupt parent death | SIGKILL of the exact owned fixture supervisor after scheduler/GC churn; two original children absent or matching zombies; peer export/session loss observed | Only a clean exit, a marker file, different PID or eventual child process count is shown |
| Export absence | Independent peer observation after crash; both sessions no longer established/accepted; no product forwarding authority persists | Only `Process.Alive=false` is reported while peers still receive exports |
| Exact known-file cleanup | Original device/inode/mode identities matched, children absent, original lock acquired; only recorded files removed, lock last; directory durable/fsynced empty | `rm -rf`, glob deletion, inferred filenames or unproved process death replaces the product cleanup |
| Unknown artifact | Actual unrecorded file/inode/content retained; product refuses deletion/adoption and preserves the obligation | Test deletes unknown files externally to make recovery succeed |
| Held lock/foreign process | Independently held original lock or genuine foreign process remains intact; product refuses unsafe cleanup/signaling | Test releases the lock/terminates foreign state before capturing refusal, or merely mocks a busy result |
| Process generation recovery | Next actual reserved generation uses gN+1; predecessor identity appended unchanged except allowed cleaned/retired-uncertain stage; ready new children recorded | Old history is overwritten, generation reused or current-process state is reset to nil to evade obligations |
| Retired uncertain history | Exact old directory/artifacts survive uncertain retirement; append-only `BGPProcessRetired`, contiguous generation bound and max16 enforced | Retirement is interpreted as permission to delete unknown residue, acknowledge cleanup or erase duties |
| Old routes/guard | Go-owned route/journal and denial identity retained through crash; fresh CP lease required before forwarding recovery | FRR writes kernel routes, route learning grants access or crash automatically restores a stale application permit |
| Actual namespace reset | Root Linux-host observer proves exact controlled Docker stop, empty old cgroup, no old namespace holders in two passes, exact retained die event and unchanged stopped journal | Namespace disappearance/string inequality, test-crafted JSON, new boot string or recreated container alone is called a supervisor proof |
| Trusted assembler | Production `ipsec-restoration-receipt` consumes root0600 stopped journal/evidence and actual new boot/namespace; exact entry digest/owner/delivery binding; output mode0600 create-only | Test directly manufactures `runtimeRestorationReceipt` as the native acceptance path |
| Startup gate | Real privileged lifecycle supervisor installs protected `restoration-startup-gate` before stop and retains it until the exact receipt is durably installed | New agent begins an ordinary Apply before receipt, or inode reuse silently selects same-namespace recovery |
| Restored history | Old namespace/generation/process/route duties remain in validated retired restoration history; new generation and current namespace facts independently observed | Old journal namespace is edited in place, duties flattened away or history erased |
| Negative reset cases | Foreign owner/delivery/digest, missing event/holder proof, changed state mount, modified stopped journal and unknown residue all refuse without mutation | Happy-path receipt alone is accepted as sufficient lifecycle coverage |
| Final cleanup | Exact owned fixture IDs removed only after receipts; live serving CP/GW IDs/volumes/certificates unchanged; raw sensitive evidence private | Generic Compose down or cleanup of other agent/root projects |

The existing normal-session `--crash` component receipt does not on its own prove the full v7 controller generation/history/reset path. Separate evidence must identify which rows it actually covers. Local/native/component and actual CP-enrolled forwarding evidence remain distinct.

## Genuine supervised reset topology and sequence

Use only a newly owned disposable Linux Docker fixture, with its own persistent root-private journal mount and private evidence directory. Two-peer containers remain independent namespaces; only the explicitly owned lifecycle subject is stopped. No serving local/cloud gateway is a lifecycle subject while the gate is closed. The observer must run root on the Linux Docker host, not on macOS and not in a container that cannot see host cgroups/namespace holders. For Colima this means the Linux VM host; for the new AWS gateway it means that exact owned Linux host through the designated bastion. No AWS CLI is needed for this proof.

Before a future authorized run, verify actual cgroup v2 membership for the inspected Docker PID. The observer supports exactly `/docker/<full container ID>` or `/system.slice/docker-<full container ID>.scope`, mapped to the corresponding path under `/sys/fs/cgroup`. The inspected PID must occur in that exact cgroup's `cgroup.procs`, and its membership is independently reread. Unsupported layouts remain a refusal; evidence must never relabel a scope.

The release sequence should be:

1. Capture the real v7/contract3 entry, process identity, exact journal/state mount and running old fixture ID. Require ten stable full-entry observations with both peers established and one committed owned route; keep journal files root0600 and parent directories root0700. This observation criterion does not freeze the journal. Any snapshot/stop change is refused by the unchanged observer.
2. The real privileged supervisor installs/fsyncs the protected startup gate before stopping the old fixture. Use the production host observer's `snapshot` mode against that exact running container and actual journal path, writing create-only root0600 evidence.
3. Stop only the recorded owned fixture ID through Docker. Do not remove it before proof: `prove` needs its exact stopped state, unchanged start/finish metadata and retained die event. Ensure no companion/debug process, descriptor or nsfs mount holds the old namespace. A deliberately held namespace is a refusal case, not permission to kill unknown holders.
4. Run observer `prove` while that exact container remains stopped. It verifies unchanged state mount/journal, empty cgroup and no namespace holders in two passes bracketed by exact stopped-state checks. Retain the raw actual event/observer evidence privately.
5. Use a new empty sleeping runtime namespace with the same persistent journal/state and startup gate still held. It may be allocated while the old namespace is alive to guarantee distinct identity. No daemon, XFRM, product controller or product journal writes occur there before genuine receipt installation. Independently observe its actual current boot ID and namespace. The genuine production assembler consumes the original stopped journal and verified host evidence to create the exact-entry restoration receipt. Never substitute a synthetic receipt written by a native test.
6. The privileged supervisor durably installs the receipt under the journal's protected path and only then releases the startup gate. The controller must verify the receipt and real new namespace/kernel absence, retain old obligations in restoration history and require fresh CP authority before Apply. Namespace inode reuse must not bypass this gated supervised sequence.
7. Record all exact identities/digests before and after; exercise invalid receipt/held namespace negatives; remove only expressly owned fixtures after proof review.

## Current explicit dependency

The assembler now accepts applied contract2 or contract3 entries after the existing product journal reader validates the complete envelope/checksum, v7 process generations, route duties and retained history on a private temporary copy. The immutable full entry remains the receipt digest. Actual CLI execution verifies the supplied boot and new namespace against its own Linux runtime; static and native synthetic-v7 fixture unit tests pass. The stop observer supports exact Docker cgroupfs/systemd identities with inspected PID membership, and explicit state destinations `/var/lib/tunnex-node` (default) or `/state`. Source/unit checks alone do not prove a supervised namespace reset. The separately released and accepted actual local component evidence is recorded below; CP-enrolled forwarding and AWS qualification remain separate.

## Existing commands — reference only

The existing host observer interface is:

```text
python3 deploy/ipsec/runtime_stop_proof.py snapshot --state-destination /state --container <exact owned running ID> --journal <actual root0600 journal> --output <new root0600 snapshot path>
python3 deploy/ipsec/runtime_stop_proof.py prove --snapshot <actual snapshot path> --output <new root0600 stop evidence path>
ipsec-restoration-receipt --journal <exact stopped journal snapshot> --evidence <actual stop evidence> --boot <actual new boot ID> --namespace <actual new namespace> --out <new create-only receipt path>
```

These reference interfaces omit the controlled stop/recreation/gate-install steps deliberately: those require the runtime agent's final reviewed fixture and the root's separate release. No manual JSON construction is an acceptable replacement.

## Observed local trusted namespace receipt

The separately released local Colima Linux-host fixture passed with project `tunnexs2sbgpnamespace1007v2`; evidence is private at `.runtime/bgp7-namespace-local2-final/evidence/`. This is native ARM component authority, with a synthetic fresh nonce lease, actual host observer and genuine CLI receipt. It is separate from CP-enrolled integrated forwarding and AWS proof.

- Image: `sha256:6f97edac6ae8ce1cf05ed9c5b98aa014c7d85185f2774f828b51026473771d7f`.
- Native test SHA256: `9b05b69c74f6a2ba713df077f5858ebade718f8c2a21c315e3cd7cedc822aa67`; harness SHA256: `66cf31f53a3487270ed143f23ad6daa4834a8b2da31b43df5c621cfe9ac471e8`.
- Genuine immediate stop proof SHA256: `1de3fa5c8cf857146173aa9c4d020dd72ac04e25b7ec0902209030a7157d77a0`; CLI receipt SHA256: `fae2624f921534fb8f24b16ad3954affca569f337c03c537224de84427548155`.
- Actual new namespace: `net:[4026533061]`; restoration epoch one retains the full old entry and appends its cleaned process identity. Capability remains zero. Exact owned kernel/daemon absence, bounded capabilities, no SYS_ADMIN and unchanged serving project identities are recorded.

The first local attempt refused a snapshot/stop journal race and is retained in `.runtime/bgp7-namespace-local-refused/`. The successful fixture requires ten stable full-entry observations and uses an exact owned Docker SIGKILL followed by wait, keeping the observer unchanged. Its new sleeping namespace is allocated while the old fixture remains alive, preventing inode reuse; it performs no product journal write before real receipt installation. Only the existing `/test` tmpfs is used as `TMPDIR` for the strict reader's root0700 private copy. After root evidence acceptance, the exact three fixture containers and owned network were removed and their absence verified. The original and restored state journal volumes and all private evidence remain retained. `cleanup-receipt.json` records unchanged serving container IDs, healthy API and ready enrolled gateway; `result.json` now records `cleanup_complete: true`. No serving gateway was stopped or refreshed.

Final evidence archive SHA256: `04165f26cd52fa51a7c3c01b82c8558befe407a937e294d574fe6d67a411ef3b`. Root source review confirmed the production Go source profile matches the native compiled manifest; the later added mixed-static test in `runtime_bgp_cleanup_test.go` is a separate test-source change. The protected `restoration-startup-gate` file and external sleeping-process execution barrier prevent early Apply; there is no product journal freeze flag.

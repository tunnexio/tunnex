# Owned Azure accelerated scheduled IKE qualification

This source is not live authorization. The runner is separate from the AWS
runner and refuses any container other than `tunnex-azure-cloud-gateway` with
`tunnex.owner=azure-s2s-01a12505`, exact full CID/image/node executable hash and
private helper hash. Root must review and explicitly authorize execution later.
No Azure API, policy, grant, licence, or PSK is modified. Existing owned
source10.233.10.2 → application10.231.1.4 TCP8080/UDP8081 grants must cover the
whole bounded test and restoration; the initial four actual packet paths must
succeed before scheduler observation begins.

Build `go test -c ./internal/ipsec` for Linux on the exact reviewed source.
Install the reviewed test binary privately at
`/run/tunnex-ipsec/azure-scheduler.test` inside the exact owned gateway, mode0700.
Keep a root-owned host copy mode0600 for independent SHA256 comparison.
The native test is default skipped, read-only when explicitly enabled, and uses
fresh strict journal checksum over every retained obligation, exact active
org/site/gateway/connection/profile/desired/config binding selection, native
CHILD/SPI/kernel proof, full combined guard readback,
packaged daemon validation and per-VICI-connection SO_PEERCRED/executable/start
identity. It never creates a controller or changes journal/kernel/daemon state.
Private snapshots use O_EXCL0600 and never emit raw journal/VICI/XFRM data.

The Go renderer invokes the existing stage material constructor through a mock
transport. Dummy credential material never leaves that mock. It renders exactly
one or two Azure connections and actual provider `0.0.0.0/0` transport selectors,
not raw journal LAN prefixes. Production defaults are CHILD lifetime3600,
CHILD rekey3000, IKE rekey28800, reauth0, unchanged proposals/identities/IDs.
Original generated configuration and normal API/configuration authority are
saved privately with fsync. No credential loading is issued.

Operator supplies all mandatory flags to `qualify-scheduled-rekey.py`:
`--container FULL_CID --image sha256:DIGEST --node-sha DIGEST --helper PRIVATE_HOST_COPY
--helper-sha DIGEST --accounts PRIVATE_UI_ACCOUNTS --setup PRIVATE_API_SETUP
--connection UUID --evidence-dir NEW_PRIVATE_ABSOLUTE_DIRECTORY`.
API access is fixed localhost48083 and the normal owned owner account. Bootstrap
and scheduler acceptance require fresh normal enabled/applied identity and exact stored
configuration/revisions, then exact loaded connection cardinality. The API
credentials and generated configuration remain private; no raw errors print.

IKE timers become120s (standby) or120/150s (active-active), jitter0 and grace2880s.
CHILD lifetimes/timers remain untouched. Exact per-tunnel terminate/initiate
bootstrap is necessary for strongSwan6.1.0 to adopt the timer; it is explicitly
excluded. After fresh short IKE and production CHILD countdowns are independently
verified, fixed owned packet probes start and establish all four baseline paths.
Observation lasts at most220s and contains no manual initiate/terminate/rekey.
Accepted renewal requires an authenticated `ike-rekey` old/new event near the
expected countdown plus exact native proof and installed CHILDs. Ambiguous
native overlap refuses rather than relaxing ownership. Snapshots/events remain
private. Post-bootstrap baseline CHILD IDs/SPIs are saved separately from pre-bootstrap
material. IKE rekey can transfer unchanged CHILD SAs: changed IKE identity with
unchanged CHILD SPIs is legitimate IKE-only renewal, not a CHILD-rekey proof.
Sampling every2s does not prove every transient overlap was observed.

The detached420s watchdog is armed before any daemon mutation, with durable
private manifest/readiness/restore obligation files. A shared flock serializes
mutation and restoration, and prevents subsequent timer loads after restoration
or a recovery-required receipt. Finally/watchdog restore the original generated
production configuration and create fresh sessions, independently checking
IKE countdown25900..28800 and CHILD countdown2690..3000 plus strict native proof.
Bootstrap and restoration are maintenance and excluded from scheduler acceptance.
A host reboot is outside watchdog guarantees; private obligation files persist
but automatic reboot recovery is not implemented. A changed CP/container/daemon
identity causes fail-closed recovery-required, not stale replay. Root must resolve
that through the normal current controller; the runner cannot promise successful
restoration against changed authority.

The fixed packet child runs240s in `azure-s2s-client`. It records fresh TCP/UDP
and the original persistent TCP/UDP sockets, bounded .5s exchanges, safe HTTP
service/source identity, UDP exact echo and timestamps. Original TCP local port
and socket-present status are captured before each request and survive failure;
the original flow is never automatically reconnected. UDP original port survives
timeouts. Actual outcomes/counts remain in private packets.json; scheduler
success alone never marks packet continuity successful. Review packets aligned
to bootstrap-excluded and event times; report measured loss and recovery, not
uninterrupted continuity from settled snapshots. This test uses the existing app,
not the private LB/FQDN or public-fallback proof.

Results explicitly say accelerated scheduled IKE only. Natural production
CHILD scheduling and an eight-hour IKE-duration soak remain separate unproved
acceptance. Manual swanctl rekey is never scheduler proof.

The journal may contain retained history (including the actual nineteen-entry
lab shape). Every entry still passes validJournalPayload, retained-reference,
cleanup/restoration/BGP/history validation before selection. All entries must
belong to the expected org/site/gateway; every other obligation must be retained,
never applying/pending/another active binding. Retained history is pinned by a
canonical digest, independent of entry ordering. A rollback/changed history
refuses. Up to two recorded guard templates are supported only when exactly one
complete template in the current namespace matches strict full readback. Zero
or two matching templates refuse; no active-only guard is generated.

Normal lease refresh is not journal authority: leases remain unserialized.
RuntimeStore.Material reuses the persisted apply DeliveryID for a desired
revision; a new DeliveryID is not treated as an ordinary lease refresh. Stable
identity includes delivery, full Binding (including policy revision), engines,
production configuration, retained history and daemon process identity. Journal
sequence, fresh guard revision and observed CHILD/SPI changes are not compared
across samples, but all are validated anew on every complete snapshot. The
before/after journal bytes must still match within each snapshot; concurrent
journal/guard refresh refuses rather than accepting mixed proof. No lease,
guard, history or authority check is dropped.

Rollback-only authority tolerates exactly applied/pending/not_applied application
state, but still requires the unchanged enabled intent, private original normal
API identity/configuration/desired revision projection, current pinned container,
node and daemon process, and exact owned staged connection cardinality/names.
A disabled/deleted/finalized/superseded binding or unknown state refuses before
any mutation. Every restoration load/terminate/initiate repeats these checks
inside the held restore lock; read-only staged-connection verification uses the
common direct swan reader and cannot recursively acquire the mutation lock.
Final acceptance does NOT use the rollback projection: after fresh production
countdowns, bounded retries require normal Applied and the original strict native
snapshot. A pending state is never native readiness or permit authority. Failure
clears the in-memory restoration mode and leaves recovery-required evidence.

Durable fixed markers separate bootstrap start/end, automatic observation
start/end, and restoration start/end. Each packet attempt records monotonic
start/end and UTC stamps; a crossing attempt is preserved outside automatic
qualification. A watchdog-started restoration clips the automatic window even
if the foreground only notices later. packets.json retains every raw sample and
all-window counts. packet-phases.json preserves those counts and reports separate
bootstrap, automatic, restoration and outside/boundary counts. Forced restoration
losses cannot be attributed to the scheduler. Sampled automatic continuity needs
scheduler success, successful original socket baseline, consistent original TCP
and UDP ports, and at least three successful/no-failure samples per flow entirely
inside the automatic interval. This is sampled continuity, not a zero-loss
microsecond guarantee. Restoration counts are reported separately; later stable
post-restoration traffic is outside that phase. If no automatic window was reached,
no automatic continuity passes.

BGP contract3 preflight uses the valid completed journal BGP route obligation,
strict native transport/CHILD/SPI evidence for every active slot, and the existing
read-only `verifyBGPRoutes` over the full recorded route union and interface
ownership. Static profiles retain `runtimeInventoryMatches`. No controller or
permit lease is constructed by either proof.

Azure scheduler changes and rollback use the test helper's fixed `load-conn`,
`terminate`, and `initiate` VICI commands, not generic swanctl mutation/redial.
Each command connects only to the packaged private socket and checks root
SO_PEERCRED, exact pinned charon PID/start ticks and executable digest. Requests
remain root-owned 0600 and stdout/stderr are suppressed. All existing normal API,
full journal/history, combined guard, watchdog lock and phase boundaries remain.

Actual `list-conns` readback must match endpoints, IKE version/PSK identities,
IKE rekey/reauth, DPD delay, CHILD name/mode/rekey/actions and transport selectors.
Production timers are required by production snapshots; accelerated timers by
scheduled observation. Rollback alone permits a partial mixture of the exact
production/accelerated IKE timer values before loading production. Same-name drift
in any exposed field refuses before mutation. The real provider renderer supplies
the exact load tree, including unchanged CHILD lifetime and native identifiers.
strongSwan 6.1.0 list-conns also exposes exact IKE/ESP proposal transforms and
configured endpoint ports; these are checked and AH proposals must be absent.
The protocol does **not** expose original CHILD hard lifetime, reqid/if_id,
randomization or over_time; no byte-for-byte readback claim
is made for these hidden fields. Native SA/SPI/SPD/ownership proof still applies.
See the upstream [VICI query implementation](https://github.com/strongswan/strongswan/blob/6.1.0/src/libcharon/plugins/vici/vici_query.c).

Snapshot acceptance also requires the proof context to remain unexpired through
private receipt sync. A completed read after expiry cannot authorize control.

Readback follows the packaged 6.1.0 schema: PSK authentication is rendered as
`pre-shared key`; configured `dpd_action=clear` maps to `ACTION_NONE` and reads as
`none`. This preserves the configured semantics; restart/trap and other auth
classes still refuse. Exact proposal checks reject weaker/extra transforms.

A failed bootstrap/rollback is not scheduled-rekey evidence. Preserve the first
failure chain as well as restoration failure. Test-helper diagnostics classify
only fixed journal/binding/guard/bracket and loaded request/schema/control stages.
VICI terminate `success=no` with zero matches remains refusal, including rollback;
partial termination also refuses. Arbitrary daemon error text is never retained
in a new diagnostic. These labels do not authorize retry, timer restoration over
a superseded desired revision, or helper/manifest replacement in an active run.

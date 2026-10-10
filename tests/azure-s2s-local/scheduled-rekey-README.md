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
fresh strict journal checksum, native CHILD/SPI/kernel proof, full guard readback,
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
API access is fixed localhost48083 and the normal owned owner account. Every
mutation checks fresh normal enabled/applied identity and exact stored
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

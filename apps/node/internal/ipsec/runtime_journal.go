package ipsec

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
)

var ErrRuntimeJournal = errors.New("IPsec runtime journal unavailable")

type RuntimePhase string

const (
	RuntimeReserved        RuntimePhase = "reserved"
	RuntimeApplying        RuntimePhase = "applying"
	RuntimeApplied         RuntimePhase = "applied"
	RuntimeCleanupPending  RuntimePhase = "cleanup_pending"
	RuntimeRetainedRefusal RuntimePhase = "retained_refusal"
)

// RuntimeJournalEntry is deliberately nonsecret. Grants, PSKs, raw material,
// permit leases and inferred readiness cannot be serialized in this schema.
// Engines preserve the nonsecret potentially-installed lineage for exact cleanup.
type RuntimeRecoveryState struct {
	SelectedSlot           uint8
	Sequence               uint64
	PendingFrom, PendingTo uint8
	Stage                  string
}

// RuntimeResetCleanup records cleanup evidence, never apply authority.
type RuntimeResetCleanup struct {
	BootID        string
	Namespace     string
	ReceiptDigest string
}

type RuntimeJournalEntry struct {
	// Omitted fields preserve the original v1 canonical checksum byte for byte.
	// Authorization is immutable; recovery state records duty, never authority.
	ContractVersion int                   `json:",omitempty"`
	Recovery        *RuntimeRecoveryState `json:",omitempty"`
	ResetCleanup    *RuntimeResetCleanup  `json:",omitempty"`
	Restoration     *RuntimeRestoration   `json:",omitempty"`
	// AbsenceOnly records CP-delivered lineage never observed locally; it permits
	// only independent absence proof, never adoption or deletion of objects.
	AbsenceOnly                                     bool
	DeliveryID, SiteID                              uuid.UUID
	OwnershipDigest                                 string
	Allocation                                      KernelAllocation
	Engines                                         [2]EngineTunnel
	Observed                                        [2]Ownership
	Phase                                           RuntimePhase
	CleanupID                                       uuid.UUID
	CleanupDesiredRevision, CoveredDeliveryRevision int64
}

// Templates record prior object shape for withdrawal only, never a lease or
// permission to reinstall a permitting template. Only RenderGuard output enters.
type runtimeGuardTemplate struct {
	Namespace            string
	Revision             int64
	Digest, ExpectedJSON string
}
type runtimeJournalPayload struct {
	Guards   []runtimeGuardTemplate
	Version  int
	OwnerID  uuid.UUID
	Sequence uint64
	Entries  []RuntimeJournalEntry
}
type runtimeJournalEnvelope struct {
	Payload  runtimeJournalPayload
	Checksum string
}
type RuntimeJournal struct {
	mu            sync.Mutex
	dir           string
	directory     os.FileInfo
	lock          *os.File
	lockInfo      os.FileInfo
	payload       runtimeJournalPayload
	poisoned      bool
	syncDirectory func() error
}

// OpenRuntimeJournal requires an existing private directory and takes an
// exclusive process lock for its entire lifetime. No saved state grants authority.
func OpenRuntimeJournal(dir string, owner uuid.UUID) (*RuntimeJournal, error) {
	if owner == uuid.Nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return nil, ErrRuntimeJournal
	}
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil || resolved != dir {
		return nil, ErrRuntimeJournal
	}
	info, err := os.Lstat(dir)
	if err != nil || !journalPrivate(info, true) {
		return nil, ErrRuntimeJournal
	}
	lock, err := journalOpenNoFollow(filepath.Join(dir, "journal.lock"), true)
	if err != nil {
		return nil, ErrRuntimeJournal
	}
	li, err := lock.Stat()
	if err != nil || !journalPrivate(li, false) || journalLock(lock) != nil {
		lock.Close()
		return nil, ErrRuntimeJournal
	}
	j := &RuntimeJournal{dir: dir, directory: info, lock: lock, lockInfo: li, payload: runtimeJournalPayload{Version: 1, OwnerID: owner, Entries: []RuntimeJournalEntry{}}}
	j.syncDirectory = func() error {
		d, e := os.Open(dir)
		if e != nil {
			return e
		}
		defer d.Close()
		return d.Sync()
	}
	if !j.pathsIntact() {
		j.Close()
		return nil, ErrRuntimeJournal
	}
	p, err := j.read()
	if errors.Is(err, os.ErrNotExist) {
		return j, nil
	}
	if err != nil || p.OwnerID != owner {
		j.Close()
		return nil, ErrRuntimeJournal
	}
	j.payload = p
	return j, nil
}
func (j *RuntimeJournal) pathsIntact() bool {
	if j.lock == nil || j.poisoned {
		return false
	}
	d, e := os.Lstat(j.dir)
	if e != nil || !journalPrivate(d, true) || !os.SameFile(d, j.directory) {
		return false
	}
	l, e := os.Lstat(filepath.Join(j.dir, "journal.lock"))
	return e == nil && journalPrivate(l, false) && os.SameFile(l, j.lockInfo)
}
func (j *RuntimeJournal) Close() error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if j.lock == nil {
		return nil
	}
	journalUnlock(j.lock)
	e := j.lock.Close()
	j.lock = nil
	return e
}
func (j *RuntimeJournal) read() (runtimeJournalPayload, error) {
	path := filepath.Join(j.dir, "journal.json")
	f, e := journalOpenNoFollow(path, false)
	if e != nil {
		return runtimeJournalPayload{}, e
	}
	defer f.Close()
	info, e := f.Stat()
	if e != nil || !journalPrivate(info, false) || info.Size() > kernelDumpLimit {
		return runtimeJournalPayload{}, ErrRuntimeJournal
	}
	raw, e := io.ReadAll(io.LimitReader(f, kernelDumpLimit+1))
	if e != nil || len(raw) > kernelDumpLimit {
		return runtimeJournalPayload{}, ErrRuntimeJournal
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if !kernelJSONValue(d, 0) {
		return runtimeJournalPayload{}, ErrRuntimeJournal
	}
	if _, e = d.Token(); e != io.EOF {
		return runtimeJournalPayload{}, ErrRuntimeJournal
	}
	var env runtimeJournalEnvelope
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(&env) != nil || !validJournalPayload(env.Payload) || env.Checksum != journalChecksum(env.Payload) {
		return runtimeJournalPayload{}, ErrRuntimeJournal
	}
	return env.Payload, nil
}
func journalChecksum(p runtimeJournalPayload) string {
	b, _ := json.Marshal(p)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}
func cloneJournal(p runtimeJournalPayload) runtimeJournalPayload {
	b, _ := json.Marshal(p)
	var out runtimeJournalPayload
	_ = json.Unmarshal(b, &out)
	return out
}
func (j *RuntimeJournal) Entries() ([]RuntimeJournalEntry, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() {
		return nil, ErrRuntimeJournal
	}
	return cloneJournal(j.payload).Entries, nil
}
func validDigest(v string) bool {
	b, e := hex.DecodeString(v)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == v
}
func validJournalPayload(p runtimeJournalPayload) bool {
	if (p.Version != 1 && p.Version != 2 && p.Version != 3 && p.Version != 4) || p.OwnerID == uuid.Nil || len(p.Entries) > 256 || len(p.Guards) > 2 {
		return false
	}
	for _, g := range p.Guards {
		if !validKernelNamespace(g.Namespace) || g.Revision <= 0 || !validDigest(g.Digest) || len(g.ExpectedJSON) > kernelDumpLimit {
			return false
		}
		if _, ok := normalizedGuardObjects([]byte(g.ExpectedJSON)); !ok {
			return false
		}
	}
	ids := map[uuid.UUID]bool{}
	for _, r := range p.Entries {
		if !validRestoration(r) || (r.Restoration != nil && p.Version < 4) {
			return false
		}
		if !validJournalResetCleanup(r) || (r.ResetCleanup != nil && p.Version < 3) {
			return false
		}
		if !validJournalRecovery(r) || (p.Version == 1 && (r.ContractVersion == 2 || r.Recovery != nil)) {
			return false
		}
		if r.DeliveryID == uuid.Nil || r.SiteID == uuid.Nil || ids[r.DeliveryID] || !validDigest(r.OwnershipDigest) || !validKernelAllocation(r.Allocation) {
			return false
		}
		ids[r.DeliveryID] = true
		for i, e := range r.Engines {
			a := r.Allocation.Tunnels[i]
			if !validEngineTunnel(e) || e.Binding.GatewayID != p.OwnerID || e.Binding.ConnectionID != r.Allocation.ConnectionID || e.TunnelID != a.TunnelID || e.XFRMID != a.XFRMID || !sameEnginePrefixes(e.RemotePrefixes, a.RemotePrefixes) || e.Binding != r.Engines[0].Binding {
				return false
			}
			o := r.Observed[i]
			if o != (Ownership{}) && (o.Namespace != r.Allocation.Namespace || o.InterfaceName != a.Name || o.XFRMID != a.XFRMID || o.InterfaceIndex <= 0) {
				return false
			}
		}
		if r.AbsenceOnly && (r.Phase == RuntimeApplying || r.Phase == RuntimeApplied || r.Observed != ([2]Ownership{})) {
			return false
		}
		switch r.Phase {
		case RuntimeReserved, RuntimeApplying, RuntimeApplied:
			if r.CleanupID != uuid.Nil || r.CleanupDesiredRevision != 0 || r.CoveredDeliveryRevision != 0 {
				return false
			}
		case RuntimeCleanupPending, RuntimeRetainedRefusal:
			if r.CleanupID == uuid.Nil || r.CleanupDesiredRevision <= r.Engines[0].Binding.DesiredRevision || r.CoveredDeliveryRevision < r.Engines[0].Binding.DesiredRevision || r.CoveredDeliveryRevision >= r.CleanupDesiredRevision {
				return false
			}
		default:
			return false
		}
	}
	return true
}
func validJournalSuccessor(old, next runtimeJournalPayload) bool {
	if next.Version < old.Version || next.Version > 4 || (next.Version > old.Version+1 && !(old.Version == 1 && next.Version == 3) && next.Version != 4) {
		return false
	}
	if next.Version == 4 && old.Version < 4 {
		upgrade := false
		for _, r := range next.Entries {
			upgrade = upgrade || r.Restoration != nil
		}
		if !upgrade {
			return false
		}
	}
	if next.Version == 3 && old.Version < 3 {
		upgrade := false
		for _, r := range next.Entries {
			upgrade = upgrade || r.ResetCleanup != nil
		}
		if !upgrade {
			return false
		}
	}
	if old.Version == 1 && next.Version == 2 {
		upgrade := false
		for _, r := range next.Entries {
			if r.ContractVersion == 2 {
				upgrade = true
			}
		}
		if !upgrade {
			return false
		}
	}
	byID := map[uuid.UUID]RuntimeJournalEntry{}
	for _, r := range next.Entries {
		byID[r.DeliveryID] = r
	}
	oldIDs := map[uuid.UUID]bool{}
	for _, r := range old.Entries {
		oldIDs[r.DeliveryID] = true
	}
	for _, r := range next.Entries {
		if !oldIDs[r.DeliveryID] {
			if r.Phase != RuntimeReserved || r.ResetCleanup != nil || r.Restoration != nil {
				return false
			}
			if r.Recovery != nil && *r.Recovery != (RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}) {
				return false
			}
		}
	}
	for _, before := range old.Entries {
		after, ok := byID[before.DeliveryID]
		if !ok {
			return false
		}
		if !validRestorationSuccessor(before, after) {
			return false
		}
		if !validRecoverySuccessor(before, after) {
			return false
		}
		if !reflect.DeepEqual(before.ResetCleanup, after.ResetCleanup) {
			if before.ResetCleanup != nil || after.ResetCleanup == nil || before.Phase != RuntimeCleanupPending || after.Phase != RuntimeCleanupPending {
				return false
			}
		}
		b, a := before, after
		if restorationAdvanced(before, after) {
			a.Allocation = b.Allocation
			a.Engines = b.Engines
		}
		b.Restoration, a.Restoration = nil, nil
		b.ResetCleanup, a.ResetCleanup = nil, nil
		b.Recovery, a.Recovery = nil, nil
		b.Phase, a.Phase = "", ""
		b.Observed, a.Observed = [2]Ownership{}, [2]Ownership{}
		b.CleanupID, a.CleanupID = uuid.Nil, uuid.Nil
		b.CleanupDesiredRevision, a.CleanupDesiredRevision = 0, 0
		b.CoveredDeliveryRevision, a.CoveredDeliveryRevision = 0, 0
		if !reflect.DeepEqual(b, a) {
			return false
		}
		if before.Phase == RuntimeRetainedRefusal && !reflect.DeepEqual(before, after) {
			return false
		}
		allowed := before.Phase == after.Phase || (before.Phase == RuntimeReserved && after.Phase == RuntimeApplying) || (before.Phase == RuntimeApplying && after.Phase == RuntimeApplied) || (before.Phase != RuntimeRetainedRefusal && after.Phase == RuntimeCleanupPending) || (before.Phase == RuntimeCleanupPending && after.Phase == RuntimeRetainedRefusal)
		if !allowed || after.CleanupDesiredRevision < before.CleanupDesiredRevision || after.CoveredDeliveryRevision < before.CoveredDeliveryRevision {
			return false
		}
		if before.CleanupDesiredRevision == after.CleanupDesiredRevision && before.CleanupID != after.CleanupID {
			return false
		}
	}
	return true
}

// Save must complete before issuing the corresponding mutation. Any ambiguous
// write/fsync failure poisons this instance; restart reloads the potential duty.
func (j *RuntimeJournal) Save(entries []RuntimeJournalEntry) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() || j.payload.Sequence == ^uint64(0) {
		return ErrRuntimeJournal
	}
	next := cloneJournal(j.payload)
	next.Sequence++
	next.Entries = entries
	for _, entry := range entries {
		if entry.ContractVersion == 2 && next.Version < 2 {
			next.Version = 2
		}
		if entry.ResetCleanup != nil && next.Version < 3 {
			next.Version = 3
		}
		if entry.Restoration != nil {
			next.Version = 4
		}
	}
	return j.saveLocked(cloneJournal(next))
}
func (j *RuntimeJournal) saveLocked(next runtimeJournalPayload) error {
	if !validJournalPayload(next) || !validJournalSuccessor(j.payload, next) {
		return ErrRuntimeJournal
	}
	raw, e := json.Marshal(runtimeJournalEnvelope{Payload: next, Checksum: journalChecksum(next)})
	if e != nil || len(raw) > kernelDumpLimit {
		return ErrRuntimeJournal
	}
	current, e := j.read()
	if (j.payload.Sequence == 0 && !errors.Is(e, os.ErrNotExist)) || (j.payload.Sequence != 0 && (e != nil || journalChecksum(current) != journalChecksum(j.payload))) {
		j.poisoned = true
		return ErrRuntimeJournal
	}
	f, e := os.CreateTemp(j.dir, ".journal-")
	if e != nil {
		j.poisoned = true
		return ErrRuntimeJournal
	}
	name := f.Name()
	defer os.Remove(name)
	n, e := f.Write(raw)
	if e == nil && n != len(raw) {
		e = io.ErrShortWrite
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, filepath.Join(j.dir, "journal.json"))
	}
	if e == nil {
		e = j.syncDirectory()
	}
	if e != nil {
		j.poisoned = true
		return ErrRuntimeJournal
	}
	j.payload = next
	return nil
}

func (j *RuntimeJournal) prepareGuard(m GuardManifest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() || m.OwnerID != j.payload.OwnerID || j.payload.Sequence == ^uint64(0) {
		return ErrRuntimeJournal
	}
	g := runtimeGuardTemplate{Namespace: m.Namespace, Revision: m.Revision, Digest: m.Digest, ExpectedJSON: m.ExpectedJSON}
	next := cloneJournal(j.payload)
	for _, old := range next.Guards {
		if old == g {
			return nil
		}
	}
	if len(next.Guards) >= 2 {
		return ErrRuntimeJournal
	}
	next.Guards = append(next.Guards, g)
	next.Sequence++
	return j.saveLocked(next)
}
func (j *RuntimeJournal) finishGuard(m GuardManifest) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() || j.payload.Sequence == ^uint64(0) {
		return ErrRuntimeJournal
	}
	g := runtimeGuardTemplate{Namespace: m.Namespace, Revision: m.Revision, Digest: m.Digest, ExpectedJSON: m.ExpectedJSON}
	found := false
	for _, old := range j.payload.Guards {
		if old == g {
			found = true
		}
	}
	if !found {
		return ErrRuntimeJournal
	}
	next := cloneJournal(j.payload)
	next.Guards = []runtimeGuardTemplate{g}
	next.Sequence++
	return j.saveLocked(next)
}
func (j *RuntimeJournal) guardTemplates() ([]runtimeGuardTemplate, uint64, error) {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() {
		return nil, 0, ErrRuntimeJournal
	}
	p := cloneJournal(j.payload)
	return p.Guards, p.Sequence, nil
}

// Called only after full table listing/withdrawal verification. Clearing absent
// templates does NOT drop any prefix reservation or active cleanup obligation.
func (j *RuntimeJournal) resolveGuardOwnership(observed *runtimeGuardTemplate) error {
	j.mu.Lock()
	defer j.mu.Unlock()
	if !j.pathsIntact() || j.payload.Sequence == ^uint64(0) {
		return ErrRuntimeJournal
	}
	next := cloneJournal(j.payload)
	if observed == nil {
		next.Guards = nil
	} else {
		found := false
		for _, g := range next.Guards {
			if g == *observed {
				found = true
			}
		}
		if !found {
			return ErrRuntimeJournal
		}
		next.Guards = []runtimeGuardTemplate{*observed}
	}
	next.Sequence++
	return j.saveLocked(next)
}

// ReadRuntimeJournalIdentity discovers only the identity needed to restore saved
// refusal offline. OpenRuntimeJournal must subsequently lock and revalidate it;
// this read never authorizes permits or mutation based on unlocked state.
// os.ErrNotExist distinguishes a brand-new journal from a corrupt existing one.
func ReadRuntimeJournalIdentity(dir string) (uuid.UUID, uuid.UUID, error) {
	fail := func() (uuid.UUID, uuid.UUID, error) { return uuid.Nil, uuid.Nil, ErrRuntimeJournal }
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return fail()
	}
	resolved, e := filepath.EvalSymlinks(dir)
	if errors.Is(e, os.ErrNotExist) {
		return uuid.Nil, uuid.Nil, os.ErrNotExist
	}
	if e != nil || resolved != dir {
		return fail()
	}
	info, e := os.Lstat(dir)
	if e != nil || !journalPrivate(info, true) {
		return fail()
	}
	j := &RuntimeJournal{dir: dir}
	p, e := j.read()
	if errors.Is(e, os.ErrNotExist) {
		return uuid.Nil, uuid.Nil, os.ErrNotExist
	}
	if e != nil || len(p.Entries) == 0 {
		return fail()
	}
	after, e := os.Lstat(dir)
	if e != nil || !os.SameFile(info, after) || !journalPrivate(after, true) {
		return fail()
	}
	org := p.Entries[0].Engines[0].Binding.OrgID
	for _, entry := range p.Entries {
		for _, engine := range entry.Engines {
			if engine.Binding.OrgID != org || engine.Binding.GatewayID != p.OwnerID {
				return fail()
			}
		}
	}
	return org, p.OwnerID, nil
}

// The selected slot denotes completed route duty only. A pending record retains
// the old slot until exact readback completes; neither stage grants permission.
func validJournalRecovery(r RuntimeJournalEntry) bool {
	if r.ContractVersion == 0 {
		return r.Recovery == nil
	}
	if r.ContractVersion != 2 || r.Recovery == nil {
		return false
	}
	v := *r.Recovery
	if (r.AbsenceOnly || r.Phase == RuntimeReserved || r.Phase == RuntimeApplying) && v != (RuntimeRecoveryState{SelectedSlot: 1, Stage: "completed"}) {
		return false
	}
	if v.SelectedSlot < 1 || v.SelectedSlot > 2 {
		return false
	}
	switch v.Stage {
	case "completed":
		return v.PendingFrom == 0 && v.PendingTo == 0 && (v.Sequence != 0 || v.SelectedSlot == 1)
	case "pending":
		return v.Sequence > 0 && v.PendingFrom == v.SelectedSlot && v.PendingTo == 3-v.SelectedSlot &&
			!r.AbsenceOnly && (r.Phase == RuntimeApplied || r.Phase == RuntimeCleanupPending || r.Phase == RuntimeRetainedRefusal)
	default:
		return false
	}
}

func validRecoverySuccessor(before, after RuntimeJournalEntry) bool {
	if reflect.DeepEqual(before.Recovery, after.Recovery) {
		return true
	}
	if before.ContractVersion != 2 || after.ContractVersion != 2 || before.Recovery == nil || after.Recovery == nil ||
		before.AbsenceOnly || after.AbsenceOnly || before.Phase != RuntimeApplied || after.Phase != RuntimeApplied {
		return false
	}
	b, a := *before.Recovery, *after.Recovery
	if b.Stage == "completed" && a.Stage == "pending" {
		return b.Sequence != ^uint64(0) && a.Sequence == b.Sequence+1 && a.SelectedSlot == b.SelectedSlot &&
			a.PendingFrom == b.SelectedSlot && a.PendingTo == 3-b.SelectedSlot
	}
	if b.Stage == "pending" && a.Stage == "completed" {
		return a.Sequence == b.Sequence && a.SelectedSlot == b.PendingTo && a.PendingFrom == 0 && a.PendingTo == 0
	}
	return false
}

func validJournalResetCleanup(r RuntimeJournalEntry) bool {
	if r.ResetCleanup == nil {
		return true
	}
	v := r.ResetCleanup
	boot, err := uuid.Parse(v.BootID)
	return err == nil && boot != uuid.Nil && boot.String() == v.BootID && validKernelNamespace(v.Namespace) && v.Namespace != r.Allocation.Namespace && validDigest(v.ReceiptDigest) && (r.Phase == RuntimeCleanupPending || r.Phase == RuntimeRetainedRefusal)
}

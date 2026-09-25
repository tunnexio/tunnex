package ipsec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/uuid"
)

// A privileged supervisor attests termination of the previous VM. This receipt
// is NOT inferred from a missing namespace, nor accepted by the Apply path.
// Legacy journals cannot establish their original boot identity retroactively.
type runtimeResetReceipt struct {
	Version                                                       int
	OwnerID, CleanupID                                            uuid.UUID
	CleanupRevision                                               int64
	CoveredDigest, BootID, Namespace, Termination, EvidenceDigest string
}

func stringDigest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func resetCoveredDigest(entries []RuntimeJournalEntry) string {
	copyEntries := append([]RuntimeJournalEntry(nil), entries...)
	for i := range copyEntries {
		copyEntries[i].Phase = ""
		copyEntries[i].CleanupID = uuid.Nil
		copyEntries[i].CleanupDesiredRevision = 0
		copyEntries[i].CoveredDeliveryRevision = 0
		copyEntries[i].ResetCleanup = nil
	}
	sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].DeliveryID.String() < copyEntries[j].DeliveryID.String() })
	b, err := json.Marshal(copyEntries)
	if err != nil {
		return ""
	}
	return stringDigest(b)
}

func resetBootID() (string, error) {
	b, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	if err != nil {
		return "", ErrRuntimeController
	}
	value := strings.TrimSpace(string(b))
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil || id.String() != value {
		return "", ErrRuntimeController
	}
	return value, nil
}

func parseResetReceipt(raw []byte, owner uuid.UUID, cleanup RuntimeCleanup, covered []RuntimeJournalEntry, boot, ns string) (*RuntimeResetCleanup, error) {
	fail := func() (*RuntimeResetCleanup, error) { return nil, ErrRuntimeController }
	if len(raw) == 0 || len(raw) > 8192 || !validKernelNamespace(ns) || len(covered) == 0 || !cleanup.RetainGuard {
		return fail()
	}
	bootUUID, err := uuid.Parse(boot)
	if err != nil || bootUUID == uuid.Nil || bootUUID.String() != boot {
		return fail()
	}
	var receipt runtimeResetReceipt
	if _, ok := runtimeJSONObject(raw); !ok {
		return fail()
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if dec.Decode(&receipt) != nil {
		return fail()
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return fail()
	}
	if receipt.Version != 1 || receipt.OwnerID != owner || owner == uuid.Nil || receipt.CleanupID != cleanup.ID || cleanup.ID == uuid.Nil || receipt.CleanupRevision != cleanup.DesiredRevision || receipt.CleanupRevision <= 0 || receipt.CoveredDigest != resetCoveredDigest(covered) || receipt.BootID != boot || receipt.Namespace != ns || receipt.Termination != "supervisor-confirmed-vm-stop" || !validDigest(receipt.EvidenceDigest) {
		return fail()
	}
	return &RuntimeResetCleanup{BootID: boot, Namespace: ns, ReceiptDigest: stringDigest(raw)}, nil
}

func (c *RuntimeController) resetCleanupReceipt(cleanup RuntimeCleanup, covered []RuntimeJournalEntry) (*RuntimeResetCleanup, error) {
	// The agent runs privileged; never accept a receipt supplied by another uid,
	// through a symlink, or in an unprotected journal directory.
	if os.Geteuid() != 0 || !c.journal.pathsIntact() {
		return nil, ErrRuntimeController
	}
	boot, err := resetBootID()
	if err != nil {
		return nil, err
	}
	ns, err := c.namespace()
	if err != nil {
		return nil, ErrRuntimeController
	}
	path := filepath.Join(c.config.JournalDir, "reset-cleanup-"+cleanup.ID.String()+".json")
	f, err := journalOpenNoFollow(path, false)
	if err != nil {
		return nil, ErrRuntimeController
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !journalPrivate(info, false) || info.Size() > 8192 {
		return nil, ErrRuntimeController
	}
	raw, err := io.ReadAll(io.LimitReader(f, 8193))
	if err != nil {
		return nil, ErrRuntimeController
	}
	current, err := os.Lstat(path)
	if err != nil || !os.SameFile(info, current) || !journalPrivate(current, false) {
		return nil, ErrRuntimeController
	}
	return parseResetReceipt(raw, c.config.GatewayID, cleanup, covered, boot, ns)
}

// Supplement the standard XFRM inventory with all-link aliases and addresses;
// renamed or non-XFRM survivors must never be treated as an empty namespace.
func resetExtraObjectsAbsent(e RuntimeJournalEntry, linksRaw, addressesRaw []byte) bool {
	links, ok := kernelObjects(linksRaw)
	if !ok {
		return false
	}
	addresses, ok := kernelObjects(addressesRaw)
	if !ok {
		return false
	}
	for _, link := range links {
		name, ok := kernelString(link, "ifname")
		if !ok {
			return false
		}
		alias := ""
		if _, exists := link["ifalias"]; exists {
			alias, ok = kernelString(link, "ifalias")
			if !ok {
				return false
			}
		}
		for _, t := range e.Allocation.Tunnels {
			if name == t.Name || alias == t.Alias {
				return false
			}
		}
	}
	for _, link := range addresses {
		raw, exists := link["addr_info"]
		if !exists {
			return false
		}
		rows, ok := kernelObjects(raw)
		if !ok {
			return false
		}
		for _, address := range rows {
			family, ok := kernelString(address, "family")
			if !ok {
				return false
			}
			if family != "inet" {
				continue
			}
			local, ok := kernelString(address, "local")
			if !ok {
				return false
			}
			ip, err := netip.ParseAddr(local)
			if err != nil || !ip.Is4() {
				return false
			}
			for _, t := range e.Allocation.Tunnels {
				if t.InsideAddress.Masked().Contains(ip) {
					return false
				}
			}
		}
	}
	return true
}

func (c *RuntimeController) proveResetAbsent(ctx context.Context, e RuntimeJournalEntry, proof *RuntimeResetCleanup) error {
	if proof == nil || e.Allocation.Namespace == proof.Namespace {
		return ErrRuntimeController
	}
	for pass := 0; pass < 2; pass++ {
		boot, err := resetBootID()
		if err != nil || boot != proof.BootID {
			return ErrRuntimeController
		}
		ns, err := c.namespace()
		if err != nil || ns != proof.Namespace {
			return ErrRuntimeController
		}
		// Projection is observation-only. Old ownership in the journal is immutable.
		projected := e
		projected.Allocation.Namespace = ns
		if c.proveAbsent(ctx, projected) != nil {
			return ErrRuntimeController
		}
		links, err := runKernelCommand(ctx, c.config.IPPath, "-j", "-d", "link", "show")
		if err != nil {
			return ErrRuntimeController
		}
		addresses, err := runKernelCommand(ctx, c.config.IPPath, "-j", "-4", "address", "show")
		if err != nil || !resetExtraObjectsAbsent(e, links, addresses) {
			return ErrRuntimeController
		}
		bootAfter, err := resetBootID()
		if err != nil || bootAfter != boot {
			return ErrRuntimeController
		}
		nsAfter, err := c.namespace()
		if err != nil || nsAfter != ns || ctx.Err() != nil {
			return ErrRuntimeController
		}
	}
	return nil
}

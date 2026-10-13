// Linux local harness only: release an already verified genuine restoration.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"os"
	"regexp"
	"syscall"
)

func private(path string) []byte { return privateLimit(path, 1<<20) }
func privateLimit(path string, limit int64) []byte {
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		panic("private input unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Sys().(*syscall.Stat_t).Uid != 0 || st.Size() > limit {
		panic("private input identity refused")
	}
	b, e := os.ReadFile("/proc/self/fd/" + itoa(fd))
	if e != nil {
		panic("private input read refused")
	}
	return b
}
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	b := []byte{}
	for v > 0 {
		b = append([]byte{byte(v%10) + '0'}, b...)
		v /= 10
	}
	return string(b)
}
func digest(b []byte) string { v := sha256.Sum256(b); return hex.EncodeToString(v[:]) }
func fsyncDir(path string) {
	f, e := os.Open(path)
	if e != nil {
		panic("parent open refused")
	}
	defer f.Close()
	if f.Sync() != nil {
		panic("parent fsync refused")
	}
}
func validDelivery(s string) bool {
	return s != "00000000-0000-0000-0000-000000000000" && regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`).MatchString(s)
}
func receiptMatches(raw []byte, delivery, ns string) bool {
	var r struct {
		Version    int
		DeliveryID string
		Namespace  string
	}
	return validDelivery(delivery) && json.Unmarshal(raw, &r) == nil && r.Version == 1 && r.DeliveryID == delivery && r.Namespace == ns
}
func journalMatches(raw []byte, delivery string) bool {
	var j struct {
		Payload struct {
			Entries []struct {
				DeliveryID string
				Phase      string
			}
		}
	}
	if json.Unmarshal(raw, &j) != nil {
		return false
	}
	count := 0
	for _, e := range j.Payload.Entries {
		if e.Phase == "retained_refusal" {
			continue
		}
		count++
		if e.Phase != "applied" || e.DeliveryID != delivery {
			return false
		}
	}
	return count == 1
}

type receiptSet struct {
	JournalSHA     string
	EvidenceDigest string
	OwnerID        string
	Namespace      string
	Receipts       map[string]string
}

func matchesReceiptSet(journal []byte, set receiptSet, receipts map[string][]byte) bool {
	if digest(journal) != set.JournalSHA || len(set.EvidenceDigest) != 64 || len(set.Receipts) == 0 || len(set.Receipts) > 256 || len(receipts) != len(set.Receipts) || !validDelivery(set.OwnerID) {
		return false
	}
	var j struct {
		Payload struct {
			OwnerID string
			Entries []json.RawMessage
		}
	}
	if json.Unmarshal(journal, &j) != nil || j.Payload.OwnerID != set.OwnerID || len(j.Payload.Entries) > 256 {
		return false
	}
	active := map[string]bool{}
	for _, raw := range j.Payload.Entries {
		var e struct {
			DeliveryID string
			Phase      string
		}
		if json.Unmarshal(raw, &e) != nil {
			return false
		}
		if e.Phase == "retained_refusal" {
			continue
		}
		if e.Phase != "applied" || !validDelivery(e.DeliveryID) || active[e.DeliveryID] {
			return false
		}
		active[e.DeliveryID] = true
		rraw, ok := receipts[e.DeliveryID]
		if !ok || digest(rraw) != set.Receipts[e.DeliveryID] {
			return false
		}
		var r struct {
			Version                                                                  int
			OwnerID, DeliveryID, Namespace, EntryDigest, EvidenceDigest, Termination string
		}
		if json.Unmarshal(rraw, &r) != nil {
			return false
		}
		var canonical bytes.Buffer
		if json.Compact(&canonical, raw) != nil {
			return false
		}
		if r.Version != 1 || r.OwnerID != set.OwnerID || r.DeliveryID != e.DeliveryID || r.Namespace != set.Namespace || r.EntryDigest != digest(canonical.Bytes()) || r.EvidenceDigest != set.EvidenceDigest || r.Termination != "supervisor-confirmed-runtime-stop" {
			return false
		}
	}
	return len(active) == len(set.Receipts)
}
func main() {
	setPath := flag.String("receipt-set", "", "optional complete pinned receipt-set manifest")
	setSHA := flag.String("receipt-set-sha", "", "exact receipt-set SHA256")
	delivery := flag.String("delivery", "", "exact validated delivery UUID")
	ns := flag.String("namespace", "", "")
	journal := flag.String("journal-sha", "", "")
	receipt := flag.String("receipt-sha", "", "")
	flag.Parse()
	if os.Geteuid() != 0 || len(*journal) != 64 || (*setPath == "" && len(*receipt) != 64) || (*setPath == "" && !validDelivery(*delivery)) {
		panic("release identity missing")
	}
	actual, e := os.Readlink("/proc/self/ns/net")
	if e != nil || actual != *ns {
		panic("namespace mismatch")
	}
	rawJournal := privateLimit("/state/ipsec/journal.json", 4<<20)
	if *setPath != "" {
		if *delivery != "" || *receipt != "" || len(*setSHA) != 64 {
			panic("ambiguous receipt mode")
		}
		rawSet := private(*setPath)
		var set receiptSet
		if digest(rawSet) != *setSHA || json.Unmarshal(rawSet, &set) != nil || set.Namespace != *ns || set.JournalSHA != *journal {
			panic("receipt set mismatch")
		}
		receipts := map[string][]byte{}
		for id := range set.Receipts {
			if !validDelivery(id) {
				panic("invalid delivery")
			}
			receipts[id] = private("/state/ipsec/restore-" + id + ".json")
		}
		if !matchesReceiptSet(rawJournal, set, receipts) {
			panic("incomplete receipt set")
		}
	} else {
		rawReceipt := private("/state/ipsec/restore-" + *delivery + ".json")
		if digest(rawJournal) != *journal || !journalMatches(rawJournal, *delivery) || digest(rawReceipt) != *receipt || !receiptMatches(rawReceipt, *delivery, *ns) {
			panic("genuine receipt/journal mismatch")
		}
	}
	gate := private("/state/ipsec/restoration-startup-gate")
	if string(gate) != "owned enrolled restoration supervisor blocks Apply until genuine new namespace receipt durable\n" {
		panic("foreign gate refused")
	}
	if _, e = os.Lstat("/run/enrolled-restoration-release"); !os.IsNotExist(e) {
		panic("release marker already exists")
	}
	if os.Remove("/state/ipsec/restoration-startup-gate") != nil {
		panic("gate release refused")
	}
	fsyncDir("/state/ipsec")
	f, e := os.OpenFile("/run/enrolled-restoration-release.next", os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		panic("startup release refused")
	}
	if _, e = f.WriteString("genuine enrolled restoration receipt installed; startup authorized\n"); e != nil || f.Sync() != nil {
		f.Close()
		panic("startup release fsync refused")
	}
	if f.Close() != nil {
		panic("startup release close refused")
	}
	if os.Link("/run/enrolled-restoration-release.next", "/run/enrolled-restoration-release") != nil {
		panic("startup marker publish refused")
	}
	if os.Remove("/run/enrolled-restoration-release.next") != nil {
		panic("startup temporary marker cleanup refused")
	}
	fsyncDir("/run")
}

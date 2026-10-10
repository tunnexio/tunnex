package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type freshRuntime struct {
	CurrentJournalSHA256 string `json:"current_journal_sha256"`
	Version              int    `json:"version"`
	Kind                 string `json:"kind"`
	Container            string `json:"container"`
	Boot                 string `json:"boot"`
	Namespace            string `json:"namespace"`
	PID                  int    `json:"pid"`
	PIDStartTicks        uint64 `json:"pid_start_ticks"`
	StartedAt            string `json:"started_at"`
	StopEvidenceSHA256   string `json:"stop_evidence_sha256"`
	StoppedJournalSHA256 string `json:"stopped_journal_sha256"`
	StartupGateSHA256    string `json:"startup_gate_sha256"`
	StartupGateDevice    uint64 `json:"startup_gate_device"`
	StartupGateInode     uint64 `json:"startup_gate_inode"`
}

func parseFresh(raw []byte) (freshRuntime, error) {
	var f freshRuntime
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if err := d.Decode(&f); err != nil {
		return f, err
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return f, errors.New("extra fresh runtime evidence")
	}
	return f, nil
}
func validateFresh(raw, journal, current, evidence []byte, p proof, boot, ns string) error {
	f, err := parseFresh(raw)
	if err != nil {
		return err
	}
	old, err := time.Parse(time.RFC3339Nano, p.Snapshot.Started)
	if err != nil {
		return err
	}
	started, err := time.Parse(time.RFC3339Nano, f.StartedAt)
	if err != nil {
		return err
	}
	if f.Version != 1 || f.Kind != "supervisor-confirmed-fresh-runtime" || f.Container != p.Snapshot.Container || f.Boot != boot || f.Namespace != ns || p.Snapshot.PID <= 0 || f.PID <= 0 || f.PID == p.Snapshot.PID || f.PIDStartTicks == 0 || !started.After(old) || p.Termination.TimeNS <= old.UnixNano() || started.UnixNano() <= p.VerifiedNS || f.StopEvidenceSHA256 != digest(evidence) || f.StoppedJournalSHA256 != digest(journal) || f.CurrentJournalSHA256 != digest(current) || len(f.StartupGateSHA256) != 64 || f.StartupGateDevice == 0 || f.StartupGateInode == 0 {
		return errors.New("fresh runtime evidence mismatch")
	}
	return validateCurrentJournal(journal, current)
}

// Independent reads in the executing helper refuse a recycled PID or replaced
// gate after the supervisor's Docker observation. No evidence file is rewritten.
func verifyFreshCurrent(raw []byte, gate, boot, ns string) error {
	f, err := parseFresh(raw)
	if err != nil {
		return err
	}
	before, err := os.Lstat(gate)
	if err != nil {
		return err
	}
	st, ok := before.Sys().(*syscall.Stat_t)
	if !ok || uint64(st.Dev) != f.StartupGateDevice || st.Ino != f.StartupGateInode {
		return errors.New("gate identity mismatch")
	}
	b, err := privateRead(gate, 8192)
	if err != nil || digest(b) != f.StartupGateSHA256 {
		return errors.New("gate content mismatch")
	}
	var g struct {
		Version       int
		SupervisorRun string
		ContainerID   string
	}
	if json.Unmarshal(b, &g) != nil || g.Version != 1 || g.SupervisorRun == "" || g.ContainerID != f.Container {
		return errors.New("gate owner mismatch")
	}
	cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", f.PID))
	if err != nil || strings.TrimSpace(string(cgroup)) != "0::/docker/"+f.Container {
		return errors.New("fresh process cgroup mismatch")
	}
	current, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", f.PID))
	if err != nil || current != ns || f.Namespace != ns || f.Boot != boot {
		return errors.New("fresh process namespace mismatch")
	}
	proc, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", f.PID))
	if err != nil {
		return err
	}
	at := strings.LastIndex(string(proc), ") ")
	if at < 0 {
		return errors.New("process stat invalid")
	}
	fields := strings.Fields(string(proc)[at+2:])
	if len(fields) <= 19 {
		return errors.New("process stat invalid")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks != f.PIDStartTicks {
		return errors.New("fresh process identity changed")
	}
	after, err := os.Lstat(gate)
	if err != nil || !os.SameFile(before, after) || after.Mode().Perm() != 0600 {
		return errors.New("startup gate replaced")
	}
	final, err := privateRead(gate, 8192)
	if err != nil || digest(final) != f.StartupGateSHA256 {
		return errors.New("startup gate changed")
	}
	return nil
}

func validateCurrentJournal(stopped, current []byte) error {
	oldOwner, err := validateJournal(stopped)
	if err != nil {
		return err
	}
	owner, err := validateJournal(current)
	if err != nil || owner != oldOwner {
		return errors.New("current journal invalid")
	}
	type projection struct {
		Payload struct {
			OwnerID  uuid.UUID
			Version  int
			Sequence uint64
			Entries  []ipsec.RuntimeJournalEntry
		}
	}
	var before, after projection
	if json.Unmarshal(stopped, &before) != nil || json.Unmarshal(current, &after) != nil || before.Payload.OwnerID != after.Payload.OwnerID || before.Payload.Version != after.Payload.Version || after.Payload.Sequence < before.Payload.Sequence || !reflect.DeepEqual(before.Payload.Entries, after.Payload.Entries) {
		return errors.New("current journal lineage changed")
	}
	return nil
}

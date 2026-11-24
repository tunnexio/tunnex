package hostposture

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

const (
	// HostFactsSchemaVersion 2 adds netfilter.legacy_iptables (K8N review,
	// finding 5). A receipt of version 1 says nothing about legacy tables and
	// is refused as an unknown schema, before its digest is checked.
	//
	// Version 3 carries Cilium's routing member and device list in
	// cilium.status (K8N-6). A version 2 receipt from a Cilium node lacks them,
	// and a gateway of this release would refuse it as "no routing section",
	// which blames Cilium for an old manager; a gateway of the release before
	// would accept a version 3 receipt and ignore the host routing mode. Both
	// are refused as an unknown schema instead, on every node, as the manager
	// and the gateway must be of the same release.
	HostFactsSchemaVersion = 3
	HostFactsContract      = "tunnex-host-posture-facts/v1"
	// HostFactsFreshness is how old the manager's read may be when a gateway
	// takes it. It is the heartbeat's own window.
	HostFactsFreshness = HeartbeatFreshness

	hostFactsFile = "host-facts.json"
	maxHostFacts  = 256 << 10
)

// HostFacts is the public receipt of what the privileged manager read on this
// node for a gateway that cannot read it itself (K8N-1, Decision 9). It carries
// facts, never a verdict, and nothing secret: rule text and set members.
//
// It is bound to one heartbeat of one manager process by node, manager, boot
// and sequence, like the CNI authority receipt. ObservedAt is when the manager
// began reading, which may be before or after that heartbeat's own time.
type HostFacts struct {
	SchemaVersion int                     `json:"schema_version"`
	Contract      string                  `json:"contract"`
	NodeName      string                  `json:"node_name"`
	ManagerUID    string                  `json:"manager_uid"`
	ManagerBootID string                  `json:"manager_boot_id"`
	Sequence      uint64                  `json:"sequence"`
	ObservedAt    time.Time               `json:"observed_at"`
	Netfilter     k8snetprep.HostNetFacts `json:"netfilter"`
	// Cilium is present only when the manager saw a trace of Cilium on the
	// node (K8N-2). It is under the same identity, freshness and digest as the
	// rest. A node without Cilium publishes the receipt exactly as before.
	Cilium *k8snetprep.CiliumFacts `json:"cilium,omitempty"`
	// Digest is the SHA-256 of the receipt encoded with this field empty. It
	// detects a damaged or partly rewritten file. It is not a signature: the
	// directory is writable by root on the node only.
	Digest string `json:"digest"`
}

// HostFactsReader is the manager's privileged reader.
type HostFactsReader interface {
	Read(context.Context) k8snetprep.HostNetFacts
}

// CiliumFactsReader is the manager's reader of Cilium's own report. It
// returns nil on a node that shows no Cilium.
type CiliumFactsReader interface {
	Read(context.Context) *k8snetprep.CiliumFacts
}

func hostFactsDigest(receipt HostFacts) (string, error) {
	receipt.Digest = ""
	var body bytes.Buffer
	enc := json.NewEncoder(&body)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(receipt); err != nil {
		return "", fmt.Errorf("encode host facts: %w", err)
	}
	sum := sha256.Sum256(body.Bytes())
	return hex.EncodeToString(sum[:]), nil
}

// SealHostFacts seals facts read at observedAt into the receipt of one
// heartbeat. Facts that are malformed or would not fit the file are replaced
// by the statement that they could not be published; they are never cut.
func SealHostFacts(heartbeat Heartbeat, observedAt time.Time, facts k8snetprep.HostNetFacts) (HostFacts, error) {
	return SealHostFactsWithCilium(heartbeat, observedAt, facts, nil)
}

// SealHostFactsWithCilium is SealHostFacts with the `cilium` section of a node
// that shows Cilium. The same rule holds for it: a section that is malformed
// or does not fit is replaced by the statement that it could not be published.
func SealHostFactsWithCilium(heartbeat Heartbeat, observedAt time.Time, facts k8snetprep.HostNetFacts, cilium *k8snetprep.CiliumFacts) (HostFacts, error) {
	if err := facts.Validate(); err != nil {
		facts = k8snetprep.UnreadableHostNetFacts(err.Error())
	}
	if cilium != nil {
		if err := cilium.Validate(); err != nil {
			cilium = k8snetprep.UnreadableCiliumFacts(err.Error())
		}
	}
	receipt := HostFacts{
		SchemaVersion: HostFactsSchemaVersion, Contract: HostFactsContract,
		NodeName: heartbeat.NodeName, ManagerUID: heartbeat.ManagerUID, ManagerBootID: heartbeat.ManagerBootID,
		Sequence: heartbeat.Sequence, ObservedAt: observedAt.UTC(), Netfilter: facts, Cilium: cilium,
	}
	for attempt := 0; ; attempt++ {
		digest, err := hostFactsDigest(receipt)
		if err != nil {
			return HostFacts{}, err
		}
		receipt.Digest = digest
		encoded, err := json.Marshal(receipt)
		if err != nil {
			return HostFacts{}, fmt.Errorf("encode host facts: %w", err)
		}
		// Escaping can grow the text; leave room for the encoder's own form.
		if len(encoded) <= maxHostFacts-1024 {
			return receipt, nil
		}
		if attempt > 0 {
			return HostFacts{}, fmt.Errorf("host facts receipt exceeds bounded size")
		}
		receipt.Netfilter = k8snetprep.UnreadableHostNetFacts(fmt.Sprintf("host facts exceed %d bytes", maxHostFacts))
		if receipt.Cilium != nil {
			receipt.Cilium = k8snetprep.UnreadableCiliumFacts(fmt.Sprintf("host facts exceed %d bytes", maxHostFacts))
		}
		receipt.Digest = ""
	}
}

// validateHostFacts accepts a receipt only for the live heartbeat it was
// written with, on this node, within the freshness window, undamaged.
func validateHostFacts(receipt HostFacts, heartbeat Heartbeat, node string, now time.Time) error {
	if err := validateHeartbeat(heartbeat, node, now); err != nil {
		return err
	}
	if heartbeat.State != HeartbeatActive {
		return fmt.Errorf("host facts require an active host-posture heartbeat")
	}
	if receipt.SchemaVersion != HostFactsSchemaVersion || receipt.Contract != HostFactsContract {
		return fmt.Errorf("host facts receipt has an unknown schema or contract")
	}
	if receipt.NodeName != node {
		return fmt.Errorf("host facts receipt is from another node")
	}
	if receipt.ManagerUID != heartbeat.ManagerUID || receipt.ManagerBootID != heartbeat.ManagerBootID {
		return fmt.Errorf("host facts receipt is from another host-posture manager process")
	}
	if receipt.Sequence != heartbeat.Sequence {
		return fmt.Errorf("host facts receipt does not belong to the live heartbeat")
	}
	if receipt.ObservedAt.IsZero() || receipt.ObservedAt.After(now.Add(2*time.Second)) || now.Sub(receipt.ObservedAt) > HostFactsFreshness {
		return fmt.Errorf("host facts receipt is stale or from the future")
	}
	digest, err := hostFactsDigest(receipt)
	if err != nil || digest != receipt.Digest {
		return fmt.Errorf("host facts receipt is damaged: its digest does not match")
	}
	if err := receipt.Netfilter.Validate(); err != nil {
		return err
	}
	if receipt.Cilium != nil {
		if err := receipt.Cilium.Validate(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) LoadHostFacts() (HostFacts, error) {
	var receipt HostFacts
	if err := readStrictJSON(s.HostFactsPath(), maxHostFacts, &receipt); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return HostFacts{}, fmt.Errorf("host facts receipt is missing")
		}
		return HostFacts{}, fmt.Errorf("read host facts receipt: %w", err)
	}
	return receipt, nil
}

func (s *Store) SaveHostFacts(receipt HostFacts) error {
	if s.readOnly {
		return fmt.Errorf("read-only posture store cannot publish host facts")
	}
	return s.atomicBoundedJSON(hostFactsFile, receipt, 0o644, maxHostFacts)
}

// HostNetFacts is the gateway's side: the facts of the receipt that belongs to
// the live heartbeat of this node, or the reason there are none. The caller
// holds the CNI operation lock, under which the manager writes both files, so
// the two are read as one publication.
func (s *Store) HostNetFacts(node string, now time.Time) (k8snetprep.HostNetFacts, error) {
	receipt, err := s.liveHostFacts(node, now)
	if err != nil {
		return k8snetprep.HostNetFacts{}, err
	}
	return receipt.Netfilter, nil
}

// CiliumFacts is the gateway's side for the `cilium` section: the section of
// the receipt that belongs to the live heartbeat of this node, nil when that
// receipt has none, or the reason there is no such receipt. The receipt is
// accepted under exactly the rules of HostNetFacts, with the same lock held.
func (s *Store) CiliumFacts(node string, now time.Time) (*k8snetprep.CiliumFacts, error) {
	receipt, err := s.liveHostFacts(node, now)
	if err != nil {
		return nil, err
	}
	return receipt.Cilium, nil
}

func (s *Store) liveHostFacts(node string, now time.Time) (HostFacts, error) {
	if !validNodeName(node) {
		return HostFacts{}, fmt.Errorf("gateway host facts identity is invalid")
	}
	heartbeat, err := s.LoadHeartbeat()
	if err != nil {
		return HostFacts{}, err
	}
	receipt, err := s.LoadHostFacts()
	if err != nil {
		return HostFacts{}, err
	}
	if err := validateHostFacts(receipt, heartbeat, node, now); err != nil {
		return HostFacts{}, err
	}
	return receipt, nil
}

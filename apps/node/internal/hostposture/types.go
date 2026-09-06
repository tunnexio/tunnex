// Package hostposture owns the provider-neutral, per-node lifecycle boundary
// for host-network Kubernetes gateways. It deliberately consumes only
// Kubernetes Pod identity plus Linux kernel state; cloud-provider SDKs and
// provider labels are not part of the contract.
package hostposture

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/k8snetprep"
)

const (
	Contract                      = "tunnex-host-posture/v1"
	OwnerLabelKey                 = "tunnex.io/host-posture-owner"
	OwnerLabelValue               = "true"
	OwnerContractAnnotation       = "tunnex.io/host-posture-contract"
	OwnerServiceAccountAnnotation = "tunnex.io/host-posture-service-account"
	DefaultStateDir               = "/var/lib/tunnex/host-posture/v1"
	DefaultHostProcSys            = "/host/proc/sys"
	DefaultWireGuardIface         = "wg0"
	WireGuardAlias                = "tunnex-host-posture/v1"
	NFTMarkerComment              = "tunnex_host_posture_v1"
	RouteMetric                   = 8021
	ReturnRulePriority            = 100
	ReturnRuleLookup              = "main"
	LegacyJournalSchemaVersion    = 1
	StagedJournalSchemaVersion    = 2
	AWSJournalSchemaVersion       = 3
	JournalSchemaVersion          = 4
	HeartbeatSchemaVersion        = 1
	DefaultMaxOwners              = 32
	// Invalid label-selected Pods do not consume the valid-owner limit, but the
	// candidate scan itself remains independently bounded against list abuse.
	DefaultMaxOwnerCandidates = 256
	MaxOwnerUIDBytes          = 128
	MaxReasonBytes            = 240
	MaxKubernetesResponse     = 1 << 20
	DefaultReconcileInterval  = 2 * time.Second
	DefaultAPIRequestTimeout  = 10 * time.Second
	HeartbeatFreshness        = 10 * time.Second
)

const (
	StatePreparing = "preparing"
	StateActive    = "active"
	StateRestoring = "restoring"
	StateRestored  = "restored"

	HeartbeatIdle    = "idle"
	HeartbeatActive  = "active"
	HeartbeatBlocked = "blocked"
)

const (
	WireGuardPhaseStagingPlanned = "staging_planned"
	WireGuardPhaseStagingCreated = "staging_created"
	WireGuardPhaseStagingMarked  = "staging_marked"
	WireGuardPhaseCommitted      = "committed"
)

var ErrNoJournal = errors.New("host-posture journal does not exist")

// SysctlReceipt records the exact pre-Tunnex value before the first mutation
// in an ownership epoch. The key and desired value are fixed product inputs.
type SysctlReceipt struct {
	Key      string `json:"key"`
	Original string `json:"original"`
	Desired  string `json:"desired"`
	Restored bool   `json:"restored,omitempty"`
	Skipped  bool   `json:"skipped_external_change,omitempty"`
}

// Owner is a live Kubernetes Pod identity on one exact node. Names are useful
// only for diagnostics; UID is the ownership key.
type Owner struct {
	UID       string `json:"uid"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
}

// ArtifactJournal is a closed set of kernel ownership signatures. Variable
// route prefixes and rule handles are enumerated only through these exact
// signatures; a marked artifact with an unknown shape blocks cleanup.
type ArtifactJournal struct {
	WireGuard WireGuardReceipt  `json:"wireguard"`
	NFTables  []NFTTableReceipt `json:"nftables"`
	Routes    RouteReceipt      `json:"routes"`
	CNI       CNIReceipt        `json:"cni"`
	Docker    DockerReceipt     `json:"docker"`
	// Omitted for historical epochs, including when those epochs are saved by
	// a new manager. A legacy receipt never gains AWS cleanup authority.
	AWSCNI *CNIReceipt `json:"aws_cni,omitempty"`
}

type WireGuardReceipt struct {
	Name           string `json:"name"`
	Alias          string `json:"alias"`
	IfIndex        int    `json:"ifindex,omitempty"`
	StagingName    string `json:"staging_name,omitempty"`
	StagingIfIndex int    `json:"staging_ifindex,omitempty"`
	Phase          string `json:"phase,omitempty"`
}

type NFTTableReceipt struct {
	Family  string `json:"family"`
	Name    string `json:"name"`
	Comment string `json:"marker_comment"`
}

type RouteReceipt struct {
	Interface    string `json:"interface"`
	Protocol     string `json:"protocol"`
	Metric       int    `json:"metric"`
	RulePriority int    `json:"rule_priority"`
	RuleLookup   string `json:"rule_lookup"`
}

type CNIReceipt struct {
	Family   string   `json:"family"`
	Table    string   `json:"table"`
	Chain    string   `json:"chain"`
	Comments []string `json:"comments"`
}

type DockerReceipt struct {
	Family  string `json:"family"`
	Table   string `json:"table"`
	Chain   string `json:"chain"`
	Comment string `json:"comment"`
}

// Journal is the crash authority. State=preparing is durable before creation,
// and state=restoring is durable before teardown; a restart can mutate only
// the exact fixed artifacts and direction named by this epoch.
type Journal struct {
	SchemaVersion int             `json:"schema_version"`
	Contract      string          `json:"contract"`
	NodeName      string          `json:"node_name"`
	Epoch         uint64          `json:"epoch"`
	State         string          `json:"state"`
	Sysctls       []SysctlReceipt `json:"sysctls"`
	Owners        []Owner         `json:"owners"`
	Artifacts     ArtifactJournal `json:"artifacts"`
	UpdatedAt     time.Time       `json:"updated_at"`
	LastError     string          `json:"last_error,omitempty"`
}

// UnmarshalJSON preserves the old strict schemas even for an explicit null
// aws_cni field, which the old decoders rejected as an unknown field.
func (j *Journal) UnmarshalJSON(body []byte) error {
	type wireJournal Journal
	var decoded wireJournal
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return err
	}
	if decoded.SchemaVersion == LegacyJournalSchemaVersion || decoded.SchemaVersion == StagedJournalSchemaVersion {
		var fields struct {
			Artifacts map[string]json.RawMessage `json:"artifacts"`
		}
		if err := json.Unmarshal(body, &fields); err != nil {
			return err
		}
		if _, present := fields.Artifacts["aws_cni"]; present {
			return fmt.Errorf("legacy journal contains unsupported AWS CNI receipt")
		}
	}
	*j = Journal(decoded)
	return nil
}

// Heartbeat is the non-secret, read-only admission handshake consumed by a
// gateway init container on the same node.
type Heartbeat struct {
	SchemaVersion int    `json:"schema_version"`
	Contract      string `json:"contract"`
	NodeName      string `json:"node_name"`
	ManagerUID    string `json:"manager_uid"`
	// ManagerBootID changes on every manager process start. The DaemonSet Pod UID
	// remains stable across a container restart, so UID alone cannot identify a
	// monotonic Sequence epoch.
	ManagerBootID string    `json:"manager_boot_id"`
	Sequence      uint64    `json:"sequence"`
	State         string    `json:"state"`
	Owners        []Owner   `json:"owners"`
	ObservedAt    time.Time `json:"observed_at"`
	Reason        string    `json:"reason,omitempty"`
}

// ValidateNFTMarkerChain accepts only the one fixed journal-owned marker rule.
// Both the manager and gateway shutdown use it before mutating shared tables.
func ValidateNFTMarkerChain(out, marker string) error {
	marker = `comment "` + marker + `"`
	markerToken := strings.TrimPrefix(marker, "comment ")
	lines := make([][]string, 0, 5)
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) != 0 {
			lines = append(lines, fields)
		}
	}
	if len(lines) != 5 || !isNFTMarkerTableHeader(lines[0]) || !isNFTMarkerChainHeader(lines[1]) || !isNFTMarkerRule(lines[2], markerToken) || !isNFTClosingBrace(lines[3]) || !isNFTClosingBrace(lines[4]) {
		return fmt.Errorf("nft owner chain contains an unrecognized rule")
	}
	if strings.Count(out, marker) != 1 {
		return fmt.Errorf("nft ownership marker is missing or ambiguous")
	}
	return nil
}

func isNFTMarkerTableHeader(fields []string) bool {
	return len(fields) == 4 && fields[0] == "table" && (fields[1] == "ip" || fields[1] == "ip6") && fields[2] == "tunnex" && fields[3] == "{"
}

func isNFTMarkerChainHeader(fields []string) bool {
	return len(fields) == 6 && fields[0] == "chain" && fields[1] == "tunnex_posture_owner" && fields[2] == "{" && fields[3] == "#" && fields[4] == "handle" && isCanonicalNFTDecimal(fields[5], false)
}

func isNFTMarkerRule(fields []string, marker string) bool {
	return len(fields) == 10 && fields[0] == "counter" && fields[1] == "packets" && isCanonicalNFTDecimal(fields[2], true) && fields[3] == "bytes" && isCanonicalNFTDecimal(fields[4], true) && fields[5] == "comment" && fields[6] == marker && fields[7] == "#" && fields[8] == "handle" && isCanonicalNFTDecimal(fields[9], false)
}

func isNFTClosingBrace(fields []string) bool {
	return len(fields) == 1 && fields[0] == "}"
}

func isCanonicalNFTDecimal(value string, allowZero bool) bool {
	if value == "0" {
		return allowZero
	}
	if value == "" || value[0] < '1' || value[0] > '9' {
		return false
	}
	for i := 1; i < len(value); i++ {
		if value[i] < '0' || value[i] > '9' {
			return false
		}
	}
	return true
}

func desiredSysctls() []SysctlReceipt {
	return []SysctlReceipt{
		{Key: "net/ipv4/ip_forward", Desired: "1"},
		{Key: "net/ipv4/conf/all/rp_filter", Desired: "0"},
		{Key: "net/ipv4/conf/default/rp_filter", Desired: "0"},
	}
}

func fixedArtifacts() ArtifactJournal {
	return ArtifactJournal{
		WireGuard: WireGuardReceipt{Name: DefaultWireGuardIface, Alias: WireGuardAlias},
		NFTables: []NFTTableReceipt{
			{Family: "ip", Name: "tunnex", Comment: NFTMarkerComment},
			{Family: "ip6", Name: "tunnex", Comment: NFTMarkerComment},
		},
		Routes: RouteReceipt{Interface: DefaultWireGuardIface, Protocol: "static", Metric: RouteMetric, RulePriority: ReturnRulePriority, RuleLookup: ReturnRuleLookup},
		CNI:    CNIReceipt{Family: "ip", Table: "nat", Chain: "IP-MASQ-AGENT", Comments: []string{"tunnex_k8s_ip_masq_bypass", "tunnex_ha_cni_masq_bypass"}},
		Docker: DockerReceipt{Family: "ip", Table: "filter", Chain: "DOCKER-USER", Comment: "tunnex-site-fwd"},
	}
}

func fixedArtifactsForSchema(schema int) ArtifactJournal {
	artifacts := fixedArtifacts()
	if schema == AWSJournalSchemaVersion || schema == JournalSchemaVersion {
		artifacts.AWSCNI = &CNIReceipt{Family: "ip", Table: "nat", Chain: "AWS-SNAT-CHAIN-0", Comments: []string{k8snetprep.AWSOwnedRuleComment}}
		if schema == JournalSchemaVersion {
			artifacts.AWSCNI.Comments = append(artifacts.AWSCNI.Comments, k8snetprep.AWSTransitOwnedRuleComment)
		}
	}
	return artifacts
}

func newJournal(node string, epoch uint64, originals []SysctlReceipt, owners []Owner, stagingName string, now time.Time) (Journal, error) {
	if !validWireGuardStagingName(stagingName) {
		return Journal{}, fmt.Errorf("WireGuard staging identity is invalid")
	}
	artifacts := fixedArtifactsForSchema(JournalSchemaVersion)
	artifacts.WireGuard.StagingName = stagingName
	artifacts.WireGuard.Phase = WireGuardPhaseStagingPlanned
	return Journal{
		SchemaVersion: JournalSchemaVersion,
		Contract:      Contract,
		NodeName:      node,
		Epoch:         epoch,
		State:         StatePreparing,
		Sysctls:       originals,
		Owners:        canonicalOwners(owners),
		Artifacts:     artifacts,
		UpdatedAt:     now.UTC(),
	}, nil
}

func (j Journal) validate(node string) error {
	if (j.SchemaVersion != LegacyJournalSchemaVersion && j.SchemaVersion != StagedJournalSchemaVersion && j.SchemaVersion != AWSJournalSchemaVersion && j.SchemaVersion != JournalSchemaVersion) || j.Contract != Contract || j.NodeName != node || j.Epoch == 0 {
		return fmt.Errorf("journal identity does not match %s on node %q", Contract, node)
	}
	if j.State != StatePreparing && j.State != StateActive && j.State != StateRestoring && j.State != StateRestored {
		return fmt.Errorf("journal state %q is unsupported", j.State)
	}
	wantSysctls := desiredSysctls()
	if len(j.Sysctls) != len(wantSysctls) {
		return fmt.Errorf("journal sysctl set is incomplete")
	}
	for i, want := range wantSysctls {
		got := j.Sysctls[i]
		if got.Key != want.Key || got.Desired != want.Desired || strings.TrimSpace(got.Original) == "" || strings.ContainsAny(got.Original, "\r\n") {
			return fmt.Errorf("journal sysctl receipt %d is invalid", i)
		}
	}
	wg := j.Artifacts.WireGuard
	baseArtifacts := j.Artifacts
	baseArtifacts.WireGuard.StagingName = ""
	baseArtifacts.WireGuard.StagingIfIndex = 0
	baseArtifacts.WireGuard.Phase = ""
	wantArtifacts := fixedArtifactsForSchema(j.SchemaVersion)
	wantArtifacts.WireGuard.IfIndex = wg.IfIndex
	if !reflect.DeepEqual(baseArtifacts, wantArtifacts) {
		return fmt.Errorf("journal artifact ownership contract is invalid")
	}
	if j.SchemaVersion == LegacyJournalSchemaVersion {
		if wg.StagingName != "" || wg.StagingIfIndex != 0 || wg.Phase != "" {
			return fmt.Errorf("legacy journal contains unsupported staged WireGuard state")
		}
	} else if err := validateStagedWireGuardReceipt(wg, j.State); err != nil {
		return err
	}
	if len(j.Owners) > DefaultMaxOwners {
		return fmt.Errorf("journal owner set is unbounded")
	}
	if !ownersEqual(j.Owners, canonicalOwners(j.Owners)) {
		return fmt.Errorf("journal owner set is not canonical")
	}
	if j.State == StateRestoring && len(j.Owners) != 0 {
		return fmt.Errorf("restoring journal retains owners")
	}
	return nil
}

func newWireGuardStagingName() (string, error) {
	var entropy [6]byte
	if _, err := rand.Read(entropy[:]); err != nil {
		return "", fmt.Errorf("generate WireGuard staging identity: %w", err)
	}
	// Linux IFNAMSIZ includes the trailing NUL, so the visible name must remain
	// at most 15 bytes. The persisted 48-bit suffix binds an otherwise inert
	// staging link to this exact journal before any kernel mutation occurs.
	return "tnx" + hex.EncodeToString(entropy[:]), nil
}

func validWireGuardStagingName(name string) bool {
	if len(name) != 15 || !strings.HasPrefix(name, "tnx") {
		return false
	}
	decoded, err := hex.DecodeString(name[3:])
	return err == nil && len(decoded) == 6
}

func validateStagedWireGuardReceipt(wg WireGuardReceipt, journalState string) error {
	if !validWireGuardStagingName(wg.StagingName) {
		return fmt.Errorf("journal WireGuard staging identity is invalid")
	}
	switch wg.Phase {
	case WireGuardPhaseStagingPlanned:
		if wg.StagingIfIndex != 0 || wg.IfIndex != 0 {
			return fmt.Errorf("planned WireGuard staging receipt contains live indices")
		}
	case WireGuardPhaseStagingCreated, WireGuardPhaseStagingMarked:
		if wg.StagingIfIndex < 1 || wg.IfIndex != 0 {
			return fmt.Errorf("staged WireGuard receipt has invalid indices")
		}
	case WireGuardPhaseCommitted:
		if wg.StagingIfIndex < 1 || wg.IfIndex != wg.StagingIfIndex {
			return fmt.Errorf("final WireGuard receipt has invalid indices")
		}
	default:
		return fmt.Errorf("journal WireGuard phase %q is unsupported", wg.Phase)
	}
	if journalState == StateActive && wg.Phase != WireGuardPhaseCommitted {
		return fmt.Errorf("active journal does not contain a final WireGuard receipt")
	}
	return nil
}

func fixedArtifactsWithIfIndex(index int) ArtifactJournal {
	a := fixedArtifacts()
	a.WireGuard.IfIndex = index
	return a
}

func canonicalOwners(in []Owner) []Owner {
	out := append([]Owner(nil), in...)
	sort.Slice(out, func(i, k int) bool {
		if out[i].UID != out[k].UID {
			return out[i].UID < out[k].UID
		}
		if out[i].Namespace != out[k].Namespace {
			return out[i].Namespace < out[k].Namespace
		}
		return out[i].Name < out[k].Name
	})
	return out
}

func ownersEqual(a, b []Owner) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func boundedReason(value string) string {
	value = strings.TrimSpace(value)
	if len(value) > MaxReasonBytes {
		return value[:MaxReasonBytes]
	}
	return value
}

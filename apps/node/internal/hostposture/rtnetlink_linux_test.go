//go:build linux

package hostposture

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestAtomicWireGuardLinkMessageCarriesCompleteOwnerIdentity(t *testing.T) {
	message, err := atomicWireGuardLinkMessage()
	if err != nil {
		t.Fatal(err)
	}
	wantFlags := netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl
	if message.Header.Type != netlink.HeaderType(unix.RTM_NEWLINK) || message.Header.Flags != wantFlags {
		t.Fatalf("header=%+v, want RTM_NEWLINK flags=%v", message.Header, wantFlags)
	}
	if len(message.Data) < unix.SizeofIfInfomsg || binary.NativeEndian.Uint32(message.Data[12:16]) != math.MaxUint32 {
		t.Fatalf("ifinfomsg is missing or has invalid ifi_change: %x", message.Data)
	}

	decoder, err := netlink.NewAttributeDecoder(message.Data[unix.SizeofIfInfomsg:])
	if err != nil {
		t.Fatal(err)
	}
	var name, alias, kind string
	seen := 0
	for decoder.Next() {
		seen++
		switch decoder.Type() {
		case unix.IFLA_IFNAME:
			name = decoder.String()
		case unix.IFLA_IFALIAS:
			alias = decoder.String()
		case unix.IFLA_LINKINFO:
			if decoder.TypeFlags() != netlink.Nested {
				t.Fatalf("IFLA_LINKINFO flags=%#x, want nested", decoder.TypeFlags())
			}
			decoder.Nested(func(nested *netlink.AttributeDecoder) error {
				if !nested.Next() || nested.Type() != unix.IFLA_INFO_KIND {
					return fmt.Errorf("missing exact IFLA_INFO_KIND")
				}
				kind = nested.String()
				if nested.Next() {
					return fmt.Errorf("unexpected extra link-info attribute %d", nested.Type())
				}
				return nested.Err()
			})
		default:
			t.Fatalf("unexpected top-level attribute %d", decoder.Type())
		}
	}
	if err := decoder.Err(); err != nil {
		t.Fatal(err)
	}
	if seen != 3 || name != DefaultWireGuardIface || alias != WireGuardAlias || kind != "wireguard" {
		t.Fatalf("atomic identity attrs=%d name=%q alias=%q kind=%q", seen, name, alias, kind)
	}
}

type fakeLinkCommandError string

func (e fakeLinkCommandError) Error() string { return string(e) }
func (fakeLinkCommandError) ExitCode() int   { return 1 }

func validPreparingJournal(nowNode string) Journal {
	receipts := desiredSysctls()
	for i := range receipts {
		receipts[i].Original = "0"
	}
	return newJournal(nowNode, 1, receipts, []Owner{{UID: "owner-uid", Namespace: "tunnex", Name: "gateway-a"}}, time.Time{})
}

func TestPrepareCreatesAndRecoversOnlyAtomicAliasOwnedWireGuard(t *testing.T) {
	procSys := t.TempDir()
	for _, receipt := range desiredSysctls() {
		writeSysctlFixture(t, procSys, receipt.Key, "0")
	}
	present := false
	link := wireGuardLink{}
	nftPresent := map[string]bool{}
	var commands []string
	runner := runnerFunc(func(_ context.Context, name string, input []byte, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		commands = append(commands, name+" "+joined)
		switch {
		case name == "ip" && joined == "-j -d link show dev wg0":
			if !present {
				return "", fakeLinkCommandError("Device wg0 does not exist")
			}
			return fmt.Sprintf(`[{"ifindex":%d,"ifname":%q,"ifalias":%q,"linkinfo":{"info_kind":%q}}]`, link.IfIndex, link.Name, link.Alias, link.Kind), nil
		case name == "nft" && strings.HasPrefix(joined, "list table "):
			parts := strings.Fields(joined)
			if !nftPresent[parts[2]] {
				return "", fakeLinkCommandError("No such file or directory")
			}
			return "table present", nil
		case name == "nft" && joined == "-f -":
			if strings.Contains(string(input), "add table ip6 tunnex") {
				nftPresent["ip6"] = true
			} else if strings.Contains(string(input), "add table ip tunnex") {
				nftPresent["ip"] = true
			} else {
				return "", fmt.Errorf("unexpected nft input %q", input)
			}
			return "", nil
		case name == "nft" && strings.HasPrefix(joined, "-a list chain "):
			return "chain tunnex_posture_owner {\n counter packets 0 bytes 0 comment \"tunnex_host_posture_v1\" # handle 2\n}\n", nil
		default:
			return "", fmt.Errorf("unexpected command %s %s", name, joined)
		}
	})
	kernel, err := NewLinuxKernel(procSys, runner)
	if err != nil {
		t.Fatal(err)
	}
	creates := 0
	kernel.createWireGuard = func(context.Context) error {
		creates++
		present = true
		link = wireGuardLink{Name: DefaultWireGuardIface, Alias: WireGuardAlias, Kind: "wireguard", IfIndex: 47}
		return nil
	}
	journal := validPreparingJournal("worker-node-a")
	if err := kernel.Prepare(t.Context(), &journal); err != nil {
		t.Fatal(err)
	}
	if creates != 1 || journal.Artifacts.WireGuard.IfIndex != 47 {
		t.Fatalf("creates=%d ifindex=%d", creates, journal.Artifacts.WireGuard.IfIndex)
	}
	for _, command := range commands {
		if strings.Contains(command, "ip link add") || strings.Contains(command, "ip link set") || strings.Contains(command, " alias ") {
			t.Fatalf("WireGuard identity used a non-atomic command: %s", command)
		}
	}

	// Simulate a process crash after the atomic kernel operation but before the
	// in-memory ifindex was saved. The complete alias-owned identity is safe to
	// recover without another create or an ownership mutation.
	journal.Artifacts.WireGuard.IfIndex = 0
	if err := kernel.Prepare(t.Context(), &journal); err != nil {
		t.Fatalf("recover complete atomic identity: %v", err)
	}
	if creates != 1 || journal.Artifacts.WireGuard.IfIndex != 47 {
		t.Fatalf("crash recovery creates=%d ifindex=%d", creates, journal.Artifacts.WireGuard.IfIndex)
	}
}

func TestPrepareRefusesUnmarkedWireGuardCrashCandidate(t *testing.T) {
	runner := runnerFunc(func(_ context.Context, name string, _ []byte, args ...string) (string, error) {
		if name == "ip" && strings.Join(args, " ") == "-j -d link show dev wg0" {
			return `[{"ifindex":51,"ifname":"wg0","ifalias":"","linkinfo":{"info_kind":"wireguard"}}]`, nil
		}
		return "", fmt.Errorf("unexpected mutation %s %s", name, strings.Join(args, " "))
	})
	kernel, err := NewLinuxKernel(t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}
	kernel.createWireGuard = func(context.Context) error {
		t.Fatal("creator must not run when an ambiguous wg0 is present")
		return nil
	}
	journal := validPreparingJournal("worker-node-a")
	err = kernel.Prepare(t.Context(), &journal)
	if err == nil || !strings.Contains(err.Error(), "ownership marker is missing or ambiguous") {
		t.Fatalf("unmarked crash candidate error=%v", err)
	}
	if journal.Artifacts.WireGuard.IfIndex != 0 {
		t.Fatalf("ambiguous interface entered journal: %+v", journal.Artifacts.WireGuard)
	}
}

func TestPrepareRefusesAtomicCreateWithoutExactOwnerReadback(t *testing.T) {
	reads := 0
	runner := runnerFunc(func(_ context.Context, name string, _ []byte, args ...string) (string, error) {
		if name != "ip" || strings.Join(args, " ") != "-j -d link show dev wg0" {
			return "", fmt.Errorf("unexpected mutation %s %s", name, strings.Join(args, " "))
		}
		reads++
		if reads == 1 {
			return "", fakeLinkCommandError("Device wg0 does not exist")
		}
		return `[{"ifindex":52,"ifname":"wg0","ifalias":"foreign-owner","linkinfo":{"info_kind":"wireguard"}}]`, nil
	})
	kernel, err := NewLinuxKernel(t.TempDir(), runner)
	if err != nil {
		t.Fatal(err)
	}
	creates := 0
	kernel.createWireGuard = func(context.Context) error {
		creates++
		return nil
	}
	journal := validPreparingJournal("worker-node-a")
	err = kernel.Prepare(t.Context(), &journal)
	if err == nil || !strings.Contains(err.Error(), "ownership marker is missing or ambiguous") {
		t.Fatalf("foreign post-create readback error=%v", err)
	}
	if creates != 1 || reads != 2 || journal.Artifacts.WireGuard.IfIndex != 0 {
		t.Fatalf("creates=%d reads=%d journal=%+v", creates, reads, journal.Artifacts.WireGuard)
	}
}

func TestRestoreRecoversAtomicAliasIfOwnerDisappearsBeforeIfIndexPersistence(t *testing.T) {
	procSys := t.TempDir()
	for _, receipt := range desiredSysctls() {
		writeSysctlFixture(t, procSys, receipt.Key, "0")
	}
	present := true
	deleted := 0
	runner := runnerFunc(func(_ context.Context, name string, _ []byte, args ...string) (string, error) {
		joined := strings.Join(args, " ")
		switch {
		case name == "nft" && (joined == "-a list chain ip nat IP-MASQ-AGENT" ||
			joined == "-a list chain ip filter DOCKER-USER" || strings.HasPrefix(joined, "list table ")):
			return "", fakeLinkCommandError("Error: Could not process rule: No such file or directory")
		case name == "ip" && (joined == "-4 route show" || joined == "-4 rule show pref 100" ||
			joined == "-6 route show" || joined == "-6 rule show pref 100"):
			return "", nil
		case name == "ip" && joined == "-j -d link show dev wg0":
			if !present {
				return "", fakeLinkCommandError("Device wg0 does not exist")
			}
			return `[{"ifindex":61,"ifname":"wg0","ifalias":"tunnex-host-posture/v1","linkinfo":{"info_kind":"wireguard"}}]`, nil
		case name == "ip" && joined == "link del wg0":
			present = false
			deleted++
			return "", nil
		default:
			return "", fmt.Errorf("unexpected command %s %s", name, joined)
		}
	})
	kernel, err := NewLinuxKernel(procSys, runner)
	if err != nil {
		t.Fatal(err)
	}
	journal := validPreparingJournal("worker-node-a")
	journal.Owners = nil
	if journal.Artifacts.WireGuard.IfIndex != 0 {
		t.Fatalf("test requires the pre-persistence journal: %+v", journal.Artifacts.WireGuard)
	}
	if err := kernel.RestoreAndCleanup(t.Context(), &journal); err != nil {
		t.Fatalf("clean exact atomic crash identity after owner disappeared: %v", err)
	}
	if deleted != 1 || present || journal.Artifacts.WireGuard.IfIndex != 61 {
		t.Fatalf("deleted=%d present=%v recovered ifindex=%d", deleted, present, journal.Artifacts.WireGuard.IfIndex)
	}
}

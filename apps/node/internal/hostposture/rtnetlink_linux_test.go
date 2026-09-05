//go:build linux

package hostposture

import (
	"encoding/binary"
	"testing"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

func TestLinkMutationMessagesTargetOnlyExactIfIndexAndAttribute(t *testing.T) {
	tests := []struct {
		name        string
		messageType int
		attribute   uint16
		value       string
	}{
		{name: "alias", messageType: unix.RTM_NEWLINK, attribute: unix.IFLA_IFALIAS, value: WireGuardAlias},
		{name: "rename", messageType: unix.RTM_NEWLINK, attribute: unix.IFLA_IFNAME, value: DefaultWireGuardIface},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attributes := netlink.NewAttributeEncoder()
			attributes.String(tt.attribute, tt.value)
			encoded, err := attributes.Encode()
			if err != nil {
				t.Fatal(err)
			}
			message, err := linkMutationMessage(tt.messageType, 77, encoded)
			if err != nil {
				t.Fatal(err)
			}
			assertLinkMutationEnvelope(t, message, tt.messageType, 77)
			decoder, err := netlink.NewAttributeDecoder(message.Data[unix.SizeofIfInfomsg:])
			if err != nil {
				t.Fatal(err)
			}
			if !decoder.Next() || decoder.Type() != tt.attribute || decoder.String() != tt.value {
				t.Fatalf("unexpected mutation attribute type=%d value=%q", decoder.Type(), tt.value)
			}
			if decoder.Next() || decoder.Err() != nil {
				t.Fatalf("mutation contains extra or malformed attributes: %v", decoder.Err())
			}
		})
	}
}

func TestDeleteLinkMutationHasNoAttributesOrFlagChanges(t *testing.T) {
	message, err := linkMutationMessage(unix.RTM_DELLINK, 91, nil)
	if err != nil {
		t.Fatal(err)
	}
	assertLinkMutationEnvelope(t, message, unix.RTM_DELLINK, 91)
	if len(message.Data) != unix.SizeofIfInfomsg {
		t.Fatalf("delete message has unexpected attributes: %x", message.Data[unix.SizeofIfInfomsg:])
	}
}

func assertLinkMutationEnvelope(t *testing.T, message netlink.Message, messageType, ifIndex int) {
	t.Helper()
	if message.Header.Type != netlink.HeaderType(messageType) || message.Header.Flags != netlink.Request|netlink.Acknowledge {
		t.Fatalf("header=%+v", message.Header)
	}
	if len(message.Data) < unix.SizeofIfInfomsg {
		t.Fatalf("short ifinfomsg: %x", message.Data)
	}
	if got := int(int32(binary.NativeEndian.Uint32(message.Data[4:8]))); got != ifIndex {
		t.Fatalf("ifindex=%d want=%d", got, ifIndex)
	}
	if got := binary.NativeEndian.Uint32(message.Data[8:12]); got != 0 {
		t.Fatalf("ifi_flags=%#x, want zero", got)
	}
	if got := binary.NativeEndian.Uint32(message.Data[12:16]); got != 0 {
		t.Fatalf("ifi_change=%#x, want zero", got)
	}
}

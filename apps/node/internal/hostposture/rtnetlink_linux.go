//go:build linux

package hostposture

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const atomicLinkCreateTimeout = 10 * time.Second

// atomicWireGuardLinkMessage carries the fixed name, kind, and ownership alias
// in one RTM_NEWLINK request. The kernel either accepts that complete identity
// or rejects the create; there is no user-space interval in which an unmarked
// wg0 can be mistaken for a crash intermediate.
func atomicWireGuardLinkMessage() (netlink.Message, error) {
	linkInfo := netlink.NewAttributeEncoder()
	linkInfo.String(unix.IFLA_INFO_KIND, "wireguard")
	encodedLinkInfo, err := linkInfo.Encode()
	if err != nil {
		return netlink.Message{}, fmt.Errorf("encode WireGuard link kind: %w", err)
	}

	attributes := netlink.NewAttributeEncoder()
	attributes.String(unix.IFLA_IFNAME, DefaultWireGuardIface)
	attributes.String(unix.IFLA_IFALIAS, WireGuardAlias)
	attributes.Do(unix.IFLA_LINKINFO|netlink.Nested, func() ([]byte, error) {
		return encodedLinkInfo, nil
	})
	encodedAttributes, err := attributes.Encode()
	if err != nil {
		return netlink.Message{}, fmt.Errorf("encode WireGuard link identity: %w", err)
	}

	// struct ifinfomsg is 16 bytes on Linux. ifi_change must be all ones for
	// RTM_NEWLINK; every other field is intentionally the zero/AF_UNSPEC create
	// default and the exact identity lives in the attributes above.
	ifInfo := make([]byte, unix.SizeofIfInfomsg)
	ifInfo[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(ifInfo[12:16], math.MaxUint32)
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(unix.RTM_NEWLINK),
			Flags: netlink.Request | netlink.Acknowledge | netlink.Create | netlink.Excl,
		},
		Data: append(ifInfo, encodedAttributes...),
	}, nil
}

func createWireGuardLinkAtomic(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	message, err := atomicWireGuardLinkMessage()
	if err != nil {
		return err
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return fmt.Errorf("open route netlink socket: %w", err)
	}
	defer conn.Close()

	deadline := time.Now().Add(atomicLinkCreateTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("bound route netlink create: %w", err)
	}
	if _, err := conn.Execute(message); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("atomic RTM_NEWLINK WireGuard create: %w", err)
	}
	return nil
}

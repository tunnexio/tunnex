//go:build linux

package hostposture

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/mdlayher/netlink"
	"golang.org/x/sys/unix"
)

const linkMutationTimeout = 10 * time.Second

func setLinkAliasByIndex(ctx context.Context, ifIndex int, alias string) error {
	attributes := netlink.NewAttributeEncoder()
	attributes.String(unix.IFLA_IFALIAS, alias)
	encoded, err := attributes.Encode()
	if err != nil {
		return fmt.Errorf("encode link alias: %w", err)
	}
	return executeLinkMutation(ctx, unix.RTM_NEWLINK, ifIndex, encoded)
}

func renameLinkByIndex(ctx context.Context, ifIndex int, name string) error {
	attributes := netlink.NewAttributeEncoder()
	attributes.String(unix.IFLA_IFNAME, name)
	encoded, err := attributes.Encode()
	if err != nil {
		return fmt.Errorf("encode link name: %w", err)
	}
	return executeLinkMutation(ctx, unix.RTM_NEWLINK, ifIndex, encoded)
}

func deleteLinkByIndex(ctx context.Context, ifIndex int) error {
	return executeLinkMutation(ctx, unix.RTM_DELLINK, ifIndex, nil)
}

func executeLinkMutation(ctx context.Context, messageType int, ifIndex int, attributes []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ifIndex < 1 {
		return fmt.Errorf("refuse invalid link ifindex %d", ifIndex)
	}
	message, err := linkMutationMessage(messageType, ifIndex, attributes)
	if err != nil {
		return err
	}
	conn, err := netlink.Dial(unix.NETLINK_ROUTE, nil)
	if err != nil {
		return fmt.Errorf("open route netlink socket: %w", err)
	}
	defer conn.Close()
	deadline := time.Now().Add(linkMutationTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return fmt.Errorf("bound route netlink mutation: %w", err)
	}
	if _, err := conn.Execute(message); err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return contextErr
		}
		return fmt.Errorf("route netlink link mutation: %w", err)
	}
	return nil
}

func linkMutationMessage(messageType int, ifIndex int, attributes []byte) (netlink.Message, error) {
	if ifIndex < 1 {
		return netlink.Message{}, fmt.Errorf("refuse invalid link ifindex %d", ifIndex)
	}
	ifInfo := make([]byte, unix.SizeofIfInfomsg)
	ifInfo[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(ifInfo[4:8], uint32(ifIndex))
	// ifi_flags and ifi_change intentionally remain zero. These operations only
	// change the one encoded attribute and must not clear any live link flags.
	return netlink.Message{
		Header: netlink.Header{
			Type:  netlink.HeaderType(messageType),
			Flags: netlink.Request | netlink.Acknowledge,
		},
		Data: append(ifInfo, attributes...),
	}, nil
}

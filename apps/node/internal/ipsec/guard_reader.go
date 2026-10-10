package ipsec

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"time"

	"github.com/google/uuid"
)

var ErrGuardRead = errors.New("IPsec guard could not be verified")

// GuardReader only observes the current namespace. Successful Check does not
// install or renew authority, prove SA ownership, or acknowledge cleanup.
type GuardReader struct {
	run        func(context.Context, ...string) ([]byte, error)
	namespace  func() (string, error)
	interfaces func() ([]GuardInterface, error)
}

// nftPath is a trusted absolute executable from the composition root.
func NewGuardReader(nftPath string) (*GuardReader, error) {
	if !filepath.IsAbs(nftPath) {
		return nil, ErrGuardRead
	}
	return &GuardReader{
		run: func(ctx context.Context, args ...string) ([]byte, error) {
			return runKernelCommand(ctx, nftPath, args...)
		},
		namespace: func() (string, error) { return os.Readlink("/proc/self/ns/net") },
		interfaces: func() ([]GuardInterface, error) {
			links, err := net.Interfaces()
			if err != nil {
				return nil, ErrGuardRead
			}
			out := make([]GuardInterface, 0, len(links))
			for _, link := range links {
				out = append(out, GuardInterface{Name: link.Name, Index: link.Index})
			}
			return out, nil
		},
	}, nil
}

// Check compares a trusted RenderGuard manifest with a bounded complete table
// listing bracketed by namespace/interface observations. The owning controller
// must separately serialize mutations and check its monotonic lease deadline.
func (r *GuardReader) Check(ctx context.Context, manifest GuardManifest) error {
	return r.check(ctx, manifest, VerifyGuardReadbackWithInterfaces)
}

// checkConnection observes full owned structure but requires all three exact
// target sets to remain positive. Other known members may naturally expire;
// their absence can never supply authority for this target.
func (r *GuardReader) checkConnection(ctx context.Context, manifest GuardManifest, id uuid.UUID) error {
	if id == uuid.Nil {
		return ErrGuardRead
	}
	return r.check(ctx, manifest, func(expected, observed []byte, links []GuardInterface) error {
		return verifyGuardConnectionReadback(expected, observed, links, id)
	})
}

// snapshot is created and consumed within one resolver proof. Exact raw binding
// prevents using another template; it never retains parsed observed authority.
type guardExpectedSnapshot struct {
	raw     string
	objects []any
}

func (r *GuardReader) checkConnectionSnapshot(ctx context.Context, manifest GuardManifest, id uuid.UUID, snapshot guardExpectedSnapshot) error {
	return r.checkConnectionSnapshotObserved(ctx, manifest, id, snapshot, nil)
}

// Values describe one fresh bracket only, never forwarding authority.
type guardReadTiming struct {
	CommandMillis, VerificationMillis int64
	FailureClass                      string
}

func (r *GuardReader) checkConnectionSnapshotObserved(ctx context.Context, manifest GuardManifest, id uuid.UUID, snapshot guardExpectedSnapshot, observe func(guardReadTiming)) error {
	if id == uuid.Nil || snapshot.raw != manifest.ExpectedJSON || len(snapshot.objects) == 0 {
		return ErrGuardRead
	}
	return r.checkObserved(ctx, manifest, func(_, observed []byte, links []GuardInterface) error {
		return verifyGuardConnectionObjectsReadback(snapshot.objects, observed, links, id)
	}, observe)
}

func (r *GuardReader) check(ctx context.Context, manifest GuardManifest, verify func([]byte, []byte, []GuardInterface) error) error {
	return r.checkObserved(ctx, manifest, verify, nil)
}
func (r *GuardReader) checkObserved(ctx context.Context, manifest GuardManifest, verify func([]byte, []byte, []GuardInterface) error, observe func(guardReadTiming)) (resultErr error) {
	var timing guardReadTiming
	var cancel context.CancelFunc
	defer func() {
		if cancel != nil {
			cancel()
		}
	}()
	defer func() {
		if observe == nil {
			return
		}
		switch {
		case ctx.Err() == context.DeadlineExceeded:
			timing.FailureClass = "context_deadline"
		case ctx.Err() != nil:
			timing.FailureClass = "context_canceled"
		case resultErr == errGuardConnectionNotPermitted:
			timing.FailureClass = "target_not_permitted"
		case resultErr != nil:
			timing.FailureClass = "structural_or_read"
		default:
			timing.FailureClass = "none"
		}
		observe(timing)
	}()
	if r == nil || r.run == nil || r.namespace == nil || r.interfaces == nil || ctx.Err() != nil || !validKernelNamespace(manifest.Namespace) {
		return ErrGuardRead
	}
	ctx, cancel = context.WithTimeout(ctx, kernelReadTimeout)
	before, err := r.namespace()
	if err != nil || before != manifest.Namespace || ctx.Err() != nil {
		return ErrGuardRead
	}
	links, err := r.interfaces()
	if err != nil || len(links) > kernelEntryLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	var commandStarted time.Time
	if observe != nil {
		commandStarted = time.Now()
	}
	observed, err := r.run(ctx, "-j", "list", "table", "inet", "tunnex_ipsec")
	if observe != nil {
		timing.CommandMillis = time.Since(commandStarted).Milliseconds()
	}
	if err != nil || len(observed) > kernelOutputLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	afterLinks, err := r.interfaces()
	if err != nil || len(afterLinks) > kernelEntryLimit || ctx.Err() != nil {
		return ErrGuardRead
	}
	after, err := r.namespace()
	if err != nil || after != before || ctx.Err() != nil {
		return ErrGuardRead
	}
	sort.Slice(links, func(i, j int) bool { return links[i].Index < links[j].Index })
	sort.Slice(afterLinks, func(i, j int) bool { return afterLinks[i].Index < afterLinks[j].Index })
	if !reflect.DeepEqual(links, afterLinks) || ctx.Err() != nil {
		return ErrGuardRead
	}
	var verificationStarted time.Time
	if observe != nil {
		verificationStarted = time.Now()
	}
	verificationErr := verify([]byte(manifest.ExpectedJSON), observed, links)
	if observe != nil {
		timing.VerificationMillis = time.Since(verificationStarted).Milliseconds()
	}
	if err := verificationErr; err != nil {
		if err == errGuardConnectionNotPermitted {
			return err
		}
		return ErrGuardRead
	}
	if ctx.Err() != nil {
		return ErrGuardRead
	}
	return nil
}

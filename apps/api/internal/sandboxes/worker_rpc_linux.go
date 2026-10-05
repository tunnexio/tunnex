//go:build linux

package sandboxes

import (
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func verifyWorkerSocket(path string, uid uint32) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0007 != 0 {
		return ErrDisabled
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uid {
		return ErrForbidden
	}
	return nil
}
func workerPeerUID(conn net.Conn) (uint32, error) {
	socket, ok := conn.(*net.UnixConn)
	if !ok {
		return 0, ErrForbidden
	}
	raw, err := socket.SyscallConn()
	if err != nil {
		return 0, ErrForbidden
	}
	var cred *unix.Ucred
	var controlErr error
	err = raw.Control(func(fd uintptr) { cred, controlErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) })
	if err != nil || controlErr != nil || cred == nil {
		return 0, ErrForbidden
	}
	// A peer outside this process PID namespace legitimately has PID zero.
	// Authentication binds its kernel UID, independently of PID visibility.
	return cred.Uid, nil
}
func verifyConnectedWorker(conn net.Conn, uid uint32) error {
	actual, err := workerPeerUID(conn)
	if err != nil || actual != uid {
		return ErrForbidden
	}
	return nil
}

// ServeWorkerRPC accepts only the configured API uid through Linux kernel peer
// credentials. It creates no sockets/ACLs itself; those are explicit deployment
// actions. No header, body or forwarded user identity can authorize this peer.
func ServeWorkerRPC(ctx context.Context, listener *net.UnixListener, apiUID uint32, handler *WorkerRPCServer) error {
	if listener == nil || handler == nil || apiUID == 0 || os.Geteuid() == 0 {
		return ErrInvalid
	}
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 4096, ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
		uid, err := workerPeerUID(conn)
		return context.WithValue(ctx, workerPeerContext{}, err == nil && uid == apiUID)
	}, BaseContext: func(net.Listener) context.Context { return ctx }}
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			_ = server.Close()
		case <-handler.RetiredSignal:
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			if server.Shutdown(shutdownCtx) != nil {
				_ = server.Close()
			}
		case <-done:
		}
	}()
	err := server.Serve(listener)
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, http.ErrServerClosed) {
		select {
		case <-handler.RetiredSignal:
			return nil
		default:
		}
	}
	return err
}

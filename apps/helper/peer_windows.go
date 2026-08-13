//go:build windows

package helper

import (
	"net"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

// peerAuthKind — Windows uses the real GetNamedPipeClientProcessId resolver.
const peerAuthKind = "native"

// NewPeerResolver (Windows) authenticates the caller via GetNamedPipeClientProcessId
// on the server pipe handle → the client pid → QueryFullProcessImageName. The SDDL on
// the pipe (listener_windows.go) governs who may CONNECT; this governs which PROCESS is
// trusted. If the handle can't be obtained it FAILS CLOSED (refuses).
//
// go-winio (v0.6.2) does NOT implement syscall.Conn and does not export the pipe
// handle, so we dig it out of the *win32Pipe via reflection (pipeServerHandle). If
// go-winio's internals ever change, that returns false → peer_no_handle → refused.
func NewPeerResolver() PeerResolver {
	return func(c net.Conn) (string, error) {
		h, ok := pipeServerHandle(c)
		if !ok {
			return "", &ProtocolError{Code: "peer_no_handle", Msg: "could not access the pipe handle"}
		}
		var pid uint32
		if err := windows.GetNamedPipeClientProcessId(h, &pid); err != nil {
			return "", &ProtocolError{Code: "peer_pid_unresolved", Msg: err.Error()}
		}
		// EDGE (refuse-path): if the client already died, OpenProcess (or the query
		// below) errors → we return an error → the Server refuses the caller. Never
		// trust an unresolvable peer.
		ph, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
		if err != nil {
			return "", &ProtocolError{Code: "peer_open_failed", Msg: err.Error()}
		}
		defer windows.CloseHandle(ph)
		buf := make([]uint16, windows.MAX_PATH)
		n := uint32(len(buf))
		if err := windows.QueryFullProcessImageName(ph, 0, &buf[0], &n); err != nil {
			return "", &ProtocolError{Code: "peer_path_unresolved", Msg: err.Error()}
		}
		return windows.UTF16ToString(buf[:n]), nil
	}
}

// pipeServerHandle extracts the OS pipe handle from a go-winio pipe connection, which
// hides it in the unexported win32File.handle field. Reflection + unsafe is the
// established way to reach it (go-winio exposes no accessor and no syscall.Conn). Fails
// closed (false) if the field can't be found — so a go-winio change degrades to "refuse
// the caller", never to "trust an unidentified caller".
func pipeServerHandle(c net.Conn) (windows.Handle, bool) {
	rv := reflect.ValueOf(c)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return 0, false
	}
	return searchHandle(rv.Elem(), 0)
}

// searchHandle walks an addressable struct (bounded depth) for the go-winio pipe's
// server handle: a `handle` field of uintptr kind INSIDE a struct named `win32File`.
// Requiring the enclosing type to be win32File avoids grabbing some other struct's
// unrelated `handle` field and resolving the WRONG process (review #6) — if go-winio's
// layout ever changes, this returns false → the caller FAILS CLOSED (refuses).
func searchHandle(v reflect.Value, depth int) (windows.Handle, bool) {
	if depth > 4 || !v.IsValid() || v.Kind() != reflect.Struct || !v.CanAddr() {
		return 0, false
	}
	t := v.Type()
	inWin32File := t.Name() == "win32File"
	for i := 0; i < v.NumField(); i++ {
		f := v.Field(i)
		if inWin32File && t.Field(i).Name == "handle" && f.Kind() == reflect.Uintptr {
			return windows.Handle(bypass(f).Uint()), true
		}
		switch f.Kind() {
		case reflect.Pointer:
			p := bypass(f)
			if !p.IsNil() {
				if h, ok := searchHandle(p.Elem(), depth+1); ok {
					return h, true
				}
			}
		case reflect.Struct:
			if h, ok := searchHandle(f, depth+1); ok {
				return h, true
			}
		}
	}
	return 0, false
}

// bypass returns a readable view of an addressable (possibly unexported) field.
func bypass(f reflect.Value) reflect.Value {
	return reflect.NewAt(f.Type(), unsafe.Pointer(f.UnsafeAddr())).Elem()
}

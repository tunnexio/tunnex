//go:build linux

package sandboxnetwork

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const ProtocolVersion = 1

type Request struct {
	Version    int         `json:"version"`
	Operation  string      `json:"operation"`
	Plan       Plan        `json:"plan"`
	PrivateKey string      `json:"private_key,omitempty"`
	Probe      *ProbeInput `json:"probe,omitempty"`
}
type Response struct {
	Version int                 `json:"version"`
	Receipt *Receipt            `json:"receipt,omitempty"`
	Removed bool                `json:"removed,omitempty"`
	Error   string              `json:"error,omitempty"`
	Probe   *SSHObservation     `json:"probe,omitempty"`
	Gateway *GatewayObservation `json:"gateway,omitempty"`
}

// ServeUnix is a serial bounded socket boundary. Only the configured OS worker
// can send a request; namespace descriptors are passed with SCM_RIGHTS. A
// browser/workload cannot supply a path/PID, shell command or ownership Boolean.
func ServeUnix(ctx context.Context, path string, admission Admission, controller Controller, gateway ...GatewayInspector) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || admission.WorkerUID == 0 {
		return ErrInvalid
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode().Perm()&0022 != 0 {
		return ErrOwnership
	}
	stat, ok := parent.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return ErrOwnership
	}
	if info, err := os.Lstat(path); err == nil {
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode()&os.ModeSocket == 0 {
			return ErrOwnership
		}
		connection, err := net.DialTimeout("unixpacket", path, time.Second)
		if err == nil {
			connection.Close()
			return ErrOwnership
		}
		if !errors.Is(err, unix.ECONNREFUSED) {
			return ErrUnavailable
		}
		if os.Remove(path) != nil {
			return ErrUnavailable
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return ErrUnavailable
	}
	listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
	if err != nil {
		return ErrUnavailable
	}
	defer listener.Close()
	if os.Chmod(path, 0660) != nil {
		return ErrUnavailable
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return ErrUnavailable
		}
		serveConnection(ctx, connection, admission, controller, gateway...)
		connection.Close()
	}
}
func serveConnection(ctx context.Context, connection *net.UnixConn, admission Admission, controller Controller, gateway ...GatewayInspector) {
	_ = connection.SetDeadline(time.Now().Add(30 * time.Second))
	response := Response{Version: ProtocolVersion, Error: "unavailable"}
	defer func() { raw, _ := json.Marshal(response); _, _ = connection.Write(raw) }()
	uid, err := peerUID(connection)
	if err != nil || uid != admission.WorkerUID {
		response.Error = "unauthorized"
		return
	}
	request, descriptor, err := readRequest(connection)
	if descriptor != nil {
		defer descriptor.Close()
	}
	if err != nil {
		response.Error = "invalid"
		return
	}
	var identity NamespaceIdentity
	inactive := request.Operation == "remove-inactive" || request.Operation == "gateway-absence-inactive"
	if !inactive {
		identity, err = AdmitNamespace(descriptor, admission)
		if err != nil {
			response.Error = "ownership"
			return
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 25*time.Second)
	defer cancel()
	switch request.Operation {
	case "remove-inactive", "gateway-absence-inactive":
		if len(gateway) != 1 || gateway[0] == nil {
			err = ErrUnavailable
			break
		}
		// Both paths independently require the selected immutable gateway's
		// actual fresh peer absence. Provider inactivity alone grants nothing.
		observation, e := gateway[0].PeerAbsence(ctx, request.Plan)
		err = e
		if err == nil && (observation.GatewayID != request.Plan.Binding.GatewayID || observation.PublicKey != request.Plan.PublicKey || !observation.Absent || observation.ObservedAt.Before(time.Now().Add(-10*time.Second)) || observation.ObservedAt.After(time.Now().Add(time.Second))) {
			err = ErrOwnership
		}
		if err == nil {
			if request.Operation == "remove-inactive" {
				err = controller.RemoveInactive(ctx, request.Plan, admission.WorkerUID)
				response.Removed = err == nil
			} else {
				err = controller.InspectInactiveRemoved(ctx, request.Plan, admission.WorkerUID)
				if err == nil {
					response.Gateway = &observation
				}
			}
		}
	case "apply":
		receipt, e := controller.Apply(ctx, descriptor, identity, request.Plan, request.PrivateKey)
		err = e
		if err == nil {
			response.Receipt = &receipt
		}
	case "inspect":
		receipt, e := controller.Inspect(ctx, descriptor, identity, request.Plan)
		err = e
		if err == nil {
			response.Receipt = &receipt
		}
	case "probe":
		if len(gateway) != 1 || gateway[0] == nil || request.Probe == nil {
			err = ErrUnavailable
			break
		}
		receipt, e := controller.Inspect(ctx, descriptor, identity, request.Plan)
		err = e
		if err == nil {
			observation, e := gateway[0].Probe(ctx, request.Plan, *request.Probe)
			err = e
			if err == nil {
				response.Receipt = &receipt
				response.Probe = &observation
			}
		}
	case "gateway-absence":
		if len(gateway) != 1 || gateway[0] == nil {
			err = ErrUnavailable
			break
		}
		err = controller.InspectRemoved(ctx, descriptor, identity, request.Plan)
		if err == nil {
			observation, e := gateway[0].PeerAbsence(ctx, request.Plan)
			err = e
			if err == nil {
				response.Gateway = &observation
			}
		}
	case "remove":
		err = controller.Remove(ctx, descriptor, identity, request.Plan)
		response.Removed = err == nil
	default:
		err = ErrInvalid
	}
	if err == nil {
		response.Error = ""
	} else if errors.Is(err, ErrOwnership) {
		response.Error = "ownership"
	} else if errors.Is(err, ErrMissing) {
		response.Error = "missing"
	} else if errors.Is(err, ErrInvalid) {
		response.Error = "invalid"
	}
	if err != nil {
		stage := "controller"
		var staged *ControllerStageError
		if errors.As(err, &staged) {
			stage = staged.Stage
		}
		fmt.Fprintf(os.Stderr, "sandbox network pending operation=%s stage=%s code=%s\n", request.Operation, stage, response.Error)
	}
}
func peerUID(connection *net.UnixConn) (uint32, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return 0, err
	}
	var uid uint32
	var queryErr error
	if err = raw.Control(func(fd uintptr) {
		credentials, e := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		queryErr = e
		if e == nil {
			uid = credentials.Uid
		}
	}); err != nil {
		return 0, err
	}
	return uid, queryErr
}
func readRequest(connection *net.UnixConn) (Request, *os.File, error) {
	var request Request
	body := make([]byte, 65536)
	control := make([]byte, unix.CmsgSpace(4*8))
	n, oob, flags, _, err := connection.ReadMsgUnix(body, control)
	if err != nil {
		return request, nil, ErrInvalid
	}
	messages, err := unix.ParseSocketControlMessage(control[:oob])
	if err != nil {
		return request, nil, ErrInvalid
	}
	fds := []int{}
	for _, message := range messages {
		rights, e := unix.ParseUnixRights(&message)
		if e != nil {
			err = ErrInvalid
			continue
		}
		fds = append(fds, rights...)
	}
	if err != nil || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || len(fds) > 1 {
		for _, fd := range fds {
			unix.Close(fd)
		}
		return request, nil, ErrInvalid
	}
	var descriptor *os.File
	if len(fds) == 1 {
		unix.CloseOnExec(fds[0])
		descriptor = os.NewFile(uintptr(fds[0]), "sandbox-network-namespace")
	}
	decoder := json.NewDecoder(bytes.NewReader(body[:n]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&request) != nil || decoder.Decode(new(any)) != io.EOF || request.Version != ProtocolVersion || (request.Operation != "apply" && request.Operation != "inspect" && request.Operation != "remove" && request.Operation != "probe" && request.Operation != "gateway-absence" && request.Operation != "remove-inactive" && request.Operation != "gateway-absence-inactive") || (request.Operation != "apply" && request.PrivateKey != "") || (request.Operation == "probe") != (request.Probe != nil) {
		return request, descriptor, ErrInvalid
	}
	inactive := request.Operation == "remove-inactive" || request.Operation == "gateway-absence-inactive"
	if inactive && descriptor != nil || !inactive && descriptor == nil {
		return request, descriptor, ErrInvalid
	}
	if _, err = Normalize(request.Plan); err != nil {
		return request, descriptor, ErrInvalid
	}
	return request, descriptor, nil
}

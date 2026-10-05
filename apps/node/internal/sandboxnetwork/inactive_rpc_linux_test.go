//go:build linux

package sandboxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

type inactiveGatewayFixture struct {
	observation GatewayObservation
	err         error
	calls       int
}

func (g *inactiveGatewayFixture) Probe(context.Context, Plan, ProbeInput) (SSHObservation, error) {
	return SSHObservation{}, ErrUnavailable
}
func (g *inactiveGatewayFixture) PeerAbsence(context.Context, Plan) (GatewayObservation, error) {
	g.calls++
	return g.observation, g.err
}

// Pure local Unix fixture: no Podman, Docker, namespace entry, credentials or
// live gateway. Run as an unprivileged user so the authenticated worker UID is
// the same non-root boundary used by the production socket server.
func TestInactiveCleanupActualUnixBoundary(t *testing.T) {
	uid := uint32(os.Geteuid())
	if uid == 0 {
		// test-node executes this fixture as nobody before the privileged suite
		// needed by nft validation. Root cannot exercise the worker UID boundary.
		t.Skip("requires an unprivileged user; test-node runs this fixture separately before its root suite")
	}
	for _, scenario := range []string{"created", "stopped", "created-absence", "stopped-absence", "gateway-present", "foreign-gateway", "stale-observation", "wrong-worker", "descriptor-on-inactive", "missing-descriptor-on-apply"} {
		t.Run(scenario, func(t *testing.T) {
			p, _ := fixturePlan(t)
			root, err := os.OpenRoot(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()
			store := FilesystemManifests{root}
			if scenario == "stopped" || scenario == "stopped-absence" {
				if err = store.Reserve(Manifest{p, NamespaceIdentity{1, 2, uid}}); err != nil {
					t.Fatal(err)
				}
			}
			driver := newDriver(p)
			gateway := &inactiveGatewayFixture{observation: GatewayObservation{p.Binding.GatewayID, p.PublicKey, true, time.Now().UTC()}}
			operation := "remove-inactive"
			admission := Admission{WorkerUID: uid, SubUIDStart: 100000, SubUIDCount: 65536}
			var rights []byte
			switch scenario {
			case "created-absence", "stopped-absence":
				operation = "gateway-absence-inactive"
			case "gateway-present":
				gateway.err = ErrUnavailable
			case "foreign-gateway":
				gateway.observation.PublicKey = p.GatewayPublicKey
			case "stale-observation":
				gateway.observation.ObservedAt = time.Now().Add(-time.Minute)
			case "wrong-worker":
				admission.WorkerUID++
			case "descriptor-on-inactive":
				fd, err := os.Open("/dev/null")
				if err != nil {
					t.Fatal(err)
				}
				defer fd.Close()
				rights = unix.UnixRights(int(fd.Fd()))
			case "missing-descriptor-on-apply":
				operation = "apply"
			}
			path := filepath.Join(t.TempDir(), "helper.sock")
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			done := make(chan struct{})
			go func() {
				defer close(done)
				connection, e := listener.AcceptUnix()
				if e != nil {
					return
				}
				defer connection.Close()
				serveConnection(context.Background(), connection, admission, Controller{store, driver}, gateway)
			}()
			connection, err := net.DialUnix("unixpacket", nil, &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if err = connection.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			// UID admission rejects before reading a request. Read that explicit
			// rejection first: queued client data can turn the close into a reset
			// and discard the response on a real Unix packet socket.
			if scenario != "wrong-worker" {
				raw, _ := json.Marshal(Request{Version: 1, Operation: operation, Plan: p})
				if _, _, err = connection.WriteMsgUnix(raw, rights, nil); err != nil {
					t.Fatal(err)
				}
			}
			buffer := make([]byte, 65536)
			n, err := connection.Read(buffer)
			if err != nil {
				t.Fatal(err)
			}
			var response Response
			if err = json.Unmarshal(buffer[:n], &response); err != nil {
				t.Fatal(err)
			}
			<-done
			valid := scenario == "created" || scenario == "stopped" || scenario == "created-absence" || scenario == "stopped-absence"
			if valid {
				if response.Error != "" || gateway.calls != 1 {
					t.Fatal("inactive removal lacked gateway proof", response, gateway.calls)
				}
				if operation == "remove-inactive" && (!response.Removed || response.Gateway != nil) {
					t.Fatal("invalid removal response", response)
				}
				if operation == "gateway-absence-inactive" && (response.Removed || response.Gateway == nil || !response.Gateway.Absent || response.Gateway.GatewayID != p.Binding.GatewayID || response.Gateway.PublicKey != p.PublicKey) {
					t.Fatal("missing exact gateway absence", response)
				}
				if err = store.Reserve(Manifest{p, NamespaceIdentity{1, 2, uid}}); !errors.Is(err, ErrOwnership) {
					t.Fatal("inactive epoch could be activated", err)
				}
			} else {
				if response.Error == "" || response.Removed {
					t.Fatal("invalid proof admitted", scenario, response)
				}
				if scenario == "wrong-worker" && (response.Error != "unauthorized" || gateway.calls != 0) {
					t.Fatal("UID denial did not remain unauthorized before gateway access", response, gateway.calls)
				}
				if _, err = root.Lstat(p.Binding.OperationID.String() + ".inactive.json"); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("denied cleanup left successful tombstone", err)
				}
			}
			if driver.creates != 0 || driver.moves != 0 || driver.commands != 0 {
				t.Fatal("inactive operation entered or changed namespace")
			}
		})
	}
}

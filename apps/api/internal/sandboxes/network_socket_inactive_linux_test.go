//go:build linux

package sandboxes

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxruntime"
	"github.com/tunnexio/tunnex/apps/api/internal/wgkey"
	"golang.org/x/sys/unix"
)

// The only provider is this structured fake. Its post-reply inspection waits
// until the local helper has written a successful response, then reports the
// same owned resource active. No executable, PID or namespace is accessed.
type inactiveSocketProviderFixture struct {
	target                   PrivateNetworkTarget
	initialState             string
	becomesActive            bool
	helperRead, replyWritten <-chan struct{}
	mu                       sync.Mutex
	postReplyInspections     int
}

func (f *inactiveSocketProviderFixture) Run(ctx context.Context, args ...string) ([]byte, error) {
	if len(args) == 3 && args[0] == "container" && args[1] == "exists" {
		return nil, nil
	}
	if len(args) != 4 || args[0] != "inspect" || args[1] != "--type=container" || args[2] != "--format=json" {
		return nil, fmt.Errorf("fixture rejected non-inspection provider command")
	}
	active := false
	select {
	case <-f.helperRead:
		select {
		case <-f.replyWritten:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		f.mu.Lock()
		f.postReplyInspections++
		f.mu.Unlock()
		active = f.becomesActive
	default:
	}
	state, pid, namespace := f.initialState, 0, ""
	if active {
		state, pid, namespace = "running", 321, "/fixture/retained-network-namespace"
	}
	return json.Marshal([]any{map[string]any{
		"Id":              f.target.RuntimeID,
		"Image":           "sha256:" + strings.Repeat("c", 64),
		"Config":          map[string]any{"Labels": map[string]string{"io.tunnex.sandbox": f.target.SandboxID.String(), "io.tunnex.sandbox.spec": f.target.SpecHash}},
		"State":           map[string]any{"Running": active, "Pid": pid, "Status": state},
		"NetworkSettings": map[string]any{"SandboxKey": namespace},
	}})
}

// Run only as root to preserve SocketNetwork's real SO_PEERCRED root-helper
// check. This fixture binds a temporary Unix packet socket and uses generated
// inert configuration plus a fake provider; it never enters a real namespace,
// launches a container or reads credentials or live gateway state.
func TestSocketNetworkInactiveCleanupRechecksProviderAfterHelperReply(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("pure Linux socket fixture requires root for the existing helper-peer UID pin")
	}
	for _, operation := range []string{"remove", "gateway-absence"} {
		for _, state := range []string{"created", "exited"} {
			for _, active := range []bool{false, true} {
				name := fmt.Sprintf("%s/%s/active-after-reply=%t", operation, state, active)
				t.Run(name, func(t *testing.T) {
					private, public, err := wgkey.Generate()
					if err != nil {
						t.Fatal(err)
					}
					_, gatewayPublic, err := wgkey.Generate()
					if err != nil {
						t.Fatal(err)
					}
					target := PrivateNetworkTarget{OperationID: uuid.New(), OrgID: uuid.New(), SandboxID: uuid.New(), GatewayID: uuid.New(), PeerID: uuid.New(), Generation: 1, RuntimeID: strings.Repeat("a", 64), SpecHash: strings.Repeat("b", 64), PublicKey: public, Address: netip.MustParseAddr("10.99.0.12")}
					config := []byte("[Interface]\nPrivateKey = " + private + "\nAddress = 10.99.0.12/32\nMTU = 1280\n[Peer]\nPublicKey = " + gatewayPublic + "\nEndpoint = 172.31.1.2:51820\nAllowedIPs = 10.99.0.0/24\nPersistentKeepalive = 25\n")
					wantPlan, _, err := privateNetworkPlan(target, config)
					if err != nil {
						t.Fatal(err)
					}
					directory, err := os.MkdirTemp("", "tnx-inactive-socket-")
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { os.RemoveAll(directory) })
					path := filepath.Join(directory, "helper.sock")
					listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
					if err != nil {
						t.Fatal(err)
					}
					defer listener.Close()
					helperRead, replyWritten := make(chan struct{}), make(chan struct{})
					provider := &inactiveSocketProviderFixture{target: target, initialState: state, becomesActive: active, helperRead: helperRead, replyWritten: replyWritten}
					helperDone := make(chan error, 1)
					go func() {
						connection, e := listener.AcceptUnix()
						if e != nil {
							helperDone <- e
							return
						}
						defer connection.Close()
						_ = connection.SetDeadline(time.Now().Add(3 * time.Second))
						body, control := make([]byte, 65536), make([]byte, unix.CmsgSpace(4*8))
						n, oob, flags, _, e := connection.ReadMsgUnix(body, control)
						if e != nil {
							helperDone <- e
							return
						}
						if oob != 0 || flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 {
							helperDone <- errors.New("inactive request carried namespace rights or truncated bytes")
							return
						}
						var request struct {
							Version    int             `json:"version"`
							Operation  string          `json:"operation"`
							Plan       networkWirePlan `json:"plan"`
							PrivateKey string          `json:"private_key"`
							Probe      *wireProbeInput `json:"probe"`
						}
						if e = json.Unmarshal(body[:n], &request); e != nil {
							helperDone <- e
							return
						}
						if request.Version != 1 || request.Operation != operation+"-inactive" || networkPlanHash(request.Plan) != networkPlanHash(wantPlan) || request.PrivateKey != "" || request.Probe != nil {
							helperDone <- errors.New("helper received a different plan or non-cleanup authority")
							return
						}
						close(helperRead)
						response := wireResponse{Version: 1, Removed: operation == "remove"}
						if operation == "gateway-absence" {
							response.Gateway = &wireGatewayObservation{GatewayID: target.GatewayID.String(), PublicKey: target.PublicKey, Absent: true, ObservedAt: time.Now().UTC()}
						}
						raw, _ := json.Marshal(response)
						_, e = connection.Write(raw)
						close(replyWritten)
						helperDone <- e
					}()
					ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
					defer cancel()
					network := &SocketNetwork{Provider: sandboxruntime.NewPodman(provider), Socket: path}
					if operation == "remove" {
						err = network.RemovePrivateNetwork(ctx, target, config)
					} else {
						err = network.InspectGatewayAbsence(ctx, target, config)
					}
					if e := <-helperDone; e != nil {
						t.Fatal("local helper fixture failed", e)
					}
					provider.mu.Lock()
					checks := provider.postReplyInspections
					provider.mu.Unlock()
					if checks == 0 {
						t.Fatal("helper success accepted without a post-reply provider check")
					}
					if active {
						if !errors.Is(err, sandboxruntime.ErrOwnership) {
							t.Fatal("active provider accepted successful inactive cleanup receipt", err)
						}
					} else if err != nil {
						t.Fatal("exact inactive cleanup failed", err)
					}
				})
			}
		}
	}
}

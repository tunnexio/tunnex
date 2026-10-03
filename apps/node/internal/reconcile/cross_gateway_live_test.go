//go:build linux

package reconcile

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/tunnexio/tunnex/apps/node/internal/egress"
	"github.com/tunnexio/tunnex/apps/node/internal/ovpnserver"
)

// Explicitly opted-in adapter for the disposable qualification containers.
// It applies real production WireGuard/routes/nftables and retains the policy
// manager across updates so live conntrack withdrawal is actually exercised.
func TestCrossGatewayLiveAdapter(t *testing.T) {
	if os.Getenv("TUNNEX_GATEWAY_LIVE_FIXTURE") != "owned-container" {
		t.Skip("requires disposable gateway fixture")
	}
	key, err := os.ReadFile("/run/lab/private")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := os.ReadFile("/run/lab/public")
	if err != nil {
		t.Fatal(err)
	}
	backend, err := SelectBackend("wgctrl", "wg0", slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	r := New(backend, strings.TrimSpace(string(key)), strings.TrimSpace(string(pub)), slog.Default())
	m := egress.New("wg0")
	r.OnPolicy(m.SetPolicy)
	vpn := ovpnserver.New("/run/lab/ovpn")
	vpn.SetProcessController(ovpnserver.NewSupervisor())
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		var ds DesiredState
		if err := json.Unmarshal(scanner.Bytes(), &ds); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		_, err := r.ApplyDesiredState(ctx, ds)
		if err == nil {
			if ds.OVPNEnabled {
				files := []string{"ca.crt", "server.crt", "server.key", "crl.pem"}
				material := make([]string, 4)
				for i, name := range files {
					var data []byte
					data, err = os.ReadFile("/run/lab/" + name)
					if err != nil {
						break
					}
					material[i] = string(data)
				}
				if err == nil {
					err = vpn.WriteServerMaterial(material[0], material[1], material[2], material[3])
				}
				clients := []ovpnserver.Client{}
				for _, c := range ds.OVPNClients {
					clients = append(clients, ovpnserver.Client{CommonName: c.CommonName, IP: c.IP})
				}
				vpn.SetDesired(ovpnserver.Desired{PoolCIDR: "10.99.0.0/24", Clients: clients, Routes: OVPNPushRoutes(ds.Policy)})
			} else {
				vpn.SetDesired(ovpnserver.Desired{})
			}
			if err == nil {
				err = vpn.Reconcile(ctx)
			}
			if err == nil {
				tun := ""
				if ds.OVPNEnabled {
					tun = ovpnserver.TunName
				}
				err = m.ReconcileOVPNTunnel(ctx, tun)
			}
		}
		if err == nil {
			_, _, err = m.Reconcile(ctx)
		}
		cancel()
		if err != nil {
			t.Fatal(err)
		}
		if err := json.NewEncoder(os.Stdout).Encode(map[string]any{"applied": true, "version": ds.Version}); err != nil {
			t.Fatal(err)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal(err)
	}
}

package bgp

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDesktopExportIsAnExactBoundedHost(t *testing.T) {
	c := fixture()
	c.DesktopPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")}
	got, err := RenderConfig(c)
	if err != nil || !strings.Contains(got, "network 10.99.0.7/32") || !strings.Contains(got, "permit 10.99.0.7/32") || strings.Contains(got, "network 10.99.0.0/24") {
		t.Fatal("exact desktop export missing", err)
	}
	for _, p := range []string{"10.99.0.0/24", "10.20.0.8/32", "10.10.0.8/32", "169.254.1.1/32"} {
		c.DesktopPrefixes = []netip.Prefix{netip.MustParsePrefix(p)}
		if _, err = RenderConfig(c); err == nil {
			t.Fatal("invalid desktop export", p)
		}
	}
}

// Opt in inside a network-disabled container with the bundled daemon path.
// FRR runs without kernel writes, Zebra, or BGP/VTY TCP listeners; its Unix
// observer proves parsed configuration and actual local host origination.
func TestDesktopExportNativeConfig(t *testing.T) {
	daemon := os.Getenv("TUNNEX_TEST_BGPD")
	if daemon == "" {
		t.Skip("set TUNNEX_TEST_BGPD in an isolated native test container")
	}
	c := fixture()
	c.DesktopPrefixes = []netip.Prefix{netip.MustParsePrefix("10.99.0.7/32")}
	config, err := RenderConfig(c)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "bgpd.conf")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "bgpd.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(daemon, "--skip_runas", "--no_kernel", "--no_zebra", "--bgp_port", "0", "--vty_port", "0", "--vty_socket", dir, "--pid_file", filepath.Join(dir, "bgpd.pid"), "--config_file", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	socket := filepath.Join(dir, "bgpd.vty")
	ready := false
	for i := 0; i < 100; i++ {
		if stat, err := os.Stat(socket); err == nil && stat.Mode()&os.ModeSocket != 0 {
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		content, _ := os.ReadFile(log.Name())
		t.Fatalf("FRR observer unavailable: %s", content)
	}
	query := func(command string) string {
		t.Helper()
		output, err := exec.Command(filepath.Join(filepath.Dir(daemon), "vtysh"), "--vty_socket", dir, "-d", "bgpd", "-c", command).CombinedOutput()
		if err != nil {
			t.Fatalf("native observer: %v: %s", err, output)
		}
		return string(output)
	}
	running := query("show running-config")
	if !strings.Contains(running, "no bgp network import-check") || !strings.Contains(running, "network 10.99.0.7/32") || strings.Contains(running, "network 10.99.0.0/24") {
		t.Fatalf("native configuration changed: %s", running)
	}
	rib := query("show bgp ipv4 unicast json")
	if !strings.Contains(rib, `"10.99.0.7/32"`) || strings.Contains(rib, `"10.99.0.0/24"`) {
		t.Fatalf("exact desktop host not originated: %s", rib)
	}
	content, _ := os.ReadFile(log.Name())
	if strings.Contains(strings.ToLower(string(content)), "unknown command") {
		t.Fatalf("native parser rejected config: %s", content)
	}
}

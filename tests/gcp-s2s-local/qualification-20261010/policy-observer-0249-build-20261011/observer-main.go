package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"github.com/tunnexio/tunnex/apps/node/internal/ipsec"
	"io"
	"os"
	"os/exec"
	"time"
)

const source = "9c3ab006c13b72285f43baed1805da1af273ffa7"
const namespace = "net:[4026531840]"
const ipPath = "/usr/sbin/ip"

type projection struct {
	IfID      uint32     `json:"if_id"`
	Templates []template `json:"tmpl"`
}
type template struct {
	ReqID uint32 `json:"reqid"`
}

func parse(raw []byte) ([]projection, error) {
	inv, e := ipsec.ParseXFRMInventory(namespace, nil, raw)
	if e != nil {
		return nil, e
	}
	out := make([]projection, 0, len(inv.Policies))
	for _, p := range inv.Policies {
		out = append(out, projection{p.IfID, []template{{p.ReqID}}})
	}
	return out, nil
}

type bounded struct{ data []byte }

func (b *bounded) Write(p []byte) (int, error) {
	if len(b.data)+len(p) > 2*1024*1024 {
		return 0, fmt.Errorf("bounded policy refused")
	}
	b.data = append(b.data, p...)
	return len(p), nil
}
func ipIdentity(expected string) ([32]byte, error) {
	var zero [32]byte
	b, e := hex.DecodeString(expected)
	if e != nil || len(b) != 32 || hex.EncodeToString(b) != expected {
		return zero, fmt.Errorf("ip identity refused")
	}
	f, e := os.Open(ipPath)
	if e != nil {
		return zero, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil || !s.Mode().IsRegular() || s.Mode().Perm()&0022 != 0 {
		return zero, fmt.Errorf("ip identity refused")
	}
	raw, e := io.ReadAll(io.LimitReader(f, 16*1024*1024+1))
	if e != nil || len(raw) > 16*1024*1024 {
		return zero, fmt.Errorf("ip bound refused")
	}
	h := sha256.Sum256(raw)
	if hex.EncodeToString(h[:]) != expected {
		return zero, fmt.Errorf("ip identity refused")
	}
	return h, nil
}
func observe(expected string) ([]projection, error) {
	before, e := os.Readlink("/proc/self/ns/net")
	if e != nil || before != namespace {
		return nil, fmt.Errorf("namespace refused")
	}
	h, e := ipIdentity(expected)
	if e != nil {
		return nil, e
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bounded
	cmd := exec.CommandContext(ctx, ipPath, "xfrm", "policy", "list", "nosock")
	cmd.Stdout = &out
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return nil, fmt.Errorf("native policy command refused")
	}
	p, e := parse(out.data)
	if e != nil {
		return nil, e
	}
	after, e := os.Readlink("/proc/self/ns/net")
	h2, e2 := ipIdentity(expected)
	if e != nil || e2 != nil || after != before || h2 != h {
		return nil, fmt.Errorf("native bracket refused")
	}
	return p, nil
}
func main() {
	sha := flag.String("ip-sha256", "", "ROOT measured native ip digest")
	flag.Parse()
	if flag.NArg() != 0 {
		os.Exit(1)
	}
	p, e := observe(*sha)
	if e != nil {
		fmt.Println(`{"completed":false,"refusal_code":"native_policy_refused"}`)
		os.Exit(1)
	}
	json.NewEncoder(os.Stdout).Encode(struct {
		Completed bool         `json:"completed"`
		Source    string       `json:"source_commit"`
		Namespace string       `json:"namespace"`
		Policies  []projection `json:"policies"`
	}{true, source, namespace, p})
}

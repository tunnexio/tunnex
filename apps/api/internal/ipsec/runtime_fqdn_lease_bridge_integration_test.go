package ipsec_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	osexec "os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresolver"
	"github.com/tunnexio/tunnex/apps/api/internal/fqdnresources"
	"github.com/tunnexio/tunnex/apps/api/internal/ipsec"
	"github.com/tunnexio/tunnex/apps/api/internal/policy"
	"github.com/tunnexio/tunnex/apps/api/internal/testpostgres"
)

// Opt-in local API-store/serialization/actual Maintain bridge. Native objects
// and node PSKs remain explicit test fixtures; not production HTTP/auth or cloud.
func TestTransactionalIPsecFQDNV2MaintainFreshNonceBridge(t *testing.T) {
	binaryPath := os.Getenv("TUNNEX_TEST_IPSEC_FQDN_NODE_BINARY")
	expectedSHA := os.Getenv("TUNNEX_TEST_IPSEC_FQDN_NODE_BINARY_SHA256")
	if binaryPath == "" && expectedSHA == "" {
		t.Skip("explicit reviewed Darwin ARM64 node test binary required")
	}
	verifyFQDNBridgeBinary(t, binaryPath, expectedSHA)
	childOutput := openFQDNBridgeOutput(t, os.Getenv("TUNNEX_TEST_IPSEC_FQDN_BRIDGE_CHILD_OUTPUT_PATH"))
	defer childOutput.Close()

	resolverSource := selectFQDNBridgeSource(t)
	ctx, p := testpostgres.New(t)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, e := p.Exec(ctx, q, args...); e != nil {
			t.Fatal(e)
		}
	}
	// PostgreSQL supplies the same wall-clock authority as the real compiler.
	databaseNow := func() time.Time {
		t.Helper()
		var stamp time.Time
		if e := p.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&stamp); e != nil {
			t.Fatal(e)
		}
		return stamp.UTC()
	}
	publish := func(work *fqdnresolver.Work, generation fqdnresolver.Generation) error {
		// Observe this exact fixture resource's real publication CAS. Concurrent
		// changes still refuse; the test never retries or changes saved rows.
		if e := p.QueryRow(ctx, `SELECT COALESCE(max(generation),0) FROM fqdn_resource_answer_generations WHERE org_id=$1 AND resource_id=$2`, work.OrgID, work.ResourceID).Scan(&work.ExpectedGeneration); e != nil {
			return e
		}
		return fqdnresolver.NewPostgresStore(p).Publish(ctx, *work, generation)
	}
	org, actor, site, node := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	exec(`INSERT INTO organizations(id,name,slug,pool_cidr,zero_trust_mode,fqdn_resources_enabled) VALUES($1,'transaction compiler',$2,'10.199.0.0/24','enforcing',true)`, org, "fqdn-tx-"+org.String())
	exec(`INSERT INTO users(id,email) VALUES($1,$2)`, actor, actor.String()+"@fixture.test")
	exec(`INSERT INTO sites(id,org_id,name) VALUES($1,$2,'compiler site')`, site, org)
	exec(`INSERT INTO site_subnets(id,site_id,cidr,status) VALUES($1,$2,'10.10.0.0/16','approved')`, uuid.New(), site)
	exec(`INSERT INTO nodes(id,org_id,name,cert_serial,site_id,capabilities,policy_reported_at) VALUES($1,$2,'compiler node',$3,$4,'{"ipsec_config_version":1,"ipsec_recovery_version":1,"ipsec_fqdn_policy_version":2,"dns_resolve_rpc_version":2,"dns_ipsec_resolve_version":1}',clock_timestamp())`, node, org, node.String(), site)
	if _, e := ipsec.NewSettingsStore(p).Configure(ctx, org, actor, true, 0); e != nil {
		t.Fatal(e)
	}
	sealer, e := crypto.NewSealer(bytes.Repeat([]byte{0x49}, 32))
	if e != nil {
		t.Fatal(e)
	}
	store := ipsec.NewConnectionStore(p)
	store.ConfigureRuntimePolicy(policy.IPsecRuntimePolicyCompiler(func() bool { return true }))
	req := ipsec.CreateProviderRequest{ID: uuid.New(), SiteID: site, GatewayID: node, Name: "compiler", TunnelIDs: [2]uuid.UUID{uuid.New(), uuid.New()}, Config: staticConfigFixture()}
	if !netip.MustParsePrefix("10.10.0.0/16").Contains(resolverSource) {
		sourcePrefix := netip.PrefixFrom(resolverSource, 32).String()
		exec(`INSERT INTO site_subnets(id,site_id,cidr,status)VALUES($1,$2,$3::cidr,'approved')`, uuid.New(), site, sourcePrefix)
		req.Config.LocalPrefixes = append(req.Config.LocalPrefixes, sourcePrefix)
	}
	c, e := store.CreateProviderDisabled(ctx, org, actor, sealer, req)
	if e != nil {
		t.Fatal(e)
	}
	c, e = store.SetIntent(ctx, org, actor, c.ID, c.DesiredRevision, "enabled")
	if e != nil {
		t.Fatal(e)
	}
	profiles := fqdnresources.New(p)
	profile := fqdnresources.ResolverProfile{Name: "compiler DNS", ProviderHint: "aws", ZoneSuffixes: []string{"private.example.test"}, Endpoints: []fqdnresources.ResolverEndpoint{{Address: "10.20.0.53", Port: 53, Transport: "udp"}}, IPsecPath: &fqdnresources.ResolverIPsecPath{ConnectionID: c.ID, ConfigurationRevision: 1, SourceAddress: resolverSource.String()}}
	config, e := profiles.SetResolverProfiles(ctx, org, site, node, actor, "test", "transaction proof", []fqdnresources.ResolverProfile{profile})
	if e != nil {
		t.Fatal(e)
	}

	ordinary, ordinaryRule := uuid.New(), uuid.New()
	exec(`INSERT INTO resources(id,org_id,name,cidr,protocol,port_low,port_high)VALUES($1,$2,'ordinary','10.20.1.8/32','tcp',9090,9090)`, ordinary, org)
	exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_resource_id)VALUES($1,$2,'cidr','10.10.0.2/32','resource',$3)`, ordinaryRule, org, ordinary)
	resources := [2]uuid.UUID{uuid.New(), uuid.New()}
	rules := [2]uuid.UUID{uuid.New(), uuid.New()}
	cutoffs := [2]time.Time{databaseNow().Add(15 * time.Second), databaseNow().Add(60 * time.Second)}
	works := [2]fqdnresolver.Work{}
	for i := range resources {
		name := []string{"short.private.example.test", "long.private.example.test"}[i]
		exec(`INSERT INTO fqdn_resources(id,org_id,name,fqdn,protocol,port_low,port_high,resolver_site_id,resolver_node_id)VALUES($1,$2,$3,$3,'tcp',8080,8080,$4,$5)`, resources[i], org, name, site, node)
		exec(`INSERT INTO policy_rules(id,org_id,src_kind,src_cidr,dst_kind,dst_fqdn_resource_id,expires_at)VALUES($1,$2,'cidr','10.10.0.2/32','fqdn_resource',$3,$4)`, rules[i], org, resources[i], cutoffs[i])
		works[i] = fqdnresolver.Work{OrgID: org, ResourceID: resources[i], Hostname: name, Context: fqdnresolver.Context{ResolverID: site.String(), GatewayID: node.String()}, ResolverConfig: fqdnresolver.ResolverConfig{ID: config.ID.String(), Version: config.Version, ProfileID: config.Profiles[0].ID.String(), ProfileName: "compiler DNS", ProfileProvider: "aws", MatchedSuffix: "private.example.test", IPsecPath: &fqdnresolver.ResolverIPsecPath{ConnectionID: c.ID.String(), ConfigurationRevision: 1, SourceAddress: resolverSource.String()}, Endpoints: []fqdnresolver.ResolverEndpoint{{Address: netip.MustParseAddr("10.20.0.53"), Port: 53, Transport: "udp"}}}}
		if e := publish(&works[i], fqdnresolver.Generation{TTL: time.Minute, ResolvedAt: databaseNow(), Addresses: []netip.Addr{netip.MustParseAddr([]string{"10.20.1.4", "10.20.1.5"}[i])}}); e != nil {
			t.Fatal(e)
		}
	}
	principal := ipsec.RuntimePrincipal{OrgID: org, NodeID: node, CertificateSerial: node.String()}
	material := func() ipsec.RuntimeMaterial {
		t.Helper()
		m, e := store.Material(ctx, principal, c.ID, c.DesiredRevision, sealer)
		if e != nil {
			t.Fatal(e)
		}
		return m
	}
	original := material()
	if original.Policy.FQDNPolicyVersion != 2 || len(original.Policy.FQDNGrants) != 2 || len(original.Policy.Grants) != 1 || len(original.Policy.DNSResolverGrants) != 1 || len(original.Policy.DNSResolverProfiles) != 1 {
		t.Fatal("genuine initial ordinary/DNS/two-grant policy missing")
	}

	parent := t.TempDir()
	parent, e = filepath.EvalSymlinks(parent)
	if e != nil {
		t.Fatal("canonical metadata parent")
	}
	if e := os.Chmod(parent, 0700); e != nil {
		t.Fatal(e)
	}
	metadata := filepath.Join(parent, "metadata.json")
	raw, e := json.Marshal(map[string]any{"delivery": original.RuntimeDelivery, "policy": original.Policy})
	if e != nil || len(raw) > 262144 {
		t.Fatal("bridge metadata bounds")
	}
	file, e := os.OpenFile(metadata, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = file.Write(raw); e != nil {
		file.Close()
		t.Fatal(e)
	}
	if e = file.Sync(); e != nil {
		file.Close()
		t.Fatal(e)
	}
	if e = file.Close(); e != nil {
		t.Fatal(e)
	}
	type observed struct {
		nonce   string
		before  bool
		lease   ipsec.RuntimeLease
		success bool
	}
	var mu sync.Mutex
	observations := []observed{}
	refusals := 0
	endpoint := "/permit/" + uuid.NewString()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != endpoint || r.URL.RawQuery != "" {
			http.Error(w, "refused", http.StatusNotFound)
			return
		}
		defer r.Body.Close()
		r.Body = http.MaxBytesReader(w, r.Body, 65536)
		var request ipsec.RuntimeLeaseRequest
		decoder := json.NewDecoder(r.Body)
		decoder.DisallowUnknownFields()
		if decoder.Decode(&request) != nil {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			http.Error(w, "refused", http.StatusBadRequest)
			return
		}
		// The fixed principal/connection comes from the genuine owned child DB,
		// never client-supplied org/node/credentials or a fabricated policy result.
		var stamp time.Time
		if e := p.QueryRow(r.Context(), `SELECT clock_timestamp()`).Scan(&stamp); e != nil {
			mu.Lock()
			refusals++
			mu.Unlock()
			http.Error(w, "refused", http.StatusServiceUnavailable)
			return
		}
		lease, err := store.PermitLease(r.Context(), principal, c.ID, request)
		mu.Lock()
		observations = append(observations, observed{nonce: request.Nonce, before: stamp.Before(cutoffs[0]), lease: lease, success: err == nil})
		if err != nil {
			refusals++
		}
		mu.Unlock()
		if err != nil {
			http.Error(w, "refused", http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if json.NewEncoder(w).Encode(lease) != nil {
			return
		}
	})
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	server := httptest.NewUnstartedServer(handler)
	server.Listener = listener
	server.Start()
	defer server.Close()
	verifyFQDNBridgeBinary(t, binaryPath, expectedSHA)
	childCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	command := osexec.CommandContext(childCtx, binaryPath, "-test.run", "^TestRuntimeFQDNV2MaintainRealPermitLeaseBridge$", "-test.v", "-test.timeout", "28s")
	// Minimal fixed environment, no inherited DSN, tokens, accounts or cloud auth.
	command.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "HOME=" + parent, "TMPDIR=" + parent, "TUNNEX_TEST_IPSEC_FQDN_LEASE_BRIDGE_URL=" + server.URL + endpoint, "TUNNEX_TEST_IPSEC_FQDN_LEASE_BRIDGE_METADATA=" + metadata}
	var output, childError fqdnBridgeBoundedOutput
	command.Stdout = &output
	command.Stderr = &childError
	err := command.Run()
	exitCode := -1
	if command.ProcessState != nil {
		exitCode = command.ProcessState.ExitCode()
	}
	stdout, stderr := output.buffer.Bytes(), childError.buffer.Bytes()
	outHash, errHash := sha256.Sum256(stdout), sha256.Sum256(stderr)
	evidence, e := json.Marshal(map[string]any{"version": 1, "kind": "actual_fqdn_bridge_child_output", "node_binary_sha256": expectedSHA, "exit_code": exitCode, "timed_out": childCtx.Err() == context.DeadlineExceeded, "stdout_base64": base64.StdEncoding.EncodeToString(stdout), "stderr_base64": base64.StdEncoding.EncodeToString(stderr), "stdout_sha256": hex.EncodeToString(outHash[:]), "stderr_sha256": hex.EncodeToString(errHash[:]), "stdout_truncated": output.overflow, "stderr_truncated": childError.overflow})
	if e != nil {
		t.Fatal("child evidence marshal")
	}
	if _, e = childOutput.Write(evidence); e != nil {
		t.Fatal("child evidence write")
	}
	if e = childOutput.Sync(); e != nil {
		t.Fatal("child evidence file durability")
	}
	syncFQDNBridgeDirectory(t, filepath.Dir(childOutput.Name()))
	verifyFQDNBridgeBinary(t, binaryPath, expectedSHA)
	if err != nil || output.overflow || childError.overflow || strings.Contains(output.buffer.String(), "SKIP") || strings.Count(output.buffer.String(), "--- PASS: TestRuntimeFQDNV2MaintainRealPermitLeaseBridge ") != 1 || !strings.HasSuffix(strings.TrimSpace(output.buffer.String()), "PASS") {
		t.Fatal("pinned node Maintain bridge did not produce exact bounded non-SKIP PASS")
	}
	mu.Lock()
	defer mu.Unlock()
	if refusals != 0 || len(observations) < 2 {
		t.Fatal("genuine bridge requests missing or refused")
	}
	seen := map[string]bool{}
	before, after := false, false
	for _, entry := range observations {
		if len(entry.nonce) != 64 || seen[entry.nonce] {
			t.Fatal("bridge did not use distinct actual request nonces")
		}
		seen[entry.nonce] = true
		if !entry.success || entry.lease.TTLMS != 60000 || entry.lease.Nonce != entry.nonce || len(entry.lease.FQDNGrants) != 0 || len(entry.lease.FQDNPermits) != 2 {
			t.Fatal("real store lease identity/ordinary authority mismatch")
		}
		zeros, positive := 0, 0
		for _, permit := range entry.lease.FQDNPermits {
			if permit.TTLMS == 0 {
				zeros++
			} else if permit.TTLMS > 0 {
				positive++
			} else {
				t.Fatal("negative permit")
			}
		}
		if entry.before {
			if zeros != 0 || positive != 2 {
				t.Fatal("preexpiry genuine permits changed")
			}
			before = true
		} else {
			if zeros != 1 || positive != 1 {
				t.Fatal("postexpiry selective genuine lease missing")
			}
			after = true
		}
	}
	if !before || !after {
		t.Fatal("actual preexpiry and postexpiry database lease observations required")
	}
}

type fqdnBridgeBoundedOutput struct {
	mu       sync.Mutex
	buffer   bytes.Buffer
	overflow bool
}

func (b *fqdnBridgeBoundedOutput) Write(raw []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	available := 262144 - b.buffer.Len()
	if len(raw) > available {
		b.overflow = true
		if available > 0 {
			b.buffer.Write(raw[:available])
		}
		return len(raw), nil
	}
	return b.buffer.Write(raw)
}

func verifyFQDNBridgeBinary(t *testing.T, path, digest string) {
	t.Helper()
	if len(digest) != 64 {
		t.Fatal("reviewed binary SHA required")
	}
	if _, e := hex.DecodeString(digest); e != nil {
		t.Fatal("binary SHA format")
	}
	absolute, e := filepath.Abs(path)
	resolved, e2 := filepath.EvalSymlinks(path)
	if e != nil || e2 != nil || absolute != path || resolved != path {
		t.Fatal("absolute binary no-symlink path")
	}
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		t.Fatal("binary open")
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, e := file.Stat()
	if e != nil {
		t.Fatal("binary stat")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) || owner.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm() != 0700 || info.Size() < 32 || info.Size() > 134217728 {
		t.Fatal("private owned executable binary")
	}
	parent := filepath.Dir(path)
	pinfo, e := os.Stat(parent)
	presolved, e2 := filepath.EvalSymlinks(parent)
	if e != nil || e2 != nil || presolved != parent || !pinfo.IsDir() || pinfo.Mode().Perm() != 0700 {
		t.Fatal("private binary parent")
	}
	powner, ok := pinfo.Sys().(*syscall.Stat_t)
	if !ok || powner.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned binary parent")
	}
	hash := sha256.New()
	header := make([]byte, 8)
	if _, e := io.ReadFull(file, header); e != nil {
		t.Fatal("binary header")
	}
	if binary.LittleEndian.Uint32(header[:4]) != 0xfeedfacf || binary.LittleEndian.Uint32(header[4:]) != 0x0100000c {
		t.Fatal("Darwin ARM64 Mach-O required")
	}
	hash.Write(header)
	if _, e := io.Copy(hash, file); e != nil {
		t.Fatal("binary hash")
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		t.Fatal("binary SHA mismatch")
	}
}

// Reserve the independently reviewed output before DB/setup/child execution.
// Both streams remain private; test errors never print captured bytes.
func openFQDNBridgeOutput(t *testing.T, path string) *os.File {
	t.Helper()
	absolute, e := filepath.Abs(path)
	if path == "" || e != nil || absolute != path {
		t.Fatal("explicit absolute private child output path required")
	}
	parent := filepath.Dir(path)
	resolved, e := filepath.EvalSymlinks(parent)
	info, e2 := os.Stat(parent)
	if e != nil || e2 != nil || resolved != parent || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatal("child output private non-symlink parent")
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != uint32(os.Geteuid()) {
		t.Fatal("owned child output parent")
	}
	fd, e := syscall.Open(path, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, 0600)
	if e != nil {
		t.Fatal("exclusive child output refused")
	}
	file := os.NewFile(uintptr(fd), path)
	if e = file.Sync(); e != nil {
		file.Close()
		t.Fatal("child output reservation durability")
	}
	syncFQDNBridgeDirectory(t, parent)
	return file
}
func syncFQDNBridgeDirectory(t *testing.T, path string) {
	t.Helper()
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if e != nil {
		t.Fatal("child output directory open")
	}
	directory := os.NewFile(uintptr(fd), path)
	defer directory.Close()
	if e = directory.Sync(); e != nil {
		t.Fatal("child output directory durability")
	}
}

// Read-only host observation, never assign an address or bypass the production
// source observer. Candidates must be unique across all UP interfaces and fit
// the owned fixture's disjoint private-source domain.
func selectFQDNBridgeSource(t *testing.T) netip.Addr {
	t.Helper()
	interfaces, e := net.Interfaces()
	if e != nil {
		t.Fatal("bridge active-interface inventory unavailable")
	}
	sort.Slice(interfaces, func(i, j int) bool { return interfaces[i].Index < interfaces[j].Index })
	type observedSource struct {
		address netip.Addr
		index   int
	}
	observed := []observedSource{}
	counts := map[netip.Addr]int{}
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 {
			continue
		}
		addresses, e := iface.Addrs()
		if e != nil {
			t.Fatal("bridge interface address inventory unavailable")
		}
		for _, value := range addresses {
			prefix, e := netip.ParsePrefix(value.String())
			if e != nil {
				t.Fatal("bridge interface address shape unavailable")
			}
			addr := prefix.Addr().Unmap()
			if !addr.Is4() {
				continue
			}
			counts[addr]++
			if iface.Index <= 0 || iface.Flags&net.FlagLoopback != 0 || !addr.IsPrivate() || !addr.IsGlobalUnicast() || addr.IsLoopback() || netip.MustParsePrefix("10.20.0.0/16").Contains(addr) || netip.MustParsePrefix("10.199.0.0/24").Contains(addr) {
				continue
			}
			observed = append(observed, observedSource{addr, iface.Index})
		}
	}
	sort.SliceStable(observed, func(i, j int) bool {
		if observed[i].index != observed[j].index {
			return observed[i].index < observed[j].index
		}
		return observed[i].address.Less(observed[j].address)
	})
	for _, value := range observed {
		if counts[value.address] == 1 {
			return value.address
		}
	}
	t.Fatal("unique active private host IPv4 required for genuine DNS source observation")
	return netip.Addr{}
}

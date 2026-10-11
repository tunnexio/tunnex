package ipsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/nodepolicy"
)

const fqdnBridgeSyntheticPSK = "Synthetic_fixture_only_PSK_123"

// Only the separate API test starts this loopback producer against a genuine
// disposable DB. Native, namespace, journal and PSKs here are synthetic fixtures.
// Every lease request/nonce and response crosses actual JSON/store.PermitLease;
// no saved response, nonce rewrite or fabricated API grant authority is accepted.
type fqdnBridgeLeaseClient struct {
	url    string
	client *http.Client
	calls  int
}

func (b *fqdnBridgeLeaseClient) RenewIPsecLease(ctx context.Context, id uuid.UUID, q RuntimeLeaseRequest) (RuntimeLease, error) {
	raw, e := json.Marshal(q)
	if e != nil {
		return RuntimeLease{}, e
	}
	call, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, e := http.NewRequestWithContext(call, http.MethodPost, b.url, bytes.NewReader(raw))
	if e != nil {
		return RuntimeLease{}, e
	}
	req.Header.Set("Content-Type", "application/json")
	response, e := b.client.Do(req)
	if e != nil {
		return RuntimeLease{}, e
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return RuntimeLease{}, fmt.Errorf("fixture lease HTTP status %d", response.StatusCode)
	}
	raw, e = io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if e != nil {
		return RuntimeLease{}, e
	}
	var lease RuntimeLease
	if e = json.Unmarshal(raw, &lease); e != nil || len(lease.FQDNGrants) != 0 {
		return RuntimeLease{}, ErrPermitLease
	}
	if lease.DeliveryID != q.DeliveryID || lease.DesiredRevision != q.DesiredRevision || lease.PolicyHash != q.PolicyHash || lease.Nonce != q.Nonce {
		return RuntimeLease{}, ErrPermitLease
	}
	b.calls++
	return lease, nil
}
func TestRuntimeFQDNV2MaintainRealPermitLeaseBridge(t *testing.T) {
	endpoint, path := os.Getenv("TUNNEX_TEST_IPSEC_FQDN_LEASE_BRIDGE_URL"), os.Getenv("TUNNEX_TEST_IPSEC_FQDN_LEASE_BRIDGE_METADATA")
	if endpoint == "" && path == "" {
		t.Skip("requires explicit genuine disposable-DB API producer; no API/native acceptance claim")
	}
	parsed, e := url.Parse(endpoint)
	if e != nil || parsed.Scheme != "http" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		t.Fatal("invalid loopback fixture URL")
	}
	addr, e := netip.ParseAddr(parsed.Hostname())
	if e != nil || !addr.IsLoopback() {
		t.Fatal("nonloopback producer")
	}
	st, e := os.Lstat(path)
	if e != nil || !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1<<20 {
		t.Fatal("invalid private metadata")
	}
	info, ok := st.Sys().(*syscall.Stat_t)
	if !ok || info.Uid != uint32(os.Geteuid()) || info.Nlink != 1 {
		t.Fatal("metadata ownership")
	}
	raw, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	var data struct {
		Delivery RuntimeDelivery `json:"delivery"`
		Policy   RuntimePolicy   `json:"policy"`
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&data) != nil || decoder.Decode(new(any)) != io.EOF {
		t.Fatal("metadata schema")
	}
	m := RuntimeMaterial{RuntimeDelivery: data.Delivery, Policy: data.Policy}
	for i, tunnel := range m.Manifest.Tunnels {
		m.Secrets[i] = RuntimeSecret{TunnelID: tunnel.ID, Revision: tunnel.SecretRevision, PSK: fqdnBridgeSyntheticPSK}
	}
	const ns = "net:[4026531992]"
	entry, grants, e := runtimeMaterialEntry(m, m.Manifest.OrgID, m.Manifest.NodeID, ns)
	if e != nil || entry.ContractVersion != 2 || !validJournalRecovery(entry) || selectedRuntimeSlot(entry) != 1 || m.Policy.FQDNPolicyVersion != 2 || len(m.Policy.FQDNGrants) != 2 || len(m.Policy.Grants) == 0 || len(m.Policy.DNSResolverGrants) == 0 {
		t.Fatal("genuine fixture contract", e)
	}
	short, long := m.Policy.FQDNGrants[0], m.Policy.FQDNGrants[1]
	if long.ExpiresAt.Before(short.ExpiresAt) {
		short, long = long, short
	}
	wait := time.Until(short.ExpiresAt) + 20*time.Millisecond
	if wait <= 0 || wait > 20*time.Second || !long.ExpiresAt.After(short.ExpiresAt.Add(10*time.Second)) {
		t.Fatal("unusable genuine fixture cutoffs")
	}
	// Dedicated DNS admission observes the real host assignment even though
	// transport/kernel readbacks below remain explicitly synthetic. The API
	// fixture approves this same existing private source /32 without mutations.
	interfaces, e := net.Interfaces()
	if e != nil {
		t.Fatal("host interface inventory refused")
	}
	var allowed []int
	for _, link := range interfaces {
		if link.Flags&net.FlagUp != 0 && link.Flags&net.FlagLoopback == 0 {
			allowed = append(allowed, link.Index)
		}
	}
	var ingress []int
	for _, grant := range m.Policy.DNSResolverGrants {
		source, err := netip.ParseAddr(grant.SourceAddress)
		if err != nil || !source.Is4() || !source.IsPrivate() {
			t.Fatal("genuine DNS source is not a private host IPv4")
		}
		index, err := observeDNSSource(source, allowed)
		if err != nil {
			t.Fatal("genuine DNS source is not assigned on an approved host interface")
		}
		found := false
		for _, prior := range ingress {
			found = found || prior == index
		}
		if !found {
			ingress = append(ingress, index)
		}
	}
	env := RuntimeEnvironment{Namespace: ns, LocalIngressIndices: ingress}
	outside, e := netip.ParseAddr(m.Manifest.CustomerOutsideAddress)
	if e != nil {
		t.Fatal(e)
	}
	links := []GuardInterface{}
	for i, tunnel := range entry.Allocation.Tunnels {
		entry.Observed[i] = Ownership{Namespace: ns, InterfaceName: tunnel.Name, InterfaceIndex: 10 + i, XFRMID: tunnel.XFRMID}
		env.Underlays[i] = RuntimeUnderlay{InterfaceIndex: 2, OuterMTU: 1500, LocalAddress: outside}
		entry.Engines[i].LocalAddress = outside
		links = append(links, GuardInterface{Name: tunnel.Name, Index: 10 + i})
	}
	j, e := OpenRuntimeJournal(journalDir(t), m.Manifest.NodeID)
	if e != nil {
		t.Fatal(e)
	}
	defer j.Close()
	for _, phase := range []RuntimePhase{RuntimeReserved, RuntimeApplying, RuntimeApplied} {
		entry.Phase = phase
		if e = j.Save([]RuntimeJournalEntry{entry}); e != nil {
			t.Fatal(e)
		}
	}
	started := time.Now()
	elapsed := func() time.Duration { return time.Since(started) }
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &fqdnBridgeLeaseClient{url: endpoint, client: &http.Client{Transport: transport}}
	identity := PermitLeaseIdentity{DeliveryID: m.ID, Binding: entry.Engines[0].Binding, PolicyHash: m.Policy.Hash}
	authority := &PermitLeaseAuthority{elapsed: elapsed}
	q, e := authority.BeginFQDN(identity, runtimeFQDNLeaseKeys(m.Policy))
	if e != nil {
		t.Fatal(e)
	}
	lease, e := client.RenewIPsecLease(context.Background(), entry.Allocation.ConnectionID, RuntimeLeaseRequest{DeliveryID: m.ID, DesiredRevision: m.DesiredRevision, PolicyHash: m.Policy.Hash, Nonce: q.Nonce, FQDNGrants: runtimeFQDNLeaseDescriptors(m.Policy)})
	if e != nil || authority.Accept(PermitLeaseResponse{PermitLeaseRequest: q, TTLMillis: lease.TTLMS, FQDNPermits: lease.FQDNPermits}) != nil {
		t.Fatal("initial genuine fresh lease", e)
	}
	c := &RuntimeController{started: true, journal: j, client: client, qualification: testRuntimeQualification(ns), config: RuntimeControllerConfig{OrgID: m.Manifest.OrgID, GatewayID: m.Manifest.NodeID, DaemonAlive: func() bool { return true }}, namespace: func() (string, error) { return ns, nil }, prove: func(context.Context, RuntimeJournalEntry, RuntimeEnvironment) error { return nil }, recoveryObserve: func(context.Context, RuntimeJournalEntry) [2]string { return [2]string{"up", "up"} }, recoveryPrepared: map[uuid.UUID]RuntimeEnvironment{m.ID: env}}
	// Reuse the synthetic native fixture from the actual finite-guard rig. Its
	// identities and selected routes come from the genuine API manifest; only
	// native readbacks are synthetic, never the lease or committed provenance.
	kernel := newRecoveryKernelFixture()
	kernel.p, kernel.owned = entry.Allocation, entry.Observed
	kernel.routes = [2]map[string]bool{{}, {}}
	for _, prefix := range entry.Engines[0].RemotePrefixes {
		kernel.routes[0][prefix.String()] = true
	}
	c.kernel = kernel.applier()
	c.config.Diagnostic = func(d RuntimeDiagnostic) {
		if d.Refused {
			t.Logf("refused stage=%s", d.Stage)
		}
	}
	c.qualification.fqdnExpiry = true
	c.config.Environment = renewalCycleEnvironment{entry.Allocation.ConnectionID: env}
	policy := &nodepolicy.Compiled{Version: 9, NodeID: m.Manifest.NodeID.String(), Mode: nodepolicy.ModeEnforcing, DNSResolverProfiles: m.Policy.DNSResolverProfiles}
	for _, g := range m.Policy.FQDNGrants {
		policy.Allow = append(policy.Allow, nodepolicy.AllowEntry{SrcIP: g.Source, DstCIDR: g.Destination, Protocol: g.Protocol, PortLow: int(g.PortLow), PortHigh: int(g.PortHigh), RuleID: g.RuleID, FQDNManaged: true})
		policy.FQDNGenerations = append(policy.FQDNGenerations, nodepolicy.FQDNGeneration{ResourceID: g.ResourceID, Name: g.Name, Generation: g.Generation, ResolverConfigID: g.ResolverConfigID, ResolverConfigVersion: g.ResolverConfigVersion, Answers: []string{g.Destination}})
	}
	source := &RuntimeFQDNPolicySource{}
	source.CommittedPolicy(policy)
	source.Attach(c)
	c.config.FQDNPolicy = source
	for _, grant := range grants {
		if grant.FQDN.Version == 2 && !source.view.Load().matches(grant) {
			t.Fatal("genuine committed provenance does not match synthetic node view")
		}
	}
	c.active = map[uuid.UUID]runtimeActive{entry.Allocation.ConnectionID: {Entry: entry, Delivery: m.RuntimeDelivery, Environment: env, Grants: grants, Identity: identity, Authority: authority}}
	expected := []byte(nil)
	installed := map[string]time.Duration{}
	c.replace = func(_ context.Context, intent GuardIntent) (GuardManifest, error) {
		manifest, e := RenderGuard(intent)
		if e != nil {
			return manifest, e
		}
		if e = j.prepareGuard(manifest); e != nil {
			return manifest, e
		}
		if e = j.finishGuard(manifest); e != nil {
			return manifest, e
		}
		expected = []byte(manifest.ExpectedJSON)
		installed = map[string]time.Duration{}
		var native map[string]any
		_ = json.Unmarshal(expected, &native)
		for _, row := range native["nftables"].([]any) {
			if set, ok := row.(map[string]any)["set"].(map[string]any); ok {
				if elements, ok := set["elem"].([]any); ok {
					for _, v := range elements {
						element := v.(map[string]any)["elem"].(map[string]any)
						installed[set["name"].(string)] = elapsed() + time.Duration(element["timeout"].(float64))*time.Second
					}
				}
			}
		}
		return manifest, nil
	}
	native := func() []byte {
		var value map[string]any
		_ = json.Unmarshal(expected, &value)
		for _, row := range value["nftables"].([]any) {
			if set, ok := row.(map[string]any)["set"].(map[string]any); ok {
				if elements, ok := set["elem"].([]any); ok {
					remaining := installed[set["name"].(string)] - elapsed()
					if remaining <= 0 {
						set["elem"] = []any{}
						continue
					}
					for _, v := range elements {
						v.(map[string]any)["elem"].(map[string]any)["expires"] = int64((remaining + time.Second - 1) / time.Second)
					}
				}
			}
		}
		out, _ := json.Marshal(value)
		return out
	}
	c.guard = &RuntimeGuard{journal: j, reader: &GuardReader{namespace: c.namespace, interfaces: func() ([]GuardInterface, error) { return links, nil }, run: func(context.Context, ...string) ([]byte, error) { return native(), nil }}}
	if e = c.installActive(context.Background(), []RuntimeJournalEntry{entry}); e != nil {
		t.Fatal("initial actual controller guard", e)
	}
	if !strings.Contains(string(expected), "fqdn_") {
		t.Fatal("initial finite membership missing")
	}
	time.Sleep(time.Until(short.ExpiresAt) + 20*time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	results, e := c.maintainIPsecRuntime(ctx, []RuntimeMaterial{m}, func() *PermitLeaseAuthority { return &PermitLeaseAuthority{elapsed: elapsed} }, func() bool { return true })
	if e != nil || len(results) != 1 || client.calls != 2 {
		t.Fatal("actual maintained fresh API exchange", e, len(results), client.calls)
	}
	current, ok := c.active[entry.Allocation.ConnectionID]
	if !ok || current.Authority == authority {
		t.Fatal("owner continuity lost")
	}
	if _, e = current.Authority.RemainingForApply(identity, time.Millisecond); e != nil {
		t.Fatal("ordinary/DNS authority lost")
	}
	if _, e = current.Authority.RemainingFQDNForApply(identity, runtimeFQDNGrantDigest(short), time.Millisecond); e == nil {
		t.Fatal("expired short proof accepted")
	}
	if _, e = current.Authority.RemainingFQDNForApply(identity, runtimeFQDNGrantDigest(long), time.Millisecond); e != nil {
		t.Fatal("current long proof lost")
	}

	shortSet, longSet := "", ""
	for _, grant := range grants {
		if grant.FQDN.Version == 2 {
			switch guardFQDNGrantDigest(grant) {
			case runtimeFQDNGrantDigest(short):
				shortSet = guardFQDNSetName(grant)
			case runtimeFQDNGrantDigest(long):
				longSet = guardFQDNSetName(grant)
			}
		}
	}
	if shortSet == "" || longSet == "" {
		t.Fatal("exact fixture set identity missing")
	}
	objects, valid := normalizedGuardObjects(native())
	if !valid {
		t.Fatal("final fixture guard malformed")
	}
	members := map[string]int{}
	for _, object := range objects {
		if set, ok := object.(map[string]any)["set"].(map[string]any); ok {
			name, _ := set["name"].(string)
			elements, _ := set["elem"].([]any)
			members[name] = len(elements)
		}
	}
	if _, present := members[shortSet]; present || members[longSet] != 1 {
		t.Fatal("exact expired/retained timed membership mismatch")
	}
	for _, name := range []string{guardLeaseName(entry.Allocation.ConnectionID), guardSALeaseName(entry.Allocation.ConnectionID), guardReplyLeaseName(entry.Allocation.ConnectionID)} {
		if members[name] == 0 {
			t.Fatal("ordinary/DNS owner membership absent")
		}
	}
	for _, oldGrant := range grants {
		if oldGrant.FQDNManaged {
			continue
		}
		found := false
		for _, nowGrant := range current.Grants {
			if oldGrant == nowGrant {
				found = true
				break
			}
		}
		if !found {
			t.Fatal("ordinary/DNS tuple lost")
		}
	}
	finalRaw, e := os.ReadFile(path)
	finalSt, se := os.Lstat(path)
	if e != nil || se != nil || !bytes.Equal(raw, finalRaw) || !os.SameFile(st, finalSt) || st.Mode() != finalSt.Mode() || st.Size() != finalSt.Size() || !st.ModTime().Equal(finalSt.ModTime()) {
		t.Fatal("metadata changed")
	}
	t.Log("genuine disposable-DB fresh-nonce JSON PermitLease -> actual Maintain: PASS; native/PSKs synthetic; not native or live acceptance")
}

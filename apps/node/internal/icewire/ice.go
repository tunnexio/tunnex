// Package icewire negotiates an encrypted-datagram carrier using upstream ICE.
// WireGuard, not ICE or TURN, owns application encryption and authorization.
package icewire

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/ice/v4"
	"github.com/pion/logging"
	"github.com/pion/stun/v4"
)

var ErrNegotiation = errors.New("connectivity negotiation failed")

type Relay struct{ URL, Username, Password string }
type Signal struct {
	Version    int      `json:"version"`
	PublicKey  string   `json:"public_key"`
	User       string   `json:"user"`
	Password   string   `json:"password"`
	Candidates []string `json:"candidates"`
}
type Endpoint struct{ agent *ice.Agent }

func validKey(key string) bool {
	b, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(b) == 32
}

func Gather(ctx context.Context, relay Relay, key string) (*Endpoint, Signal, error) {
	if !validKey(key) || relay.Username == "" || relay.Password == "" {
		return nil, Signal{}, ErrNegotiation
	}
	u, err := stun.ParseURI(relay.URL)
	if err != nil || u.Scheme != stun.SchemeTypeTURNS {
		return nil, Signal{}, ErrNegotiation
	}
	u.Username, u.Password = relay.Username, relay.Password
	logger := logging.NewDefaultLoggerFactory()
	logger.Writer = io.Discard
	agent, err := ice.NewAgent(&ice.AgentConfig{Urls: []*stun.URI{u}, CandidateTypes: []ice.CandidateType{ice.CandidateTypeHost, ice.CandidateTypeRelay}, NetworkTypes: []ice.NetworkType{ice.NetworkTypeUDP4}, LoggerFactory: logger})
	if err != nil {
		return nil, Signal{}, ErrNegotiation
	}
	endpoint := &Endpoint{agent: agent}
	ok := false
	defer func() {
		if !ok {
			endpoint.Close()
		}
	}()
	done := make(chan struct{})
	var once sync.Once
	if agent.OnCandidate(func(c ice.Candidate) {
		if c == nil {
			once.Do(func() { close(done) })
		}
	}) != nil || agent.GatherCandidates() != nil {
		return nil, Signal{}, ErrNegotiation
	}
	select {
	case <-ctx.Done():
		return nil, Signal{}, ErrNegotiation
	case <-done:
	}
	user, password, err := agent.GetLocalUserCredentials()
	if err != nil {
		return nil, Signal{}, ErrNegotiation
	}
	candidates, err := agent.GetLocalCandidates()
	if err != nil {
		return nil, Signal{}, ErrNegotiation
	}
	signal := Signal{Version: 1, PublicKey: key, User: user, Password: password}
	for _, c := range candidates {
		if safeCandidate(c) {
			signal.Candidates = append(signal.Candidates, c.Marshal())
		}
	}
	if len(signal.Candidates) == 0 || len(signal.Candidates) > 32 {
		return nil, Signal{}, ErrNegotiation
	}
	ok = true
	return endpoint, signal, nil
}

func safeCandidate(c ice.Candidate) bool {
	ip, err := netip.ParseAddr(c.Address())
	if err != nil {
		return false
	}
	return c.NetworkType() == ice.NetworkTypeUDP4 && ip.Is4() && ip.IsGlobalUnicast() && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() && c.Port() > 0 && c.Port() <= 65535
}

func Decode(raw, expectedKey string) (Signal, error) {
	var s Signal
	if len(raw) > 16384 || json.Unmarshal([]byte(raw), &s) != nil || s.Version != 1 || !validKey(expectedKey) || s.PublicKey != expectedKey || len(s.User) < 4 || len(s.User) > 256 || len(s.Password) < 16 || len(s.Password) > 256 || len(s.Candidates) == 0 || len(s.Candidates) > 32 {
		return Signal{}, ErrNegotiation
	}
	for _, raw := range s.Candidates {
		if len(raw) > 2048 {
			return Signal{}, ErrNegotiation
		}
		c, err := ice.UnmarshalCandidate(raw)
		if err != nil || !safeCandidate(c) {
			return Signal{}, ErrNegotiation
		}
	}
	return s, nil
}

func (e *Endpoint) Connect(ctx context.Context, remote Signal, initiator bool) (*ice.Conn, error) {
	// Validate again: a caller cannot bypass Decode with an unchecked struct.
	b, err := json.Marshal(remote)
	if err != nil {
		return nil, ErrNegotiation
	}
	if _, err := Decode(string(b), remote.PublicKey); err != nil {
		return nil, err
	}
	for _, raw := range remote.Candidates {
		c, _ := ice.UnmarshalCandidate(raw)
		if e.agent.AddRemoteCandidate(c) != nil {
			return nil, ErrNegotiation
		}
	}
	var conn *ice.Conn
	if initiator {
		conn, err = e.agent.Dial(ctx, remote.User, remote.Password)
	} else {
		conn, err = e.agent.Accept(ctx, remote.User, remote.Password)
	}
	if err != nil {
		return nil, ErrNegotiation
	}
	return conn, nil
}
func (e *Endpoint) Close() {
	if e != nil && e.agent != nil {
		_ = e.agent.Close()
	}
}

func (e *Endpoint) Path() string {
	pair, err := e.agent.GetSelectedCandidatePair()
	if err != nil || pair == nil {
		return "negotiating"
	}
	return candidatePath(pair.Local.Type(), pair.Remote.Type())
}

func candidatePath(local, remote ice.CandidateType) string {
	if local == ice.CandidateTypeRelay || remote == ice.CandidateTypeRelay {
		return "relay"
	}
	// A peer-reflexive candidate can conceal the remote relay. Match the
	// desktop's conservative classification instead of claiming a direct path.
	knownDirect := func(candidate ice.CandidateType) bool {
		return candidate == ice.CandidateTypeHost || candidate == ice.CandidateTypeServerReflexive
	}
	if !knownDirect(local) || !knownDirect(remote) {
		return "unknown"
	}
	return "direct"
}

// Deadline supplies one bounded negotiation budget across gather and connect.
func Deadline(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithTimeout(ctx, 30*time.Second)
}

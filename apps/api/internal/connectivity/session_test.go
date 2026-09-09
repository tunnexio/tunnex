package connectivity

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func fixture() (Session, Snapshot, Principal, time.Time) {
	now := time.Unix(1700000000, 0).UTC()
	b := Binding{uuid.New(), uuid.New(), uuid.New(), uuid.New(), uuid.New(), 1}
	s := Session{Binding: b, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	return s, Snapshot{b, true, true, true, true}, Principal{DeviceSide, b.OrgID, b.OwnerID}, now
}

func TestAuthorizeFailClosed(t *testing.T) {
	cases := map[string]func(*Session, *Snapshot, *Principal, *time.Time){
		"tenant":                func(s *Session, c *Snapshot, p *Principal, n *time.Time) { p.OrgID = uuid.New() },
		"owner":                 func(s *Session, c *Snapshot, p *Principal, n *time.Time) { p.SubjectID = uuid.New() },
		"gateway impersonation": func(s *Session, c *Snapshot, p *Principal, n *time.Time) { p.Side = GatewaySide },
		"invalid side":          func(s *Session, c *Snapshot, p *Principal, n *time.Time) { p.Side = 0 },
		"superseded":            func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.Current.Generation++ },
		"device moved":          func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.Current.DeviceID = uuid.New() },
		"owner changed":         func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.Current.OwnerID = uuid.New() },
		"gateway changed":       func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.Current.GatewayID = uuid.New() },
		"other session":         func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.Current.SessionID = uuid.New() },
		"disabled":              func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.OptedIn = false },
		"offboarded":            func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.OwnerActiveMember = false },
		"device blocked":        func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.DeviceEligible = false },
		"gateway revoked":       func(s *Session, c *Snapshot, p *Principal, n *time.Time) { c.GatewayEligible = false },
		"revoked":               func(s *Session, c *Snapshot, p *Principal, n *time.Time) { s.Revoked = true },
		"exact expiry":          func(s *Session, c *Snapshot, p *Principal, n *time.Time) { *n = s.ExpiresAt },
		"before creation":       func(s *Session, c *Snapshot, p *Principal, n *time.Time) { *n = s.CreatedAt.Add(-time.Nanosecond) },
		"zero clock":            func(s *Session, c *Snapshot, p *Principal, n *time.Time) { *n = time.Time{} },
		"zero creation":         func(s *Session, c *Snapshot, p *Principal, n *time.Time) { s.CreatedAt = time.Time{} },
		"zero expiry":           func(s *Session, c *Snapshot, p *Principal, n *time.Time) { s.ExpiresAt = time.Time{} },
		"zero binding": func(s *Session, c *Snapshot, p *Principal, n *time.Time) {
			s.Binding = Binding{}
			c.Current = s.Binding
		},
		"zero generation": func(s *Session, c *Snapshot, p *Principal, n *time.Time) {
			s.Binding.Generation = 0
			c.Current = s.Binding
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			s, c, p, n := fixture()
			mutate(&s, &c, &p, &n)
			if err := s.Authorize(p, c, n); err != ErrDenied {
				t.Fatalf("expected generic denial, got %v", err)
			}
			credential, credentialErr := s.IssueRelayCredentials(p, c, n, make([]byte, 32))
			if credentialErr != ErrDenied || credential != (RelayCredentials{}) {
				t.Fatal("denied binding issued a relay credential")
			}
			got, err := s.Accept(p, c, n, 1)
			if err != ErrDenied || got != s {
				t.Fatal("denied write changed state or succeeded")
			}
		})
	}
}

func TestIndependentSequencesAndReplay(t *testing.T) {
	s, c, p, n := fixture()
	for _, side := range []Side{DeviceSide, GatewaySide} {
		p.Side = side
		p.SubjectID = s.Binding.OwnerID
		if side == GatewaySide {
			p.SubjectID = s.Binding.GatewayID
		}
		var err error
		s, err = s.Accept(p, c, n, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, seq := range []uint64{0, 1, 3} {
			got, err := s.Accept(p, c, n, seq)
			if err != ErrDenied || got != s {
				t.Fatal("replay/gap mutated state")
			}
		}
		s, err = s.Accept(p, c, n, 2)
		if err != nil {
			t.Fatal(err)
		}
	}
	if s.DeviceSequence != 2 || s.GatewaySequence != 2 {
		t.Fatal("side counters coupled")
	}
	s.GatewaySequence = ^uint64(0)
	if _, err := s.Accept(p, c, n, 0); err != ErrDenied {
		t.Fatal("sequence wrapped")
	}
}

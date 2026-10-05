package sandboxnetwork

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"strconv"
	"time"
)

type Link struct {
	Index             int
	Name, Alias, Kind string
	MTU               int
	Up                bool
}
type Address struct {
	Interface string
	Prefix    netip.Prefix
}
type Route struct {
	Interface string
	Prefix    netip.Prefix
	Gateway   string
	Local     bool
}
type Peer struct {
	PublicKey        string
	Endpoint         netip.AddrPort
	Routes           []netip.Prefix
	KeepaliveSeconds int
}
type Snapshot struct {
	Links            []Link
	Addresses        []Address
	Routes           []Route
	DefaultRulesOnly bool
	PublicKey        string
	Peers            []Peer
}
type Receipt struct {
	Manifest   Manifest  `json:"manifest"`
	ObservedAt time.Time `json:"observed_at"`
	Interface  string    `json:"interface"`
	PlanHash   string    `json:"plan_hash"`
}

type ManifestStore interface{ Reserve(Manifest) error }
type Driver interface {
	Snapshot(context.Context, *os.File, Plan) (Snapshot, error)
	BirthLink(context.Context, Plan) (Link, error)
	CreateBirthLink(context.Context, Plan) error
	DeleteBirthLink(context.Context, Plan, Link) error
	MoveLink(context.Context, Link, *os.File) error
	Command(context.Context, *os.File, []byte, string, ...string) error
}

// Controller receives a namespace FD already admitted by the Linux boundary.
// The authenticated server serializes requests. No shell, path, PID or private
// key is returned in a receipt; a manifest never contains private key material.
type ControllerStageError struct {
	Stage string
	Cause error
}

func (e *ControllerStageError) Error() string { return "sandbox network pending: " + e.Stage }
func (e *ControllerStageError) Unwrap() error { return e.Cause }

type Controller struct {
	Store  ManifestStore
	Driver Driver
}

func (c Controller) Apply(ctx context.Context, ns *os.File, identity NamespaceIdentity, p Plan, privateKey string) (receipt Receipt, failure error) {
	stage := "normalize"
	defer func() {
		if failure != nil {
			failure = &ControllerStageError{stage, failure}
		}
	}()
	p, err := Normalize(p)
	if err != nil {
		return Receipt{}, err
	}
	config, err := WireGuardConfig(p, privateKey)
	if err != nil {
		return Receipt{}, err
	}
	if c.Store == nil || c.Driver == nil || ns == nil || identity.Inode == 0 {
		return Receipt{}, ErrUnavailable
	}
	stage = "reserve"
	manifest := Manifest{p, identity}
	if err = c.Store.Reserve(manifest); err != nil {
		return Receipt{}, err
	}
	stage = "initial-snapshot"
	snapshot, err := c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return Receipt{}, err
	}
	stage = "snapshot-admission"
	if err = checkSnapshot(p, snapshot, false); err != nil {
		return Receipt{}, err
	}
	stage = "birth-link"
	name := InterfaceName(p)
	if !hasInterface(snapshot, name) {
		link, err := c.Driver.BirthLink(ctx, p)
		if errors.Is(err, ErrMissing) {
			if err = c.Driver.CreateBirthLink(ctx, p); err != nil {
				return Receipt{}, err
			}
			link, err = c.Driver.BirthLink(ctx, p)
		}
		if err != nil {
			return Receipt{}, err
		}
		if !ownedLink(p, link) {
			return Receipt{}, ErrOwnership
		}
		if err = c.Driver.MoveLink(ctx, link, ns); err != nil {
			return Receipt{}, err
		}
	} else {
		// A second owned link in the birth namespace indicates an uncertain or
		// foreign duplicate. Never silently overwrite/delete either resource.
		if _, err = c.Driver.BirthLink(ctx, p); !errors.Is(err, ErrMissing) {
			return Receipt{}, ErrOwnership
		}
	}
	stage = "moved-snapshot"
	snapshot, err = c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return Receipt{}, err
	}
	stage = "snapshot-admission"
	if err = checkSnapshot(p, snapshot, false); err != nil {
		return Receipt{}, err
	}
	if !hasInterface(snapshot, name) {
		return Receipt{}, ErrMissing
	}
	stage = "configuration"
	if err = c.Driver.Command(ctx, ns, config, "wg", "setconf", name, "/dev/stdin"); err != nil {
		return Receipt{}, err
	}
	if !hasAddress(snapshot, name, p.Address) {
		if err = c.Driver.Command(ctx, ns, nil, "ip", "address", "add", p.Address.String(), "dev", name); err != nil {
			return Receipt{}, err
		}
	}
	stage = "link-up"
	if err = c.Driver.Command(ctx, ns, nil, "ip", "link", "set", "dev", "lo", "up"); err != nil {
		return Receipt{}, err
	}
	if err = c.Driver.Command(ctx, ns, nil, "ip", "link", "set", "dev", name, "mtu", strconv.Itoa(p.MTU), "up"); err != nil {
		return Receipt{}, err
	}
	stage = "routes"
	for _, route := range p.Routes {
		if !hasRoute(snapshot, name, route) {
			if err = c.Driver.Command(ctx, ns, nil, "ip", "route", "add", route.String(), "dev", name); err != nil {
				return Receipt{}, err
			}
		}
	}
	stage = "final-inspection"
	return c.Inspect(ctx, ns, identity, p)
}

func (c Controller) Inspect(ctx context.Context, ns *os.File, identity NamespaceIdentity, p Plan) (Receipt, error) {
	p, err := Normalize(p)
	if err != nil {
		return Receipt{}, err
	}
	if c.Store == nil || c.Driver == nil || ns == nil || identity.Inode == 0 {
		return Receipt{}, ErrUnavailable
	}
	manifest := Manifest{p, identity}
	if err = c.Store.Reserve(manifest); err != nil {
		return Receipt{}, err
	}
	snapshot, err := c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return Receipt{}, err
	}
	if err = checkSnapshot(p, snapshot, true); err != nil {
		return Receipt{}, err
	}
	hash, _ := Identity(p)
	return Receipt{manifest, time.Now().UTC(), InterfaceName(p), hash}, nil
}

func (c Controller) Remove(ctx context.Context, ns *os.File, identity NamespaceIdentity, p Plan) error {
	p, err := Normalize(p)
	if err != nil {
		return err
	}
	if c.Store == nil || c.Driver == nil || ns == nil || identity.Inode == 0 {
		return ErrUnavailable
	}
	if err = c.Store.Reserve(Manifest{p, identity}); err != nil {
		return err
	}
	snapshot, err := c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return err
	}
	if err = checkSnapshot(p, snapshot, false); err != nil {
		return err
	}
	link, birthErr := c.Driver.BirthLink(ctx, p)
	if birthErr == nil {
		if !ownedLink(p, link) || hasInterface(snapshot, InterfaceName(p)) {
			return ErrOwnership
		}
		if err = c.Driver.DeleteBirthLink(ctx, p, link); err != nil {
			return err
		}
	} else if !errors.Is(birthErr, ErrMissing) {
		return birthErr
	}
	if _, err = c.Driver.BirthLink(ctx, p); !errors.Is(err, ErrMissing) {
		return ErrOwnership
	}
	if hasInterface(snapshot, InterfaceName(p)) {
		if err = c.Driver.Command(ctx, ns, nil, "ip", "link", "delete", "dev", InterfaceName(p)); err != nil {
			return err
		}
	}
	snapshot, err = c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return err
	}
	if hasInterface(snapshot, InterfaceName(p)) {
		return ErrOwnership
	}
	return checkSnapshot(p, snapshot, false)
}

// InspectRemoved verifies the admitted namespace contains no surviving owned
// interface before an independent gateway absence observation can be requested.
func (c Controller) InspectRemoved(ctx context.Context, ns *os.File, identity NamespaceIdentity, p Plan) error {
	p, err := Normalize(p)
	if err != nil {
		return err
	}
	if c.Store == nil || c.Driver == nil || ns == nil || identity.Inode == 0 {
		return ErrUnavailable
	}
	if err = c.Store.Reserve(Manifest{p, identity}); err != nil {
		return err
	}
	snapshot, err := c.Driver.Snapshot(ctx, ns, p)
	if err != nil {
		return err
	}
	if hasInterface(snapshot, InterfaceName(p)) {
		return ErrOwnership
	}
	if err = checkSnapshot(p, snapshot, false); err != nil {
		return err
	}
	if _, err = c.Driver.BirthLink(ctx, p); !errors.Is(err, ErrMissing) {
		return ErrOwnership
	}
	return nil
}

func ownedLink(p Plan, link Link) bool {
	return link.Index > 0 && link.Name == InterfaceName(p) && link.Alias == Alias(p) && link.Kind == "wireguard"
}
func hasInterface(s Snapshot, name string) bool {
	for _, l := range s.Links {
		if l.Name == name {
			return true
		}
	}
	return false
}
func hasAddress(s Snapshot, name string, prefix netip.Prefix) bool {
	for _, a := range s.Addresses {
		if a.Interface == name && a.Prefix == prefix {
			return true
		}
	}
	return false
}
func hasRoute(s Snapshot, name string, prefix netip.Prefix) bool {
	for _, r := range s.Routes {
		if !r.Local && r.Interface == name && r.Prefix == prefix && r.Gateway == "" {
			return true
		}
	}
	return false
}
func checkSnapshot(p Plan, s Snapshot, complete bool) error {
	name := InterfaceName(p)
	seen := map[string]bool{}
	for _, link := range s.Links {
		if seen[link.Name] {
			return ErrOwnership
		}
		seen[link.Name] = true
		if link.Name == "lo" {
			if complete && !link.Up {
				return ErrUnavailable
			}
			continue
		}
		if !ownedLink(p, link) {
			return ErrOwnership
		}
		if complete && (!link.Up || link.MTU != p.MTU) {
			return ErrUnavailable
		}
	}
	if !seen["lo"] || len(seen) > 2 || !s.DefaultRulesOnly {
		return ErrOwnership
	}
	if complete && !seen[name] {
		return ErrMissing
	}
	addressCount := 0
	for _, a := range s.Addresses {
		if a.Interface == "lo" && a.Prefix.IsValid() && a.Prefix.Addr().IsLoopback() {
			continue
		}
		if !seen[name] || a.Interface != name || a.Prefix != p.Address {
			return ErrOwnership
		}
		addressCount++
	}
	if addressCount > 1 || (complete && addressCount != 1) {
		return ErrOwnership
	}
	for _, route := range s.Routes {
		if route.Gateway != "" || !route.Prefix.IsValid() {
			return ErrOwnership
		}
		if route.Interface == "lo" && route.Prefix.Addr().IsLoopback() {
			continue
		}
		if !seen[name] || route.Interface != name {
			return ErrOwnership
		}
		// Linux adds this local multicast route when the owned WG link comes
		// up. It grants no IPv6 peer transport: the exact peer AllowedIPs remain
		// the admitted IPv4-only routes, and foreign/global routes still fail.
		if route.Local && route.Prefix == netip.MustParsePrefix("ff00::/8") {
			continue
		}
		if route.Local && route.Prefix == p.Address {
			continue
		}
		allowed := false
		for _, wanted := range p.Routes {
			if !route.Local && wanted == route.Prefix {
				allowed = true
			}
		}
		if !allowed {
			return ErrOwnership
		}
	}
	if complete {
		for _, route := range p.Routes {
			if !hasRoute(s, name, route) {
				return ErrUnavailable
			}
		}
	}
	if s.PublicKey != "" && s.PublicKey != p.PublicKey {
		return ErrOwnership
	}
	if len(s.Peers) > 1 || (complete && (s.PublicKey != p.PublicKey || len(s.Peers) != 1)) {
		return ErrOwnership
	}
	for _, peer := range s.Peers {
		if peer.PublicKey != p.GatewayPublicKey || peer.Endpoint != p.Endpoint || peer.KeepaliveSeconds != p.KeepaliveSeconds || len(peer.Routes) != len(p.Routes) {
			return ErrOwnership
		}
		for _, route := range p.Routes {
			found := false
			for _, actual := range peer.Routes {
				if actual == route {
					found = true
				}
			}
			if !found {
				return ErrOwnership
			}
		}
	}
	if !seen[name] && (s.PublicKey != "" || len(s.Peers) != 0) {
		return ErrOwnership
	}
	return nil
}

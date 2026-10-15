package fqdnresolver

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/tunnexio/tunnex/apps/api/internal/fqdn"
)

// StaticRecord is part of the immutable, server-selected profile snapshot.
// Resolving this snapshot never invokes a gateway RPC or the host resolver.
type StaticRecord struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Value string `json:"value"`
	TTL   int    `json:"ttl"`
}

func validStaticRecords(records []StaticRecord) bool {
	if len(records) == 0 || len(records) > 128 {
		return false
	}
	aliases := map[string]string{}
	addresses, seen, ttls := map[string]int{}, map[string]bool{}, map[string]int{}
	for _, r := range records {
		name, err := fqdn.Normalize(r.Name)
		if err != nil || name != r.Name || r.TTL < 30 || r.TTL > 86400 {
			return false
		}
		key := r.Name + "|" + r.Type + "|" + r.Value
		if seen[key] {
			return false
		}
		seen[key] = true
		rrset := r.Name + "|" + r.Type
		if ttl, ok := ttls[rrset]; ok && ttl != r.TTL {
			return false
		}
		ttls[rrset] = r.TTL
		switch r.Type {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(r.Value)
			if err != nil || !ip.IsPrivate() || ip.Is4In6() || (r.Type == "A" && !ip.Is4()) || (r.Type == "AAAA" && !ip.Is6()) {
				return false
			}
			addresses[r.Name]++
			if addresses[r.Name] > MaxAnswers {
				return false
			}
		case "CNAME":
			target, err := fqdn.Normalize(r.Value)
			if err != nil || target != r.Value || aliases[r.Name] != "" {
				return false
			}
			aliases[r.Name] = target
		default:
			return false
		}
	}
	for name := range aliases {
		if addresses[name] > 0 {
			return false
		}
		visited := map[string]bool{}
		for current := name; aliases[current] != ""; current = aliases[current] {
			if visited[current] || len(visited) >= MaxCNAMEDepth {
				return false
			}
			visited[current] = true
		}
	}
	return true
}

func lookupStatic(ctx context.Context, w Work) ([]Response, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c := w.ResolverConfig
	name, err := fqdn.Normalize(w.Hostname)
	if err != nil || !w.Context.valid() || !c.valid() || len(c.StaticRecords) == 0 || (name != c.MatchedSuffix && !strings.HasSuffix(name, "."+c.MatchedSuffix)) {
		return nil, ErrUnboundContext
	}
	byName := map[string][]StaticRecord{}
	for _, record := range c.StaticRecords {
		byName[record.Name] = append(byName[record.Name], record)
	}
	if len(byName[name]) == 0 {
		return []Response{{Status: StatusNXDOMAIN}}, nil
	}
	response := Response{Status: StatusNoError}
	for depth := 0; depth <= MaxCNAMEDepth; depth++ {
		rows := byName[name]
		if len(rows) == 0 {
			break
		} // External aliases confer no invented addresses.
		next := ""
		for _, row := range rows {
			r := Record{Name: row.Name, Type: RecordType(row.Type), TTL: time.Duration(row.TTL) * time.Second}
			if row.Type == "CNAME" {
				r.Target, next = row.Value, row.Value
			} else {
				r.Address = netip.MustParseAddr(row.Value)
			}
			response.Records = append(response.Records, r)
		}
		if next == "" {
			break
		}
		name = next
	}
	return []Response{response}, nil
}

// StaticGenerationMatches keeps fixed-record application generations distinct
// from gateway-only external CNAME completion. It performs no DNS or RPC I/O.
func StaticGenerationMatches(g ActiveGeneration) bool {
	responses, err := lookupStatic(context.Background(), Work{Hostname: g.Hostname, Context: g.Context, ResolverConfig: g.ResolverConfig})
	if err != nil {
		return false
	}
	result, err := canonical(g.Hostname, responses)
	return err == nil && slices.Equal(result.addresses, g.Addresses)
}

// The readers reject the entire selected static snapshot on an ownership
// conflict. Dropping every record would otherwise turn public completion
// endpoints into ordinary upstream resolver mode.
func staticProfileOwnsRecords(profile ResolverProfile, profiles []ResolverProfile) bool {
	selected := -1
	zones := make([][]string, len(profiles))
	for i, candidate := range profiles {
		zones[i] = candidate.ZoneSuffixes
		if candidate.ID == profile.ID {
			if selected >= 0 {
				return false
			}
			selected = i
		}
	}
	names := make([]string, 0, len(profile.StaticRecords))
	for _, record := range profile.StaticRecords {
		names = append(names, record.Name)
	}
	return fqdn.StaticNamesOwnedByProfile(selected, names, zones)
}

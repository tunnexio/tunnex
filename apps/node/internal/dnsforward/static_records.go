package dnsforward

import (
	"net/netip"
	"strings"

	"golang.org/x/net/dns/dnsmessage"
)

// StaticRecord is one exact answer in a private-zone profile. CNAME targets are
// completed locally first; explicit profile upstreams may resolve an external tail.
type StaticRecord struct {
	Name  string
	Type  string
	Value string
	TTL   uint32
}

type staticAnswers map[string][]StaticRecord

func validStaticName(name string) string {
	name = normalizeDomain(name)
	if len(name) < 2 || len(name) > 254 || !strings.Contains(strings.TrimSuffix(name, "."), ".") {
		return ""
	}
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return ""
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return ""
			}
		}
	}
	if _, err := netip.ParseAddr(strings.TrimSuffix(name, ".")); err == nil {
		return ""
	}
	return name
}

func compileStaticRecords(records []StaticRecord, zones []string) (staticAnswers, bool) {
	if len(records) == 0 || len(records) > 128 {
		return nil, false
	}
	result := staticAnswers{}
	for _, r := range records {
		r.Name = validStaticName(r.Name)
		if r.Name == "" || r.TTL < 30 || r.TTL > 86400 {
			return nil, false
		}
		matched := false
		for _, zone := range zones {
			if r.Name == zone || strings.HasSuffix(r.Name, "."+zone) {
				matched = true
			}
		}
		if !matched {
			return nil, false
		}
		switch r.Type {
		case "A", "AAAA":
			ip, err := netip.ParseAddr(r.Value)
			if err != nil || !ip.IsPrivate() || r.Type == "A" && !ip.Is4() || r.Type == "AAAA" && (!ip.Is6() || ip.Is4In6()) {
				return nil, false
			}
			r.Value = ip.String()
		case "CNAME":
			r.Value = validStaticName(r.Value)
			if r.Value == "" {
				return nil, false
			}
		default:
			return nil, false
		}
		for _, existing := range result[r.Name] {
			if existing.Type == "CNAME" || r.Type == "CNAME" || existing.Type == r.Type && (existing.Value == r.Value || existing.TTL != r.TTL) {
				return nil, false
			}
		}
		if len(result[r.Name]) >= 32 {
			return nil, false
		}
		result[r.Name] = append(result[r.Name], r)
	}
	// Reject loops at install time; serve-time depth remains bounded as defense
	// against malformed declarations without creating another resolver authority.
	for name := range result {
		seen := map[string]bool{}
		hops := 0
		for next := name; ; {
			if seen[next] {
				return nil, false
			}
			seen[next] = true
			rows := result[next]
			if len(rows) != 1 || rows[0].Type != "CNAME" {
				break
			}
			hops++
			if hops > 8 {
				return nil, false
			}
			next = rows[0].Value
		}
	}
	return result, true
}

func (records staticAnswers) answer(id uint16, query []byte, q dnsmessage.Question) []byte {
	name := strings.ToLower(q.Name.String())
	if len(records[name]) == 0 {
		return nxdomain(id, query)
	}
	b := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: id, Response: true, Authoritative: true, RCode: dnsmessage.RCodeSuccess})
	b.EnableCompression()
	if b.StartQuestions() != nil || b.Question(q) != nil || b.StartAnswers() != nil {
		return nil
	}
	for depth := 0; depth <= 8; depth++ {
		rows := records[name]
		if len(rows) == 0 {
			break
		}
		owner, err := dnsmessage.NewName(name)
		if err != nil {
			return servfail(id, query)
		}
		alias := ""
		for _, r := range rows {
			h := dnsmessage.ResourceHeader{Name: owner, Class: dnsmessage.ClassINET, TTL: r.TTL}
			var err error
			switch r.Type {
			case "CNAME":
				target, e := dnsmessage.NewName(r.Value)
				if e != nil {
					return servfail(id, query)
				}
				err = b.CNAMEResource(h, dnsmessage.CNAMEResource{CNAME: target})
				alias = r.Value
			case "A":
				if q.Type == dnsmessage.TypeA {
					err = b.AResource(h, dnsmessage.AResource{A: netip.MustParseAddr(r.Value).As4()})
				}
			case "AAAA":
				if q.Type == dnsmessage.TypeAAAA {
					err = b.AAAAResource(h, dnsmessage.AAAAResource{AAAA: netip.MustParseAddr(r.Value).As16()})
				}
			}
			if err != nil {
				return nil
			}
		}
		if alias == "" || q.Type == dnsmessage.TypeCNAME {
			break
		}
		name = alias
	}
	response, err := b.Finish()
	if err != nil {
		return nil
	}
	return response
}

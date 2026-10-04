package appaccess

import "testing"

func TestPublicationRequiresPublicHTTPSIsolation(t *testing.T) {
	for _, tc := range []struct {
		name, base, console, host string
		want                      bool
	}{
		{"independent", "apps.example.net", "https://console.example.com", "console.example.com", true},
		{"local fixture topology", "apps.127.0.0.1.nip.io", "https://console.127.0.0.1.sslip.io:15180", "console.127.0.0.1.sslip.io", true},
		{"unknown suffix", "apps.fixture.test", "https://console.other.test", "console.other.test", false},
		{"private suffix", "apps.github.io", "https://console.example.com", "console.example.com", false},
		{"HTTP console", "apps.example.net", "http://console.example.com", "console.example.com", false},
		{"same site", "apps.example.com", "https://console.example.com", "console.example.com", false},
		{"unconfigured URL", "apps.example.net", "", "console.example.com", false},
		{"different configured host", "apps.example.net", "https://console.example.com", "other.example.org", false},
		{"query", "apps.example.net", "https://console.example.com?next=evil", "console.example.com", false},
		{"fragment", "apps.example.net", "https://console.example.com#evil", "console.example.com", false},
		{"userinfo", "apps.example.net", "https://user@console.example.com", "console.example.com", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := NewService(nil, Config{AppBaseDomain: tc.base, ConsoleURL: tc.console, ConsoleHosts: []string{tc.host}})
			if s.publicationDomainReady() != tc.want {
				t.Fatal("publication domain boundary")
			}
		})
	}
	draft := NewService(nil, Config{AppBaseDomain: "apps.fixture.test", ConsoleHosts: []string{"console.other.test"}})
	if !draft.domainReady || draft.publicationDomainReady() {
		t.Fatal("draft compatibility conflated with publication")
	}
}

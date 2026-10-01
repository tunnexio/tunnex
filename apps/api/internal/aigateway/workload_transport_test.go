package aigateway

import "testing"

func TestWorkloadPublicTransportRequiresOperatorOptIn(t *testing.T) {
	for _, tc := range []struct {
		name, base string
		allow      bool
		want       bool
	}{
		{"HTTPS hostname default", "https://vpn.example.com", false, true},
		{"HTTPS private IP default", "https://172.31.20.253", false, true},
		{"HTTP hostname default", "http://ec2-51-20-98-153.eu-north-1.compute.amazonaws.com", false, false},
		{"HTTP private IP default", "http://172.31.20.253", false, false},
		{"HTTP public IP default", "http://51.20.98.153", false, false},
		{"HTTP hostname explicit", "http://ec2-51-20-98-153.eu-north-1.compute.amazonaws.com", true, true},
		{"HTTP private IP explicit", "http://172.31.20.253", true, true},
		{"HTTP public IP explicit", "http://51.20.98.153", true, true},
		{"loopback development", "http://127.0.0.1:8080", false, true},
		{"IPv6 loopback development", "http://[::1]:8080", false, true},
		{"unsupported scheme", "ftp://vpn.example.com", true, false},
		{"userinfo", "http://private:secret@172.31.20.253", true, false},
		{"path", "http://172.31.20.253/inference", true, false},
		{"query", "http://172.31.20.253?allow_http=true", true, false},
		{"empty query", "http://172.31.20.253?", true, false},
		{"fragment", "http://172.31.20.253#allow_http", true, false},
		{"missing host", "http:///", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			service, err := NewWorkloads(&Policies{}, tc.base, WorkloadOptions{AllowPrivateHTTP: tc.allow})
			if (err == nil) != tc.want {
				t.Fatalf("base=%s explicit=%v accepted=%v want=%v", tc.base, tc.allow, err == nil, tc.want)
			}
			if err == nil && service.base != tc.base {
				t.Fatalf("base changed %s", service.base)
			}
		})
	}
	// The old call shape retains secure defaults. No identity, forwarding header
	// or trusted caller address is accepted as an alternative operator option.
	if _, err := NewWorkloads(&Policies{}, "http://172.31.20.253"); err == nil {
		t.Fatal("legacy constructor implicitly enabled HTTP")
	}
	if _, err := NewWorkloads(&Policies{}, "http://172.31.20.253", WorkloadOptions{AllowPrivateHTTP: true}, WorkloadOptions{AllowPrivateHTTP: true}); err == nil {
		t.Fatal("ambiguous operator options enabled HTTP")
	}
}

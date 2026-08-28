package fqdn

import "testing"

func TestNormalize(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"Orders.Internal.Example.", "orders.internal.example"},
		{"bücher.example", "xn--bcher-kva.example"},
		{"xn--bcher-kva.example", "xn--bcher-kva.example"},
	} {
		got, err := Normalize(tc.input)
		if err != nil || got != tc.want {
			t.Errorf("Normalize(%q) = %q, %v; want %q, nil", tc.input, got, err, tc.want)
		}
	}
}

func TestNormalizeRejectsNonFQDNInputs(t *testing.T) {
	for _, input := range []string{
		"", ".", "orders", "orders..example", "orders.example..",
		" orders.example", "orders.example ", "*.example", "api_service.example",
		"https://orders.example", "orders.example:443", "192.0.2.1", "[2001:db8::1]",
	} {
		if got, err := Normalize(input); err == nil || got != "" {
			t.Errorf("Normalize(%q) = %q, %v; want rejection", input, got, err)
		}
	}
}

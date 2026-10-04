package config

import "testing"

func TestAppAccessDomainOptInConfig(t *testing.T) {
	t.Setenv("TUNNEX_APP_ACCESS_BASE_DOMAIN", "")
	if Load().AppAccessBaseDomain != "" {
		t.Fatal("domain must default off")
	}
	t.Setenv("TUNNEX_APP_ACCESS_BASE_DOMAIN", "apps.example.net")
	if Load().AppAccessBaseDomain != "apps.example.net" {
		t.Fatal("operator domain ignored")
	}
}

func TestAppProxyAuthorityDefaultOff(t *testing.T) {
	t.Setenv("TUNNEX_APP_PROXY_AUTHORITY_ADDR", "")
	if Load().AppProxyAuthorityAddr != "" {
		t.Fatal("authority must default off")
	}
	t.Setenv("TUNNEX_APP_PROXY_AUTHORITY_ADDR", "127.0.0.1:8445")
	if Load().AppProxyAuthorityAddr != "127.0.0.1:8445" {
		t.Fatal("operator address not loaded")
	}
}

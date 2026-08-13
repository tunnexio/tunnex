package idpsync

import "testing"

func TestGoogleWorkspaceCredentialsValidateDWDInputs(t *testing.T) {
	if _, err := NewGoogleWorkspaceProvider("{}", "admin@example.com", nil); err == nil {
		t.Fatal("empty service-account credentials must be rejected")
	}
	if _, err := NewGoogleWorkspaceProvider(`{"type":"service_account","client_email":"svc@example.com","private_key":"bad"}`, "not-an-email", nil); err == nil {
		t.Fatal("invalid delegated admin email must be rejected")
	}
}

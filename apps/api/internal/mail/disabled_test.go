package mail

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"
)

// ⛔ THE SWALLOWED ERROR, PINNED. A deployment with no SMTP host used to LOG the message and return nil —
// so every invitation, verification link and password reset "sent" and vanished, while the API answered
// 202 and the screen said Sent.
//
// ⚠ AND INVITATIONS ARE NOW THE ONLY WAY ANYONE JOINS A DEPLOYMENT. A silent mail failure is therefore a
// deployment nobody can get into, reporting success on every screen it has.
func TestAnUnconfiguredDeploymentRefusesToClaimItSent(t *testing.T) {
	var buf bytes.Buffer
	m := New(Config{}, slog.New(slog.NewJSONHandler(&buf, nil)))

	err := m.Send(context.Background(), Message{
		To:      "invitee@acme.test",
		Subject: "You're invited to Tunnex",
		Text:    "Your invitation link: https://vpn.acme.test/accept-invite?token=SECRET-TOKEN-VALUE",
	})
	if err == nil {
		t.Fatal("⛔ A DEPLOYMENT WITH NO SMTP REPORTED SUCCESS. Every invitation it drops will read as sent, " +
			"and invitations are the only way anyone joins")
	}
	if !errors.Is(err, ErrNotConfigured) {
		t.Errorf("err = %v, want ErrNotConfigured so callers can tell this from a transport failure", err)
	}
	if m.Kind() != "disabled" {
		t.Errorf("Kind() = %q — the startup log names this, so it must not read like a working mailer", m.Kind())
	}

	// ⛔ AND THE BODY IS NOT IN THE LOG. It carries invitation links, password-reset links and verification
	// links; `docker compose logs` is shipped, aggregated and searchable. This repo has already ruled that
	// class once, for the bootstrap password.
	logged := buf.String()
	if strings.Contains(logged, "SECRET-TOKEN-VALUE") {
		t.Error("⛔ THE MESSAGE BODY WAS WRITTEN TO THE LOG — an invitation token now lives in log " +
			"aggregation, readable by anyone who can read logs, forever")
	}
	// It still says enough to act on: who it was for, and how to fix it.
	for _, want := range []string{"invitee@acme.test", "SMTP_HOST"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the refusal log never mentions %q — an operator cannot act on it", want)
		}
	}
}

// ⭐ AND A CONFIGURED DEPLOYMENT IS UNAFFECTED — the permitted case, so a later failure cannot be read as
// "mail is broken everywhere".
func TestAConfiguredDeploymentBuildsARealMailer(t *testing.T) {
	m := New(Config{Host: "smtp.example.test", Port: "587", From: "no-reply@example.test"},
		slog.New(slog.NewJSONHandler(&bytes.Buffer{}, nil)))
	if m.Kind() != "smtp" {
		t.Fatalf("Kind() = %q, want smtp", m.Kind())
	}
	if !Configured(Config{Host: "smtp.example.test"}) || Configured(Config{Host: "   "}) {
		t.Error("Configured() disagrees with New() about what counts as configured")
	}
}

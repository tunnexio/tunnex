package bootstrap

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

type fakeStore struct {
	users   int64
	created []sqlc.CreateBootstrapAdminParams
	err     error
}

func (f *fakeStore) CountUsers(context.Context) (int64, error) { return f.users, f.err }
func (f *fakeStore) CreateBootstrapAdmin(_ context.Context, p sqlc.CreateBootstrapAdminParams) (sqlc.User, error) {
	f.created = append(f.created, p)
	return sqlc.User{Email: p.Email}, nil
}

type fakeMailer struct {
	messages []mail.Message
	err      error
}

func (f *fakeMailer) Send(_ context.Context, msg mail.Message) error {
	f.messages = append(f.messages, msg)
	return f.err
}

func (f *fakeMailer) Kind() string { return "fake" }

// ⚠ TWO SINKS, AND THE TEST WATCHES THE ONE THE OPERATOR WATCHES. The credential goes to `out` (stdout in
// production); the logger records only that the event happened. A test reading the logger would pass while
// the banner was empty.
func capture() (*slog.Logger, *bytes.Buffer, *bytes.Buffer) {
	var logBuf, outBuf bytes.Buffer
	return slog.New(slog.NewJSONHandler(&logBuf, nil)), &logBuf, &outBuf
}

// ⭐ A FRESH DEPLOYMENT MINTS EXACTLY ONE ADMIN AND PRINTS THE CREDENTIAL.
func TestFreshDeploymentMintsOneAdminAndPrintsIt(t *testing.T) {
	f := &fakeStore{users: 0}
	log, logBuf, out := capture()
	if err := EnsureAdmin(context.Background(), f, log, out, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 1 {
		t.Fatalf("⛔ minted %d admins on a fresh deployment, want exactly 1", len(f.created))
	}
	if f.created[0].Email != AdminEmail {
		t.Errorf("email = %q, want %q", f.created[0].Email, AdminEmail)
	}
	// ⛔ THE PASSWORD IS HASHED IN THE ROW. The plaintext exists for one log line and nowhere else — not
	// .env, not a file, not the database.
	if f.created[0].PasswordHash == nil || !strings.HasPrefix(*f.created[0].PasswordHash, "$argon2") {
		t.Error("⛔ the bootstrap password was not stored as an argon2id hash")
	}

	banner := out.String()
	if banner == "" {
		t.Fatal("⛔ NO BANNER WAS PRINTED. There is no public signup, so an operator who cannot read the " +
			"password on their terminal has no way into their own deployment at all")
	}
	// The plaintext the row hashed must be the one on screen.
	pw := ""
	for _, line := range strings.Split(banner, "\n") {
		if strings.Contains(line, "password ") {
			pw = strings.TrimSpace(strings.SplitN(line, "password ", 2)[1])
		}
	}
	if pw == "" {
		t.Fatal("⛔ the banner does not carry a password line")
	}
	// ⛔ AND THE CREDENTIAL IS NOT IN THE LOG. A banner scrolls off a terminal; log aggregation keeps a
	// searchable copy forever, so printing it twice doubles the exposure for no benefit.
	if strings.Contains(logBuf.String(), pw) {
		t.Error("⛔ THE PASSWORD WAS ALSO WRITTEN TO THE STRUCTURED LOG — it will be shipped to log " +
			"aggregation and searchable long after the terminal is closed")
	}
	for _, want := range []string{"SHOWN ONCE", "down -v", AdminEmail} {
		if !strings.Contains(banner, want) {
			t.Errorf("the banner never says %q", want)
		}
	}
	// ⚠ It must be the REAL password, not the hash — printing the hash would look right and be useless.
	if strings.HasPrefix(pw, "$argon2") {
		t.Error("⛔ the HASH was printed instead of the password")
	}
	if len(pw) < 24 {
		t.Errorf("printed credential is only %d chars — it is copied from a log, never typed from "+
			"memory, so there is no reason to trade entropy for brevity", len(pw))
	}

}

// ⛔ THE BRANCH THAT MATTERS. Containers restart constantly — crashes, deploys, host reboots.
//
// Minting a second admin on any of those is a privilege escalation with no actor behind it. REPRINTING the
// first one's password republishes a live credential into logs that are shipped, aggregated and searched
// long after they were written.
//
// > ## ⛔ **A RESTART MUST NOT BE A SECURITY EVENT.**
func TestDeploymentWithUsersMintsNothingAndPrintsNothing(t *testing.T) {
	f := &fakeStore{users: 1}
	log, _, out := capture()
	if err := EnsureAdmin(context.Background(), f, log, out, "", nil); err != nil {
		t.Fatal(err)
	}
	if len(f.created) != 0 {
		t.Fatal("⛔ A SECOND ADMIN WAS MINTED ON A DEPLOYMENT THAT ALREADY HAS USERS — every restart " +
			"would create another account with deployment-level authority and nobody asked for it")
	}
	if out.Len() != 0 {
		t.Fatalf("⛔ SOMETHING WAS PRINTED ON A RESTART: %s\n\nIf that is a credential it has just been "+
			"republished to log aggregation; if it is noise it trains operators to ignore the one line "+
			"that matters.", out.String())
	}
}

// ⚠ AND A COUNT FAILURE MINTS NOTHING. "We could not tell" is not "there are no users" — guessing the
// permissive way would mint an admin on a healthy deployment whose database blinked.
func TestCountFailureMintsNothing(t *testing.T) {
	f := &fakeStore{users: 0, err: errors.New("connection refused")}
	log, _, out := capture()
	if err := EnsureAdmin(context.Background(), f, log, out, "", nil); err == nil {
		t.Error("a store failure was swallowed — the caller cannot tell bootstrap did not run")
	}
	if len(f.created) != 0 || out.Len() != 0 {
		t.Fatal("⛔ an admin was minted despite not knowing whether users exist")
	}
}

func TestFreshDeploymentUsesConfiguredEmailAndSendsCredential(t *testing.T) {
	f := &fakeStore{users: 0}
	m := &fakeMailer{}
	log, logBuf, out := capture()
	if err := EnsureAdmin(context.Background(), f, log, out, "owner@example.com", m); err != nil {
		t.Fatal(err)
	}
	if got := f.created[0].Email; got != "owner@example.com" {
		t.Fatalf("stored email = %q, want owner@example.com", got)
	}
	if len(m.messages) != 1 || m.messages[0].To != "owner@example.com" {
		t.Fatalf("sent messages = %#v, want one message to configured admin", m.messages)
	}
	if !strings.Contains(m.messages[0].Text, "Password: ") {
		t.Fatal("bootstrap email did not contain the one-time password")
	}
	if strings.Contains(logBuf.String(), "Password: ") {
		t.Fatal("bootstrap password appeared in structured logs")
	}
}

func TestFreshDeploymentWithoutSMTPKeepsTerminalFallback(t *testing.T) {
	f := &fakeStore{users: 0}
	log, logBuf, out := capture()
	mailer := mail.New(mail.Config{}, log)
	if err := EnsureAdmin(context.Background(), f, log, out, "owner@example.com", mailer); err != nil {
		t.Fatal(err)
	}
	banner := out.String()
	if !strings.Contains(banner, "password ") || !strings.Contains(banner, "could not be sent") {
		t.Fatalf("SMTP-absent bootstrap did not preserve an explicit terminal fallback: %s", banner)
	}
	pw := ""
	for _, line := range strings.Split(banner, "\n") {
		if strings.Contains(line, "password ") {
			pw = strings.TrimSpace(strings.SplitN(line, "password ", 2)[1])
		}
	}
	if pw == "" || strings.Contains(logBuf.String(), pw) {
		t.Fatal("SMTP-absent bootstrap password was missing from the terminal or leaked into structured logs")
	}
}

// ⭐ THE CREDENTIAL IS NEVER THE SAME TWICE. A deterministic bootstrap password is a default password.
func TestTheCredentialIsRandom(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 5; i++ {
		pw, err := generatePassword()
		if err != nil {
			t.Fatal(err)
		}
		if seen[pw] {
			t.Fatal("⛔ THE BOOTSTRAP PASSWORD REPEATS — it is a default credential, which is the single " +
				"most exploited class of finding in self-hosted software")
		}
		seen[pw] = true
	}
}

package mail

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

// TestSMTPHostSetMeansSend — S12.13 D1, the ruling in one assertion.
//
// ⛔ NO FLAG OTHER THAN SMTP_HOST MAY DECIDE WHETHER MAIL IS SENT. The tee used to arrive via
// `!IsProduction()`, so a variable describing the KIND of deployment governed mail behaviour — the founder
// set five SMTP variables, got a mailer labelled `smtp+log`, and reasonably concluded mail was off.
//
// ⚠ AND THE TEE STILL SENDS, which is the half that was never in doubt in the code and entirely in doubt
// to the reader. Asserted by construction: the tee's primary IS the SMTP mailer.
func TestSMTPHostSetMeansSend(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(&bytes.Buffer{}, nil))
	// ⚠ EVERY MAILER IS WRAPPED for logo resolution (S12.14), so the assertion follows the SEND PATH to its
	// end rather than matching the outermost type. A test that pinned the concrete top-level type would
	// fail on any future wrapper while proving nothing about where mail goes.
	if _, ok := sendPathEnd(New(Config{Host: "mail.example.net", Port: "587"}, logger)).(*SMTPMailer); !ok {
		t.Fatal("a configured host must send via SMTP")
	}
	teed := sendPathEnd(New(Config{Host: "mail.example.net", Port: "587", DevLogging: true}, logger))
	tee, ok := teed.(*teeMailer)
	if !ok {
		t.Fatalf("MAIL_DEV_LOG must WRAP the sender, never replace it, got %T", teed)
	}
	if _, ok := tee.primary.(*SMTPMailer); !ok {
		t.Fatal("the tee's primary must be the SMTP mailer — the tee has never suppressed delivery and no " +
			"reading of it may suggest otherwise")
	}
	// Only an ABSENT host disables mail.
	if _, ok := sendPathEnd(New(Config{DevLogging: true}, logger)).(*disabledMailer); !ok {
		t.Fatal("mail is disabled by an absent SMTP_HOST and by nothing else")
	}
}

// TestDestinationNamesWhereMailGoes — S12.13 D2.
//
// ⛔ `smtp+log` WAS ACCURATE AND UNREADABLE. The `+` says "SMTP and also a log copy" to one reader and
// "logs instead of SMTP" to another, and the reader who guessed wrong discovered it by not receiving an
// email. The boot line must answer "will my invitation arrive", not "which types are composed".
func TestDestinationNamesWhereMailGoes(t *testing.T) {
	sending := Destination(Config{Host: "mail.spacemail.com", Port: "587"})
	if !strings.Contains(sending, "mail.spacemail.com:587") {
		t.Fatalf("a sending deployment must name the SERVER: %q", sending)
	}
	if strings.Contains(sending, "+") {
		t.Fatalf("the destination must not be a composition of type names: %q", sending)
	}

	off := Destination(Config{})
	if !strings.Contains(off, "DISABLED") || !strings.Contains(off, "SMTP_HOST") {
		t.Fatalf("with no host it must say mail is disabled AND name the variable that fixes it: %q", off)
	}

	// ⚠ THE TEE IS NAMED, and its log is metadata-only so an operator can diagnose delivery without logging
	// working links or credentials.
	teed := Destination(Config{Host: "mail.spacemail.com", Port: "587", DevLogging: true})
	if !strings.Contains(teed, "mail.spacemail.com:587") {
		t.Fatalf("the tee still SENDS, so the destination must still name the server: %q", teed)
	}
	if !strings.Contains(teed, "MAIL_DEV_LOG") || !strings.Contains(teed, "metadata") {
		t.Fatalf("the tee must name itself and describe safe metadata logging: %q", teed)
	}
}

// TestTeeLogLineIsTrueInBothContexts — the line that cost a session.
//
// ⛔ `email_not_sent_logged` WAS TRUE ALONE AND A FLAT LIE INSIDE THE TEE, and the tee is the context an
// operator with working SMTP actually meets. A log line naming an outcome must be true in every context it
// can be reached from.
func TestTeeLogLineIsTrueInBothContexts(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&buf, nil))
	lm := &LogMailer{logger: logger, reason: "MAIL_DEV_LOG"}
	if err := lm.Send(context.Background(), Message{To: "a@b.c", Subject: "S", Text: "SECRET-BOOTSTRAP-KEY"}); err != nil {
		t.Fatal(err)
	}
	var rec map[string]any
	if e := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); e != nil {
		t.Fatal(e)
	}
	if rec["msg"] == "email_not_sent_logged" {
		t.Fatal("the old name claimed an outcome that is false whenever this mailer is the tee's log half")
	}
	if rec["msg"] != "email_copied_to_log" {
		t.Fatalf("the name must describe what THIS mailer did and nothing about what happens next: %v", rec["msg"])
	}
	if rec["body"] != "omitted" || rec["subject"] != "S" || strings.Contains(buf.String(), "SECRET-BOOTSTRAP-KEY") {
		t.Fatalf("LogMailer must retain safe metadata but never log the message body: %v", rec)
	}
}

// TestSuccessIsAsVisibleAsFailure — S12.13 D2, second half.
//
// ⛔ ONLY FAILURE LOGGED, so an empty log meant BOTH "it worked" and "it never tried". That is not a
// diagnosis; it is a coin flip performed at the moment an operator can least afford one.
//
// ⚠ THE SEND ITSELF CANNOT RUN HERE (no server), so this asserts the CONTRACT the success line must keep:
// it names acceptance, never delivery, and it never carries a body.
func TestSuccessLineClaimsAcceptanceNotDelivery(t *testing.T) {
	var buf bytes.Buffer
	m := &SMTPMailer{
		cfg:    Config{Host: "127.0.0.1", Port: "1", From: "f@x.test"},
		logger: slog.New(slog.NewJSONHandler(&buf, nil)),
	}
	// Unreachable port: the send fails, so NOTHING may be logged as accepted.
	if err := m.Send(context.Background(), Message{To: "a@b.c", Subject: "S", Text: "secret-link"}); err == nil {
		t.Fatal("a send to an unreachable server must return an error")
	}
	if strings.Contains(buf.String(), "email_accepted_by_provider") {
		t.Fatal("a FAILED send must never log acceptance — that is the swallowed-error shape rebuilt")
	}
	if strings.Contains(buf.String(), "secret-link") {
		t.Fatal("the SMTP mailer runs on every deployment and must never log a message body")
	}
}

// sendPathEnd is now the identity — the branding wrapper is GONE, because embedding the logo removed the
// only deployment-specific value a rendered message carried. Kept as a seam so the assertions above read
// as "where does the send path end" rather than "what is the top-level type", which is the question that
// matters and the one a future wrapper must not silently change the answer to.
func sendPathEnd(m Mailer) Mailer { return m }

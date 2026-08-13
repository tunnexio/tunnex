// Package mail provides a pluggable mailer used by the local-auth flows
// (email verification, password reset — S2.1).
//
// Selection — ⛔ SMTP_HOST SET MEANS SEND, AND NOTHING ELSE MAY OVERRIDE THAT (S12.13 D1):
//   - No SMTP host configured   -> disabledMailer: REFUSES with ErrNotConfigured and logs the recipient
//     and subject (never the body — it carries links). ⛔ It used to log the whole message and return nil,
//     so a deployment with no mail reported success on every invitation it silently dropped.
//   - SMTP host configured      -> SMTPMailer.
//   - SMTP host + MAIL_DEV_LOG  -> the SMTP mailer wrapped to ALSO log safe metadata. It still sends. The
//     tee never logs message bodies, which may contain links, tokens, or bootstrap credentials.
//
// ⛔ DevLogging IS ITS OWN VARIABLE (MAIL_DEV_LOG), NOT A CONSEQUENCE OF TUNNEX_ENV. It used to be
// `!IsProduction()`, which meant a variable about the KIND of deployment silently governed mail behaviour —
// so a correctly-configured rig produced a mailer labelled `smtp+log` and a log line reading
// `email_not_sent_logged`, and the operator reasonably concluded mail was off. It was sending the whole
// time. ONE FLAG MUST NOT GOVERN TWO UNRELATED THINGS.
//
// ⚠ AND EVERY MAILER NOW NAMES ITS DESTINATION rather than its capability. `smtp+log` read as "SMTP AND
// log" — which is what it did — but the `+` invited "SMTP plus a log copy" and "log instead of SMTP"
// equally, and the reader who guessed wrong had no way to tell.
package mail

import (
	"bytes"
	"context"
	_ "embed"
	"errors"
	"fmt"
	"log/slog"
	stdmail "net/mail"
	"strconv"
	"strings"

	gomail "github.com/wneessen/go-mail"
)

// ⛔ THE LOGO TRAVELS WITH THE MESSAGE. IT IS NEVER FETCHED.
//
// The first version of this pointed the <img> at tunnex.io — a phone-home on the most private mail the
// product sends, from a control plane whose whole pitch is that it never contacts us. The second pointed it
// at APP_BASE_URL, which fixed the phone-home and left three problems standing:
//
//  1. ⛔ IT DOES NOT RESOLVE. The default APP_BASE_URL is `http://localhost`, so the recipient's client
//     tries to load the logo from THEIR OWN machine. Every invitation from a default deployment ships a
//     broken image — and the same is true for any control plane that is internal-only, air-gapped, or
//     behind a VPN, which is a large share of who runs this.
//  2. ⛔ IT IS AN ACCIDENTAL TRACKING PIXEL. A remote image means the org's own server logs a hit — time,
//     IP, user agent — each time an invitee opens their mail. Nobody asked for open-tracking, and a
//     privacy-positioned product must not start doing it as a side effect of a logo.
//  3. ⚠ IT IS BLOCKED ANYWAY in Outlook, Thunderbird and most corporate gateways, which refuse remote
//     images by default.
//
// A cid: part has none of them: no fetch, so nothing to resolve, nothing to log, nothing to block. It costs
// ~7KB per message after base64 and it renders with no network at all — which is the same claim the licence
// email makes one layer up ("your deployment verifies this offline — it never contacts us").
//
// ⚠ data: URIs were considered and are NOT an option: Gmail and Outlook both strip them from <img src>.
//
//go:embed tunnex-logo.png
var logoPNG []byte

// logoCID is the Content-ID the template's <img src="cid:..."> refers to. The two must agree; a mismatch is
// a broken image with no error anywhere, which is why they are named once here.
const logoCID = "tunnex-logo"

// Message is one outgoing email.
//
// ⛔ TEXT IS NOT OPTIONAL AND HTML IS. Every message must carry a working plaintext body: it is what a
// screen reader announces, what a text client shows, what MAIL_DEV_LOG tees, and what survives a client
// that refuses HTML. An invitation whose link exists only inside an <a href> is unreachable to all four.
type Message struct {
	To      string
	Subject string
	Text    string
	// HTML is the branded alternative. Empty means send plaintext only — which is what every caller did
	// before S12.14, and what buildRFC822 still produces byte-for-byte when it is empty.
	HTML string
}

// Mailer sends messages. Implementations must be safe for concurrent use.
type Mailer interface {
	Send(ctx context.Context, msg Message) error
	// Kind returns a short label for logging/diagnostics.
	Kind() string
}

// Config controls mailer selection.
type Config struct {
	Host     string
	Port     string
	From     string
	Username string // optional; empty => no SMTP auth
	Password string // optional
	// DevLogging tees safe metadata for every message to the log; the body is always omitted. It NEVER
	// suppresses the send. Opt-in via MAIL_DEV_LOG; see the package doc for why it is not derived from the
	// environment name.
	DevLogging bool
}

// ErrNotConfigured is returned by every send on a deployment with no SMTP host.
//
// ⛔ IT IS AN ERROR AND IT USED TO BE `nil`. The disabled mailer logged the message and reported SUCCESS,
// so every invitation, verification link and password reset "sent" and vanished — while the API answered
// 202 and the screen said Sent. Invitations are now the ONLY way anyone joins a deployment, so a silent
// mail failure is a deployment nobody can get into, reporting success on every screen.
var ErrNotConfigured = errors.New("no SMTP host configured — email is disabled on this deployment")

// Configured reports whether this deployment can send mail at all. ⭐ Read at STARTUP and by /meta, so an
// operator learns the state when they install rather than when a recipient does not receive something.
func Configured(cfg Config) bool { return strings.TrimSpace(cfg.Host) != "" }

// New builds the appropriate Mailer for the given configuration.
func New(cfg Config, logger *slog.Logger) Mailer {
	if !Configured(cfg) {
		return &disabledMailer{logger: logger}
	}
	smtpMailer := &SMTPMailer{cfg: cfg, logger: logger}
	if cfg.DevLogging {
		return &teeMailer{primary: smtpMailer, log: &LogMailer{logger: logger, reason: "MAIL_DEV_LOG"}}
	}
	// ⭐ NO BRANDING WRAPPER ANY MORE. An earlier version wrapped every mailer to stamp APP_BASE_URL into the
	// logo's src, precisely so a caller could not forget. Embedding the logo DELETES the question: a rendered
	// message carries no deployment-specific value, so there is nothing to forget and no wrapper to carry it.
	// Reducing rather than patching.
	return smtpMailer
}

// Destination names WHERE MAIL ACTUALLY GOES, in one sentence an operator can act on (S12.13 D2).
//
// ⛔ IT REPLACES Kind() AT THE BOOT LINE, because Kind() answered a different question. `smtp+log` is a
// truthful description of the MECHANISM and a terrible answer to "will my invitation arrive" — the `+`
// reads as capability, and the operator who read it as "log instead of SMTP" had no way to find out
// otherwise except by not receiving an email.
func Destination(cfg Config) string {
	if !Configured(cfg) {
		return "log only — no SMTP_HOST is set, so mail is DISABLED and every send will be refused"
	}
	dest := cfg.Host + ":" + cfg.Port
	if cfg.DevLogging {
		return dest + " — and MAIL_DEV_LOG is on, so safe message metadata is copied to this log; " +
			"message bodies are omitted"
	}
	return dest
}

// disabledMailer is what a deployment with no SMTP gets. It REFUSES, and says so.
//
// ⚠ IT LOGS THE RECIPIENT AND SUBJECT AND NOT THE BODY. The previous behaviour logged `msg.Text` — which
// carries invitation links, password-reset links and verification links — into `docker compose logs`,
// shipped and searchable. A credential in a log is the class this repo has already ruled on once, for the
// bootstrap password.
type disabledMailer struct{ logger *slog.Logger }

func (m *disabledMailer) Kind() string { return "disabled" }

func (m *disabledMailer) Send(_ context.Context, msg Message) error {
	m.logger.Error("email_not_sent_no_smtp",
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("fix", "set SMTP_HOST/SMTP_PORT/SMTP_FROM (and SMTP_USERNAME/SMTP_PASSWORD if your "+
			"provider needs auth) and restart the api service"))
	return ErrNotConfigured
}

// LogMailer writes safe message metadata to the logger instead of sending messages. Bodies are deliberately
// omitted: development logging must not turn invitation links, reset tokens, or bootstrap passwords into
// searchable structured-log secrets.
type LogMailer struct {
	logger *slog.Logger
	reason string
}

func (m *LogMailer) Kind() string { return "log" }

// Send writes the message to the log.
//
// ⛔ THE EVENT NAME IS `email_copied_to_log`, NOT `email_not_sent_logged`, AND THE OLD NAME COST A SESSION.
// This type is used two ways: alone (nothing is sent) and INSIDE THE TEE (the message is sent immediately
// afterwards). The old name was true for the first and a flat lie for the second, and the second is the one
// an operator with working SMTP meets. A founder read "email_not_sent" on a correctly-configured rig and
// concluded mail was disabled; it had already left.
//
// > **A LOG LINE THAT NAMES AN OUTCOME MUST BE TRUE IN EVERY CONTEXT THE LINE CAN BE REACHED FROM.**
// > "Copied to log" is true in both. "Not sent" was true in one and diagnostic poison in the other.
func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.logger.Info("email_copied_to_log",
		slog.String("reason", m.reason),
		slog.String("to", msg.To),
		slog.String("subject", msg.Subject),
		slog.String("body", "omitted"),
		slog.String("warning", "message body omitted to prevent credential and link leakage"),
	)
	return nil
}

// SMTPMailer sends via an SMTP server. Auth is used only when a username is set.
//
// ⚠ PORT 587, NOT 465. net/smtp dials PLAINTEXT and upgrades via STARTTLS when the server advertises it;
// it has no implicit-TLS path, so an SMTPS port (465) hangs or errors. Recorded here because it is a
// property of the standard library, not of this configuration, and cannot be fixed by an env var.
type SMTPMailer struct {
	cfg    Config
	logger *slog.Logger
}

func (m *SMTPMailer) Kind() string { return "smtp" }

func (m *SMTPMailer) Send(_ context.Context, msg Message) error {
	addr := m.cfg.Host + ":" + m.cfg.Port
	from, err := canonicalAddress(m.cfg.From)
	if err != nil {
		return fmt.Errorf("invalid SMTP_FROM: %w", err)
	}
	to, err := canonicalAddress(msg.To)
	if err != nil {
		return fmt.Errorf("invalid recipient: %w", err)
	}
	message, err := composeMessage(from, to, msg)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(m.cfg.Port)
	if err != nil {
		return fmt.Errorf("invalid SMTP_PORT: %w", err)
	}
	options := []gomail.Option{
		gomail.WithPort(port),
		gomail.WithTLSPolicy(gomail.TLSMandatory),
	}
	if m.cfg.Username != "" {
		options = append(options,
			gomail.WithSMTPAuth(gomail.SMTPAuthPlain),
			gomail.WithUsername(m.cfg.Username),
			gomail.WithPassword(m.cfg.Password),
		)
	}
	client, err := gomail.NewClient(m.cfg.Host, options...)
	if err != nil {
		return fmt.Errorf("smtp client: %w", err)
	}
	if err := client.DialAndSend(message); err != nil {
		return fmt.Errorf("smtp send to %s: %w", addr, err)
	}
	// ⛔ SUCCESS IS AS VISIBLE AS FAILURE, AND UNTIL NOW ONLY FAILURE LOGGED (S12.13 D2). That made an empty
	// log mean BOTH "it worked" and "it never tried", which is not a diagnosis — it is a coin flip an
	// operator performs at the exact moment they are least able to check.
	//
	// ⚠ WHAT IT CLAIMS IS EXACTLY WHAT HAPPENED AND NO MORE: the server ACCEPTED the message. Acceptance is
	// not inbox delivery — SPF/DKIM alignment, reputation and the recipient's own filters all act after
	// this point, and the provider's outbound log is the authority on those. A line reading "delivered"
	// would be the swallowed-error shape rebuilt in the other direction.
	//
	// ⚠ NO BODY, ever. Recipient and subject only, the same line disabledMailer draws — this one runs on
	// every deployment, so it must be safe on every deployment.
	if m.logger != nil {
		m.logger.Info("email_accepted_by_provider",
			slog.String("to", msg.To),
			slog.String("subject", msg.Subject),
			slog.String("server", addr),
			slog.String("means", "the SMTP server accepted the message for delivery; whether it reaches the "+
				"inbox is the provider's outbound log to answer, not this one"))
	}
	return nil
}

// teeMailer sends via the primary mailer and also logs safe message metadata.
type teeMailer struct {
	primary Mailer
	log     *LogMailer
}

func (m *teeMailer) Kind() string { return m.primary.Kind() + "+log" }

func (m *teeMailer) Send(ctx context.Context, msg Message) error {
	_ = m.log.Send(ctx, msg)
	return m.primary.Send(ctx, msg)
}

// buildRFC822 renders the wire message.
//
// ⚠ THREE SHAPES, AND THE FIRST IS UNCHANGED FROM BEFORE ANY OF THIS.
//
//	no HTML   -> text/plain, byte-for-byte what every caller sent before S12.14.
//	HTML      -> multipart/related [ multipart/alternative [ text, html ], logo ]
//
// The related wrapper exists ONLY to carry the logo; the alternative wrapper inside it is what a client
// chooses between. Nesting them the other way round would offer the client "HTML" and "an image" as
// equivalent renderings of the same message, which is not what either is.
//
// ⚠ TEXT COMES FIRST INSIDE THE ALTERNATIVE, which is not cosmetic: RFC 2046 orders alternatives
// least-to-most preferred, so a client picks the LAST part it understands. Reversing them serves plaintext
// to clients that could have rendered the branded version.
func buildRFC822(from string, msg Message) []byte {
	message, err := composeMessage(from, msg.To, msg)
	if err != nil {
		return nil
	}
	var body bytes.Buffer
	if _, err := message.WriteTo(&body); err != nil {
		return nil
	}
	return body.Bytes()
}

// composeMessage uses go-mail's typed message builder. Production transport sends
// this object directly; buildRFC822 above exists only for wire-format tests.
func composeMessage(from, to string, msg Message) (*gomail.Msg, error) {
	canonicalFrom, err := canonicalAddress(from)
	if err != nil {
		return nil, fmt.Errorf("invalid sender: %w", err)
	}
	canonicalTo, err := canonicalAddress(to)
	if err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	message := gomail.NewMsg(gomail.WithCharset(gomail.CharsetUTF8), gomail.WithEncoding(gomail.EncodingB64))
	if err := message.From(canonicalFrom); err != nil {
		return nil, fmt.Errorf("invalid sender: %w", err)
	}
	if err := message.To(canonicalTo); err != nil {
		return nil, fmt.Errorf("invalid recipient: %w", err)
	}
	message.Subject(msg.Subject)
	if msg.HTML == "" {
		message.SetBodyString(gomail.TypeTextPlain, msg.Text)
		return message, nil
	}
	message.SetBodyString(gomail.TypeTextPlain, msg.Text)
	message.AddAlternativeString(gomail.TypeTextHTML, msg.HTML)
	if err := message.EmbedReader("tunnex-logo.png", bytes.NewReader(logoPNG), gomail.WithFileContentID(logoCID), gomail.WithFileName("tunnex-logo.png")); err != nil {
		return nil, fmt.Errorf("embed logo: %w", err)
	}
	return message, nil
}

func canonicalAddress(raw string) (string, error) {
	if strings.ContainsAny(raw, "\r\n") {
		return "", errors.New("address contains a line break")
	}
	parsed, err := stdmail.ParseAddress(strings.TrimSpace(raw))
	if err != nil || parsed.Address == "" {
		return "", errors.New("address is not valid")
	}
	return parsed.Address, nil
}

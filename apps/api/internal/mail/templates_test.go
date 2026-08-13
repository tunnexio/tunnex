package mail

import (
	"encoding/base64"
	"io"
	"mime/quotedprintable"
	"strings"
	"testing"
)

// decodeQP undoes the wire encoding so an assertion can be made about what the RECIPIENT sees.
//
// ⛔ ASSERTING ON THE RAW WIRE BYTES WOULD BE ASSERTING THE WRONG THING. quoted-printable rewrites `=` as
// `=3D` and may soft-break a long URL across lines, so `strings.Contains(raw, url)` is false on a perfectly
// correct message. The question is whether the URL survives DECODING, which is what the client does.
func decodeQP(t *testing.T, s string) string {
	t.Helper()
	out, err := io.ReadAll(quotedprintable.NewReader(strings.NewReader(s)))
	if err != nil {
		t.Fatalf("decode quoted-printable: %v", err)
	}
	return string(out)
}

func decodeBase64Bodies(t *testing.T, s string) string {
	t.Helper()
	const marker = "Content-Transfer-Encoding: base64\r\n"
	var decoded strings.Builder
	for rest := s; ; {
		i := strings.Index(rest, marker)
		if i < 0 {
			break
		}
		rest = rest[i+len(marker):]
		headerEnd := strings.Index(rest, "\r\n\r\n")
		if headerEnd < 0 {
			break
		}
		rest = rest[headerEnd+4:]
		end := strings.Index(rest, "\r\n--")
		if end < 0 {
			end = len(rest)
		}
		encoded := strings.ReplaceAll(rest[:end], "\r\n", "")
		body, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			t.Fatalf("decode base64 body: %v", err)
		}
		decoded.Write(body)
		rest = rest[end:]
	}
	return decoded.String()
}

const acceptURL = "https://vpn.acme.test/accept-invite?token=SECRET-TOKEN"

// TestEveryTemplateCarriesAWorkingPlaintextBody — ⛔ THE HALF THAT SILENTLY DISAPPEARS.
//
// The HTML body is the one a recipient usually sees. The PLAINTEXT is what a screen reader announces, what
// a text client shows, what MAIL_DEV_LOG tees, and what survives a client that strips HTML. A link that
// exists only inside an <a href> is unreachable to all four — and the plaintext half is the twin of the
// SMTP-less delivery path this product ships on purpose.
func TestEveryTemplateCarriesAWorkingPlaintextBody(t *testing.T) {
	for _, tc := range []struct {
		name string
		msg  Message
		link string
	}{
		{"invite", InviteMessage("a@b.test", acceptURL, "Acme"), acceptURL},
		{"resend", ResendInviteMessage("a@b.test", acceptURL, "Acme"), acceptURL},
		{"reset", PasswordResetMessage("a@b.test", "https://x.test/reset-password?token=R"), "https://x.test/reset-password?token=R"},
		{"verify", VerifyEmailMessage("a@b.test", "https://x.test/verify-email?token=V"), "https://x.test/verify-email?token=V"},
		{"account-exists", AccountExistsMessage("a@b.test", "https://x.test/reset-password"), "https://x.test/reset-password"},
	} {
		if tc.msg.Text == "" {
			t.Fatalf("%s: no plaintext body", tc.name)
		}
		if !strings.Contains(tc.msg.Text, tc.link) {
			t.Fatalf("%s: the plaintext must carry the URL IN FULL — a recipient reading text has no <a href> "+
				"to follow:\n%s", tc.name, tc.msg.Text)
		}
		// ⚠ AND THE HTML CARRIES IT AS TEXT TOO, beside the button. Some clients render a styled anchor as
		// bare label with no target, and a recipient who distrusts buttons in email is exactly the recipient
		// a security product must still be able to serve.
		if !strings.Contains(tc.msg.HTML, tc.link) {
			t.Fatalf("%s: the HTML must show the URL, not only link it", tc.name)
		}
		if tc.msg.Subject == "" {
			t.Fatalf("%s: no subject", tc.name)
		}
	}
	// The MFA notice deliberately has NO link — see its doc comment. It must still have both bodies.
	m := MFAResetMessage("a@b.test")
	if m.Text == "" || m.HTML == "" {
		t.Fatal("the MFA reset notice needs both bodies even though it carries no link")
	}
	if strings.Contains(m.HTML, "<a href=\"http") {
		t.Fatal("a security-alert email must not teach the recipient to click a link — that is the shape a " +
			"phishing copy of it takes")
	}
}

func TestBuildRFC822SanitizesHeaderInjection(t *testing.T) {
	if got := buildRFC822("from@example.test\r\nX-Injected: yes", Message{
		To:      "to@example.test\nBcc: attacker@example.test",
		Subject: "subject\r\nX-Injected: yes",
		Text:    "body",
	}); got != nil {
		t.Fatalf("invalid sender/recipient should be rejected")
	}
	raw := string(buildRFC822("Tunnex\r\nX-Injected: yes <from@example.test>", Message{
		To:      "to@example.test",
		Subject: "subject\r\nX-Injected: yes",
		Text:    "body",
	}))
	if raw != "" {
		t.Fatalf("sender display-name injection should be rejected")
	}
	if strings.Contains(raw, "\r\nX-Injected:") {
		t.Fatalf("header injection survived: %q", raw)
	}
	raw = string(buildRFC822("from@example.test", Message{
		To:      "to@example.test",
		Subject: "subject\r\nX-Injected: yes",
		Text:    "body",
	}))
	headerEnd := strings.Index(raw, "\r\n\r\n")
	if headerEnd < 0 || strings.Contains(raw[:headerEnd], "\r\nX-Injected:") {
		t.Fatalf("subject injection escaped into headers: %q", raw)
	}
}

func TestBuildRFC822EncodesBodyBoundaries(t *testing.T) {
	raw := string(buildRFC822("from@example.test", Message{
		To:      "to@example.test",
		Subject: "hello",
		Text:    "before\r\nX-Injected: yes\r\nafter",
	}))
	headerEnd := strings.Index(raw, "\r\n\r\n")
	if headerEnd < 0 || strings.Contains(raw[:headerEnd], "\r\nX-Injected:") {
		t.Fatalf("body boundary escaped into a header: %q", raw)
	}
	decoded := decodeBase64Bodies(t, raw)
	if !strings.Contains(decoded, "before\r\nX-Injected: yes\r\nafter") {
		t.Fatalf("body did not survive base64 encoding: %q", raw)
	}
}

// TestUserInputIsEscapedInHTMLAndRawInText — ⛔ THE INVARIANT A PORT LOSES FIRST.
//
// The reference's own comment says "never user input without escaping there". renderShell cannot tell an
// intended <strong> from an injected <script>, so escaping belongs at the template, where the value's
// origin is known. This drives an org name — a field an admin types — all the way through.
//
// ⚠ AND THE PLAINTEXT MUST NOT BE ESCAPED. Entities in plain text are the bug, not the fix: a reader of
// the text half should see the org's actual name, not `&lt;script&gt;`.
func TestUserInputIsEscapedInHTMLAndRawInText(t *testing.T) {
	hostile := `<script>alert('x')</script>`
	m := InviteMessage("a@b.test", acceptURL, hostile)

	if strings.Contains(m.HTML, "<script>") {
		t.Fatal("an org name reached the HTML body unescaped — renderShell trusts its input, so a template " +
			"that forgets escapeHTML is the whole vulnerability")
	}
	if !strings.Contains(m.HTML, "&lt;script&gt;") {
		t.Fatalf("the org name must appear ESCAPED rather than dropped:\n%s", m.HTML)
	}
	if !strings.Contains(m.Text, hostile) {
		t.Fatal("the plaintext half must carry the name verbatim — HTML entities in plain text are a defect")
	}
}

// TestEscapeOrderDoesNotDoubleEscape — & must be replaced first or every other entity is mangled.
func TestEscapeOrderDoesNotDoubleEscape(t *testing.T) {
	if got := escapeHTML("a<b&c"); got != "a&lt;b&amp;c" {
		t.Fatalf("escapeHTML mangled its own output: %q", got)
	}
}

// TestLogoTravelsWithTheMessageAndIsNeverFetched — the port's ONE deliberate divergence, and the reason it
// changed shape twice.
//
// ⛔ v1 POINTED AT tunnex.io: a phone-home on the most private mail the product sends.
// ⛔ v2 POINTED AT APP_BASE_URL: no phone-home, and three problems left standing — the DEFAULT is
// `http://localhost`, which resolves to the RECIPIENT's machine, so every invitation from a default
// deployment shipped a broken image; a remote fetch logs an open in the org's own access log, which is
// open-tracking nobody asked for; and Outlook and most corporate gateways block remote images anyway.
// ⭐ v3 EMBEDS IT. No fetch: nothing to resolve, nothing to log, nothing to block.
func TestLogoTravelsWithTheMessageAndIsNeverFetched(t *testing.T) {
	m := InviteMessage("a@b.test", acceptURL, "")
	if !strings.Contains(m.HTML, `src="cid:tunnex-logo"`) {
		t.Fatalf("the logo must be referenced by Content-ID:\n%s", m.HTML)
	}
	// ⛔ NO http(s) URL MAY POINT AT AN IMAGE ANYWHERE IN THE BODY. This is the assertion that would have
	// caught v1 and v2 alike, and it is deliberately broader than "does not mention tunnex.io".
	for _, bad := range []string{"src=\"http", "src='http", "/email/tunnex-logo"} {
		if strings.Contains(m.HTML, bad) {
			t.Fatalf("the message must fetch NOTHING when opened; found %q", bad)
		}
	}

	raw := string(buildRFC822("f@x.test", m))
	if !strings.Contains(raw, "multipart/related") {
		t.Fatal("an HTML message must be multipart/related so the logo can ride with it")
	}
	if !strings.Contains(raw, "Content-Id: tunnex-logo") {
		t.Fatal("the image part's Content-ID must match the src the HTML refers to — a mismatch is a broken " +
			"image with no error anywhere")
	}
	if !strings.Contains(raw, "Content-Disposition: inline") {
		t.Fatal("the logo must be offered as inline, not as an attachment")
	}
	if !strings.Contains(raw, "Content-Transfer-Encoding: base64") {
		t.Fatal("binary must be base64 on the wire")
	}
	// ⚠ RFC 2045 CAPS AN ENCODED LINE AT 76 CHARACTERS and SMTP caps any line at 998. A 7KB single-line
	// attachment violates both, and the servers that enforce it mangle or reject the message rather than
	// explaining why — a failure that would look like "the logo is broken" and be an envelope bug.
	for _, line := range strings.Split(raw, "\r\n") {
		if len(line) > 998 {
			t.Fatalf("a %d-character line will not survive SMTP", len(line))
		}
	}
	if !strings.Contains(raw, "iVBORw0KGgo") { // the PNG magic, base64-encoded
		t.Fatal("the embedded PNG is missing from the wire message")
	}
}

// TestPlainTextAndHTMLSurviveTheRelatedWrapper — the alternative must stay nested inside the related part.
//
// ⛔ NESTING THEM THE OTHER WAY ROUND would offer a client "the HTML" and "an image" as equivalent
// RENDERINGS of the same message, which neither is. related carries parts that belong together; alternative
// carries parts the client chooses between.
func TestPlainTextAndHTMLSurviveTheRelatedWrapper(t *testing.T) {
	raw := string(buildRFC822("f@x.test", InviteMessage("a@b.test", acceptURL, "")))
	relAt := strings.Index(raw, "multipart/related")
	altAt := strings.Index(raw, "multipart/alternative")
	if relAt < 0 || altAt < 0 || relAt > altAt {
		t.Fatalf("multipart/alternative must be nested INSIDE multipart/related: rel=%d alt=%d", relAt, altAt)
	}
	decoded := decodeBase64Bodies(t, raw)
	if !strings.Contains(decoded, acceptURL) {
		t.Fatal("the plaintext half must still carry the URL through the extra wrapper and the encoding")
	}
	if strings.Count(raw, "Content-Transfer-Encoding: base64") != 3 {
		t.Fatal("text, HTML, and logo parts must declare base64")
	}
}

// TestPlainTextMessagesAreUnchangedOnTheWire — the multipart branch must not touch callers that have no HTML.
func TestPlainTextMessagesAreUnchangedOnTheWire(t *testing.T) {
	raw := string(buildRFC822("f@x.test", Message{To: "a@b.test", Subject: "S", Text: "body"}))
	if strings.Contains(raw, "multipart") {
		t.Fatal("a message with no HTML must still be a bare text/plain message")
	}
	if !strings.Contains(raw, base64.StdEncoding.EncodeToString([]byte("body"))) {
		t.Fatalf("the plaintext wire format changed:\n%q", raw)
	}
}

// TestMultipartOrdersTextBeforeHTML — RFC 2046 orders alternatives least-to-most preferred.
//
// ⛔ A CLIENT PICKS THE LAST PART IT UNDERSTANDS. Reversing these serves plaintext to clients that could
// have rendered the branded version — a bug that looks like "the template didn't apply" and is really an
// ordering mistake in the envelope.
func TestMultipartOrdersTextBeforeHTML(t *testing.T) {
	raw := string(buildRFC822("f@x.test", InviteMessage("a@b.test", acceptURL, "")))
	if !strings.Contains(raw, "multipart/alternative") {
		t.Fatal("a message with both bodies must be multipart/alternative")
	}
	textAt := strings.Index(raw, "text/plain")
	htmlAt := strings.Index(raw, "text/html")
	if textAt < 0 || htmlAt < 0 || textAt > htmlAt {
		t.Fatalf("text/plain must come FIRST: text=%d html=%d", textAt, htmlAt)
	}
	if !strings.HasSuffix(strings.TrimRight(raw, "\r\n"), "--") {
		t.Fatal("the multipart body must be terminated by the closing boundary")
	}
}

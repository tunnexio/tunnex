package mail

import "strings"

// ⛔ A PORT OF tunnex-web's src/lib/email/{palette,layout}.ts, NOT A SECOND DESIGN.
//
// The marketing site already sends branded mail — the licence-key delivery is the reference the founder
// pointed at — while the product sent bare plaintext from the same domain. Two mails from `tunnex.io`, one
// designed and one not, and the undesigned one is the FIRST thing a new user ever receives from Tunnex.
//
// Values and structure are copied deliberately so the two stay recognisably one product. When the site's
// shell changes, this is the file that has to follow; that coupling is the cost of the decision and is
// cheaper than the two drifting into different-looking mail from one brand.
//
// ⛔ ONE DELIBERATE DIVERGENCE: THE LOGO TRAVELS WITH THE MESSAGE, IT IS NEVER FETCHED.
//
// The reference hard-codes `https://tunnex.io/email/tunnex-logo-2x.png`, which is right for a site we run
// and wrong for software other people run. Pointing it at the deployment's own APP_BASE_URL fixed the
// phone-home and left three problems standing — a default `http://localhost` that resolves to the
// RECIPIENT's machine, an accidental open-tracking pixel in the org's own logs, and remote images blocked
// by default in Outlook and most corporate gateways. See the embed note in mail.go.
//
// So the src is `cid:tunnex-logo` and the PNG rides in a multipart/related part. No fetch: nothing to
// resolve, nothing to log, nothing to block, and the mail renders with no network at all.
//
// ⚠ AND THE NONCE IS DROPPED. The reference stamps `Date.now()`/`Math.random()` into an HTML comment for
// its own CSP reporting; a mailed document has no CSP, and it would make this renderer nondeterministic and
// therefore untestable for no gain.

// emailPalette mirrors tunnex-web's src/lib/email/palette.ts.
//
// LITERALS, BECAUSE EMAIL CLIENTS CANNOT RESOLVE CSS CUSTOM PROPERTIES. This is the same narrow exception
// the reference documents — the values track the semantic tokens in packages/shared/generated/tokens.css
// and must be updated together.
const (
	emailBG        = "#0A0A0A"
	emailSurface   = "#141414"
	emailBorder    = "#2E2E2E"
	emailText      = "#EDEDEB"
	emailTextMuted = "#A9A9A6"
	emailPrimary   = "#B03A45"
	emailPrimaryFg = "#FFFFFF"
)

// shellOptions carries the parts of an email that are not its body.
type shellOptions struct {
	Title string
	// Preheader is the inbox preview line — the text a client shows beside the subject. Hidden in the
	// rendered body. Absent means the client picks the first words of the body, which for a link-led email
	// is a URL.
	Preheader string
}

// renderShell wraps a pre-rendered body in the Tunnex email shell.
//
// ⛔ bodyHTML IS TRUSTED AND EVERY CALLER MUST HAVE ESCAPED ALREADY. The reference carries the same
// invariant ("never user input without escaping there") and it is the one a port most easily loses: this
// function cannot tell an intentional <strong> from an injected <script>, so the escaping decision belongs
// where the value's origin is known. Use escapeHTML on anything that came from a user, an org name, or an
// email address.
func renderShell(bodyHTML string, opts shellOptions) string {
	preheader := ""
	if opts.Preheader != "" {
		preheader = `<span style="display:none;font-size:1px;color:` + emailBG +
			`;max-height:0;max-width:0;opacity:0;overflow:hidden;">` + escapeHTML(opts.Preheader) + `</span>`
	}
	return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>` + escapeHTML(opts.Title) + `</title>
</head>
<body style="margin:0;padding:0;background-color:` + emailBG + `;color:` + emailText + `;">
` + preheader + `
<div style="max-width:560px;margin:0 auto;padding:40px 20px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;">
  <div style="background-color:` + emailSurface + `;border:1px solid ` + emailBorder + `;border-radius:12px;padding:32px 28px;color:` + emailText + `;font-size:15px;line-height:1.6;">
    <div style="padding-bottom:24px;margin-bottom:24px;border-bottom:1px solid ` + emailBorder + `;text-align:center;">
      <img src="cid:tunnex-logo" alt="Tunnex" width="176" height="22" style="display:block;border:0;margin:0 auto;outline:none;">
    </div>
` + bodyHTML + `
  </div>
  <p style="color:` + emailTextMuted + `;font-size:12px;line-height:1.6;padding-top:20px;margin:0;text-align:center;">
    Tunnex · Connect everything. Trust nothing.<br>
    Questions? Reply to this email or write to <a href="mailto:support@tunnex.io" style="color:` + emailTextMuted + `;text-decoration:underline;">support@tunnex.io</a>.
  </p>
</div>
</body>
</html>`
}

// paragraph renders a body paragraph. The html argument is TRUSTED — see renderShell.
func paragraph(html string) string {
	return `<p style="margin:0 0 16px;color:` + emailText + `;font-size:15px;line-height:1.6;">` + html + `</p>`
}

// muted renders secondary text — the sentence a recipient reads only if something looks wrong.
func muted(html string) string {
	return `<p style="margin:16px 0 0;color:` + emailTextMuted + `;font-size:13px;line-height:1.5;">` + html + `</p>`
}

// button renders the primary call to action.
//
// ⚠ THE HREF IS ESCAPED HERE, unlike paragraph's body. A link target is never decorative markup, so there
// is no case where a caller wants raw HTML in it — which makes escaping unconditionally safe and removes
// the chance of a caller forgetting.
func button(href, label string) string {
	return `<p style="margin:28px 0 16px;text-align:center;"><a href="` + escapeHTML(href) +
		`" style="display:inline-block;background-color:` + emailPrimary + `;color:` + emailPrimaryFg +
		`;text-decoration:none;font-weight:600;font-size:15px;padding:12px 24px;border-radius:8px;">` +
		escapeHTML(label) + `</a></p>`
}

// escapeHTML is the reference's five replacements, in the same order.
//
// ⛔ & FIRST, ALWAYS. Replacing it after the others would double-escape their output (`&lt;` becoming
// `&amp;lt;`), which is a rendering bug in the harmless direction and a signal that the order was not
// thought about in the dangerous one.
func escapeHTML(v string) string {
	v = strings.ReplaceAll(v, "&", "&amp;")
	v = strings.ReplaceAll(v, "<", "&lt;")
	v = strings.ReplaceAll(v, ">", "&gt;")
	v = strings.ReplaceAll(v, `"`, "&quot;")
	v = strings.ReplaceAll(v, "'", "&#39;")
	return v
}

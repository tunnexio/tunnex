package mail

import "strings"

// BootstrapAdminMessage delivers the one-time first-run credential. The password is intentionally present
// only in this SMTP message and the operator-facing stdout banner; callers must never log the Message body.
func BootstrapAdminMessage(to, password string) Message {
	return Message{
		To:      to,
		Subject: "Your Tunnex administrator credential",
		Text: strings.Join([]string{
			"Your Tunnex deployment has created its first administrator account.",
			"",
			"Sign in with:",
			"Email: " + to,
			"Password: " + password,
			"",
			"This password is one-time. Tunnex will require you to choose a new password immediately after sign-in.",
			"If you did not just install Tunnex, contact the person who manages this server.",
		}, "\n"),
		HTML: renderShell(
			paragraph("Your Tunnex deployment has created its first administrator account.")+
				paragraph("<strong>Email:</strong> "+escapeHTML(to)+"<br><strong>Password:</strong> "+escapeHTML(password))+
				paragraph("This password is one-time. Tunnex will require you to choose a new password immediately after sign-in.")+
				muted("If you did not just install Tunnex, contact the person who manages this server."),
			shellOptions{Title: "Your Tunnex administrator credential", Preheader: "Your one-time first-run password."},
		),
	}
}

// Every product email, in one file, each returning a Message with BOTH bodies.
//
// ⛔ THE PLAINTEXT IS WRITTEN FIRST AND IT CARRIES THE LINK IN FULL. The HTML half is the one a recipient
// usually sees and the one that can silently fail — a client that strips HTML, a screen reader, a text
// client, the MAIL_DEV_LOG tee. An invitation whose URL exists only inside an <a href> is unreachable to
// every one of them, and the plaintext half is the twin of the SMTP-less delivery path the product already
// ships deliberately.
//
// ⛔ AND EVERY INTERPOLATED VALUE PASSES THROUGH escapeHTML ON THE HTML SIDE. Org names, display names and
// email addresses reach these functions from user input; renderShell cannot tell an intended <strong> from
// an injected <script>, so the escaping belongs here, where the value's origin is known. The plaintext side
// is deliberately NOT escaped — entities in plain text are the bug, not the fix.

// InviteMessage is the mail a new member receives. It is the FIRST thing anyone ever receives from Tunnex,
// which is the argument for it being branded at all.
func InviteMessage(to, acceptURL, orgName string) Message {
	where := "an organization on Tunnex"
	whereHTML := where
	if strings.TrimSpace(orgName) != "" {
		where = orgName + " on Tunnex"
		whereHTML = "<strong>" + escapeHTML(orgName) + "</strong> on Tunnex"
	}
	return Message{
		To:      to,
		Subject: "You're invited to Tunnex",
		Text: strings.Join([]string{
			"You've been invited to join " + where + ".",
			"",
			"Open this link to set your password and get in:",
			acceptURL,
			"",
			"The link works once and expires. If you were not expecting this, ignore it —",
			"nothing happens until you open it.",
		}, "\n"),
		HTML: renderShell(
			paragraph("You've been invited to join "+whereHTML+".")+
				paragraph("Open the link below to set your password and get in.")+
				button(acceptURL, "Accept the invitation")+
				// ⚠ THE URL IN FULL, BESIDE THE BUTTON. A recipient who distrusts a button in an email is
				// exactly the recipient a security product should be able to satisfy — and some clients
				// render buttons as bare text with no href at all.
				muted("Or paste this into your browser:<br>"+escapeHTML(acceptURL))+
				muted("The link works once and expires. If you were not expecting this, ignore it — nothing happens until you open it."),
			shellOptions{
				Title:     "You're invited to Tunnex",
				Preheader: "Set your password and get in.",
			},
		),
	}
}

// ResendInviteMessage is the same invitation, sent again, and it says so.
//
// ⚠ IT IS A DIFFERENT SUBJECT ON PURPOSE. An identical subject arriving twice reads as a duplicate and gets
// ignored — and the resent link is a NEW token, so ignoring it in favour of the first one means clicking a
// link that no longer works.
func ResendInviteMessage(to, acceptURL, orgName string) Message {
	m := InviteMessage(to, acceptURL, orgName)
	m.Subject = "Your Tunnex invitation"
	m.Text = "Here is your Tunnex invitation again. This link REPLACES any earlier one.\n\n" + m.Text
	m.HTML = strings.Replace(m.HTML,
		paragraph("Open the link below to set your password and get in."),
		paragraph("Here is your invitation again. <strong>This link replaces any earlier one</strong> — an older link will no longer work."),
		1)
	return m
}

// PasswordResetMessage carries a reset link.
func PasswordResetMessage(to, resetURL string) Message {
	return Message{
		To:      to,
		Subject: "Reset your Tunnex password",
		Text: strings.Join([]string{
			"Someone asked to reset the password for this Tunnex account.",
			"",
			"Open this link to choose a new one:",
			resetURL,
			"",
			"The link works once and expires shortly. If this was not you, ignore this email —",
			"your password has not changed and nothing has happened to your account.",
		}, "\n"),
		HTML: renderShell(
			paragraph("Someone asked to reset the password for this Tunnex account.")+
				button(resetURL, "Choose a new password")+
				muted("Or paste this into your browser:<br>"+escapeHTML(resetURL))+
				// ⛔ THE REASSURANCE IS THE POINT OF THIS EMAIL FOR EVERY RECIPIENT WHO DID NOT ASK FOR IT.
				// A reset mail arriving unrequested reads as a break-in; saying plainly that nothing has
				// happened is what stops a support ticket and a panicked password change.
				muted("The link works once and expires shortly. If this was not you, ignore this email — your password has not changed and nothing has happened to your account."),
			shellOptions{
				Title:     "Reset your Tunnex password",
				Preheader: "Choose a new password. If this was not you, nothing has happened.",
			},
		),
	}
}

// VerifyEmailMessage confirms an address belongs to the person using it.
func VerifyEmailMessage(to, verifyURL string) Message {
	return Message{
		To:      to,
		Subject: "Confirm your Tunnex email address",
		Text: strings.Join([]string{
			"Confirm this address so your Tunnex account can send and receive account mail.",
			"",
			"Open this link to confirm:",
			verifyURL,
			"",
			"If you were not expecting this, ignore it.",
		}, "\n"),
		HTML: renderShell(
			paragraph("Confirm this address so your Tunnex account can send and receive account mail.")+
				button(verifyURL, "Confirm this address")+
				muted("Or paste this into your browser:<br>"+escapeHTML(verifyURL))+
				muted("If you were not expecting this, ignore it."),
			shellOptions{
				Title:     "Confirm your Tunnex email address",
				Preheader: "One click to confirm this address.",
			},
		),
	}
}

// MFAResetMessage tells someone an administrator switched their second factor off.
//
// ⛔ NO LINK AND NO BUTTON, DELIBERATELY. Every other mail here asks the recipient to follow a link; this
// one tells them something already happened to their account and points them at a HUMAN. A "secure your
// account" link in a security-alert email is precisely the shape a phishing copy of this email takes, and
// the recipient who learns to click it here is the one who clicks it there.
func MFAResetMessage(to string) Message {
	return Message{
		To:      to,
		Subject: "Your two-factor authentication was reset",
		Text: strings.Join([]string{
			"An administrator reset the two-factor authentication (MFA) on your Tunnex account.",
			"",
			"If your organization requires MFA, you will be asked to set it up again at your next sign-in.",
			"",
			"If you did not expect this, contact your administrator immediately — someone who can reset",
			"your second factor can sign in as you.",
		}, "\n"),
		HTML: renderShell(
			paragraph("An administrator reset the two-factor authentication (MFA) on your Tunnex account.")+
				paragraph("If your organization requires MFA, you will be asked to set it up again at your next sign-in.")+
				muted("If you did not expect this, <strong>contact your administrator immediately</strong> — someone who can reset your second factor can sign in as you."),
			shellOptions{
				Title:     "Your two-factor authentication was reset",
				Preheader: "An administrator reset MFA on your account.",
			},
		),
	}
}

// AccountExistsMessage answers a signup for an address that already has an account.
//
// ⚠ IT IS SENT TO THE ADDRESS, NEVER REPORTED TO THE SIGNUP FORM. That asymmetry is the no-oracle rule:
// the form must not reveal whether an address is registered, so the only place that fact may surface is
// the mailbox of whoever owns it.
func AccountExistsMessage(to, resetURL string) Message {
	return Message{
		To:      to,
		Subject: "Your Tunnex account",
		Text: strings.Join([]string{
			"You already have a Tunnex account with this address.",
			"",
			"If you did not just try to sign up, you can ignore this — nothing has changed.",
			"",
			"Forgot your password? Reset it here:",
			resetURL,
		}, "\n"),
		HTML: renderShell(
			paragraph("You already have a Tunnex account with this address.")+
				paragraph("If you did not just try to sign up, you can ignore this — nothing has changed.")+
				button(resetURL, "Reset your password")+
				muted("Or paste this into your browser:<br>"+escapeHTML(resetURL)),
			shellOptions{
				Title:     "Your Tunnex account",
				Preheader: "You already have an account with this address.",
			},
		),
	}
}

// Package bootstrap mints the one account a fresh deployment needs to be usable at all.
//
// ⛔ THERE IS NO PUBLIC SIGNUP. A self-hosted control plane is owned by one company: everyone inside
// arrives by invitation, and an invitation has to be sent BY somebody. This package is that somebody's
// account, and it exists because without it a fresh install has no way in.
package bootstrap

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
	"github.com/tunnexio/tunnex/apps/api/internal/password"
)

// AdminEmail is the CP admin's address.
//
// ⚠ A LOCAL, NON-ROUTABLE ADDRESS ON PURPOSE. It is a login identifier, not a mailbox — nothing is ever
// sent to it, and choosing a real-looking domain would invite an operator to expect mail there.
const AdminEmail = "admin@tunnex.local"

// Store is the slice of sqlc this package needs. ⚠ An interface so the reds can drive both branches
// without a database — and the branch that matters is the one that does NOTHING.
type Store interface {
	CountUsers(ctx context.Context) (int64, error)
	CreateBootstrapAdmin(ctx context.Context, arg sqlc.CreateBootstrapAdminParams) (sqlc.User, error)
}

// EnsureAdmin creates the CP admin on a deployment that has never had a user, prints its one-time
// credential, and emails it when SMTP is configured. On every other start it does nothing at all.
//
// ⛔ IDEMPOTENT, AND THE NO-OP BRANCH IS THE SECURITY-CRITICAL ONE. A container restarts constantly —
// crashes, deploys, host reboots. Minting a second admin on any of those would be a privilege escalation
// with no actor behind it, and REPRINTING the first one's password would republish a live credential into
// logs that are shipped, aggregated and searched long after they were written.
//
// > ## ⛔ **A RESTART MUST NOT BE A SECURITY EVENT.**
//
// ⚠ THE CONDITION IS "HAS THIS DEPLOYMENT EVER HAD A USER", counting soft-deleted rows — self-closing in
// exactly the way `SetupComplete` is. Keyed on live users instead, deleting every account would reopen
// admin minting to whoever restarts the container next.
// ⚠ `out` IS INJECTABLE so the reds can assert what an OPERATOR SEES. The credential is no longer in any
// log line, so a test that read the logger would be testing the wrong surface.
func EnsureAdmin(ctx context.Context, q Store, logger *slog.Logger, out io.Writer, configuredEmail string, mailer mail.Mailer) error {
	n, err := q.CountUsers(ctx)
	if err != nil {
		return err
	}
	if n > 0 {
		return nil // already set up — mint nothing, print nothing
	}

	pw, err := generatePassword()
	if err != nil {
		return err
	}
	hash, err := password.Hash(pw)
	if err != nil {
		return err
	}
	email := configuredEmail
	if email == "" {
		email = AdminEmail
	}
	if _, err := q.CreateBootstrapAdmin(ctx, sqlc.CreateBootstrapAdminParams{
		Email: email, Name: "Control Plane Admin", PasswordHash: &hash,
	}); err != nil {
		return err
	}

	// ⭐ A BANNER ON STDOUT, NOT A STRUCTURED LOG LINE — AND THE DIFFERENCE IS WHETHER ANYONE SEES IT.
	//
	// The credential shipped first as a slog JSON record: correct, greppable, invisible. It scrolled past
	// inside a wall of identical JSON during `docker compose up`, and the operator had to be TOLD to grep
	// for it. A file was tried next and was worse — the path is INSIDE THE CONTAINER, so `cat` on the host
	// finds nothing, which is exactly how it failed the first time somebody used it.
	//
	// ⛔ SO IT IS PRINTED, FRAMED, AND ONCE. This is the only moment the plaintext exists — it is stored as
	// an argon2id hash and nowhere else, and there is no command that reprints it.
	// ⚠ THE STRUCTURED LINE RECORDS THE EVENT AND NOT THE CREDENTIAL. Logging it too would double the
	// exposure — a banner scrolls off a terminal, but log aggregation keeps a searchable copy forever.
	logger.Warn("bootstrap_admin_created", slog.String("email", email),
		slog.String("credential", "printed to stdout once; not stored in plaintext"))

	fmt.Fprint(out, "\n"+
		"==========================================================================\n"+
		"  TUNNEX - FIRST RUN: ADMINISTRATOR ACCOUNT\n"+
		"==========================================================================\n"+
		"\n"+
		"  email     "+email+"\n"+
		"  password  "+pw+"\n"+
		"\n"+
		"  SHOWN ONCE. Stored only as a hash; it cannot be reprinted. Copy it now.\n"+
		"\n"+
		"  You will be required to set your own password immediately, and this one\n"+
		"  stops working the moment you do.\n"+
		"\n"+
		"  Lost it before signing in? There is no recovery and no second admin -\n"+
		"  reset the deployment with:  docker compose down -v\n"+
		"\n"+
		"==========================================================================\n\n")

	if mailer != nil {
		if err := mailer.Send(ctx, mail.BootstrapAdminMessage(email, pw)); err != nil {
			// Keep the terminal banner as the safe recovery path. Never include the password or message body
			// in this log line: SMTP failures are routinely shipped to centralized logging.
			logger.Warn("bootstrap_admin_email_failed", slog.String("email", email), slog.String("error", err.Error()))
			fmt.Fprint(out, "  ⚠ The administrator email could not be sent. Use the one-time credential shown above.\n\n")
		} else {
			fmt.Fprint(out, "  administrator credential emailed to "+email+"\n\n")
		}
	}
	return nil
}

// generatePassword returns a high-entropy one-time credential.
//
// ⚠ 24 RANDOM BYTES, base64url — ~192 bits. It is never typed from memory, only copied from a log line, so
// there is no reason to trade entropy for memorability.
func generatePassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

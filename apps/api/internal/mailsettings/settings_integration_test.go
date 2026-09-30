package mailsettings

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/url"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/tunnexio/tunnex/apps/api/db"
	"github.com/tunnexio/tunnex/apps/api/internal/crypto"
	"github.com/tunnexio/tunnex/apps/api/internal/mail"
)

func TestEmailSettingsPersistenceIntegration(t *testing.T) {
	dsn := os.Getenv("TUNNEX_EMAIL_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("requires fresh isolated email test database")
	}
	u, err := url.Parse(dsn)
	if err != nil || !strings.HasPrefix(u.Path, "/tunnex_email_") {
		t.Fatal("refusing non-test database")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	var count int
	if err = pool.QueryRow(ctx, "SELECT count(*) FROM information_schema.tables WHERE table_schema='public'").Scan(&count); err != nil || count != 0 {
		t.Fatal("database must be empty")
	}
	if err = db.Up(dsn); err != nil {
		t.Fatal(err)
	}
	actor := uuid.New()
	if _, err = pool.Exec(ctx, "INSERT INTO users(id,email) VALUES($1,'admin@example.test')", actor); err != nil {
		t.Fatal(err)
	}
	sealer, _ := crypto.NewSealer(make([]byte, 32))
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	fallback := mail.Config{Host: "old.example.test", Port: "587", From: "old@example.test", Password: "old-secret-marker"}
	service := New(pool, sealer, fallback, logger)
	v, err := service.Get(ctx)
	if err != nil || v.Revision != 0 || v.Source != "installer" {
		t.Fatal("installer fallback", err)
	}
	in := Update{Enabled: true, Host: "new.example.test", Port: 587, From: "new@example.test", Username: "new", PasswordAction: "replace", Password: "new-secret-marker"}
	var results [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); _, results[i] = service.Save(ctx, actor, in) }(i)
	}
	wg.Wait()
	if (results[0] == nil) == (results[1] == nil) {
		t.Fatal("concurrent initial saves did not reject stale writer")
	}
	v, err = service.Get(ctx)
	if err != nil || v.Revision != 1 || v.Source != "server" || !v.PasswordConfigured {
		t.Fatal("saved state", err)
	}
	var raw string
	if err = pool.QueryRow(ctx, "SELECT config_ciphertext FROM server_email_settings").Scan(&raw); err != nil || strings.Contains(raw, "new-secret-marker") {
		t.Fatal("unencrypted settings", err)
	}
	replica := New(pool, sealer, mail.Config{}, logger)
	sends := 0
	replica.send = func(_ context.Context, cfg mail.Config, _ mail.Message) error {
		sends++
		if cfg.Host != "new.example.test" || cfg.Password != "new-secret-marker" {
			t.Fatal("replica did not use saved configuration")
		}
		return nil
	}
	if err = replica.Send(ctx, mail.Message{}); err != nil || sends != 1 {
		t.Fatal("replica send", err)
	}
	in.Revision = 1
	in.PasswordAction = "keep"
	in.Password = ""
	service.send = func(context.Context, mail.Config, mail.Message) error { return errors.New("secret-provider-error") }
	if err = service.Test(ctx, actor, "admin@example.test", in); err == nil || strings.Contains(err.Error(), "secret-provider-error") {
		t.Fatal("test error was not redacted")
	}
	after, _ := service.Get(ctx)
	if after.Revision != 1 {
		t.Fatal("test saved configuration")
	}
	if err = service.Test(ctx, actor, "admin@example.test", in); err == nil {
		t.Fatal("test throttle absent")
	}
	if _, err = pool.Exec(ctx, `CREATE FUNCTION email_audit_refuse() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='server.email_settings_updated' THEN RAISE EXCEPTION 'injected failure'; END IF; RETURN NEW; END $$; CREATE TRIGGER email_audit_refuse BEFORE INSERT ON audit_logs FOR EACH ROW EXECUTE FUNCTION email_audit_refuse()`); err != nil {
		t.Fatal(err)
	}
	in.Enabled = false
	if _, err = service.Save(ctx, actor, in); err == nil {
		t.Fatal("audit failure did not roll back")
	}
	after, _ = service.Get(ctx)
	if after.Revision != 1 || !after.Enabled {
		t.Fatal("partial save escaped rollback")
	}
	if _, err = pool.Exec(ctx, "DROP TRIGGER email_audit_refuse ON audit_logs; DROP FUNCTION email_audit_refuse()"); err != nil {
		t.Fatal(err)
	}
	v, err = service.Save(ctx, actor, in)
	if err != nil || v.Enabled || v.Host != "new.example.test" {
		t.Fatal("disable did not retain fields", err)
	}
	fresh := New(pool, sealer, fallback, logger)
	if configured, err := fresh.Configured(ctx); err != nil || configured {
		t.Fatal("restart reenabled old environment")
	}
	if _, err = pool.Exec(ctx, "UPDATE server_email_settings SET config_ciphertext='broken'"); err != nil {
		t.Fatal(err)
	}
	if err = replica.Send(ctx, mail.Message{}); err == nil || sends != 1 {
		t.Fatal("failed read used a fallback mailer")
	}
}

package sandboxrunner

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestRunnerExecutionCannotOutliveCertificate(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	certificateExpiry := time.Now().Add(time.Second)
	c := &Client{Store: LeaseStore{root}, certificate: tls.Certificate{Leaf: &x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: certificateExpiry}}}
	command := Command{ID: uuid.New(), Deadline: time.Now().Add(10 * time.Second), Payload: json.RawMessage(`{"Operation":"start"}`)}
	called := false
	_, err = c.ExecuteOne(context.Background(), command, func(ctx context.Context, _ Command) (json.RawMessage, error) {
		called = true
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(certificateExpiry) {
			t.Fatal("credential lifetime did not fence command", deadline)
		}
		return json.RawMessage(`{"ok":true}`), nil
	})
	if err != nil || !called {
		t.Fatal("valid bounded execution failed", err)
	}
	c.certificate.Leaf = &x509.Certificate{NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(-time.Second)}
	called = false
	if _, err := c.ExecuteOne(context.Background(), command, func(context.Context, Command) (json.RawMessage, error) { called = true; return nil, nil }); err != ErrUnavailable || called {
		t.Fatal("expired credential executed or replayed a cached receipt", err, called)
	}
}

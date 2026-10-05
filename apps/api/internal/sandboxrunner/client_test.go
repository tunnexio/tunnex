package sandboxrunner

import (
	"context"
	"encoding/json"
	"github.com/google/uuid"
	"os"
	"testing"
	"time"
)

func TestDurableCommandRetry(t *testing.T) {
	root, e := os.OpenRoot(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	defer root.Close()
	c := Client{Store: LeaseStore{root}}
	command := Command{uuid.New(), time.Now().Add(10 * time.Second), json.RawMessage(`{"op":"ping"}`)}
	calls := 0
	effect := func(context.Context, Command) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"ok":true}`), nil
	}
	if _, e = c.ExecuteOne(context.Background(), command, effect); e != nil {
		t.Fatal(e)
	}
	restarted := Client{Store: LeaseStore{root}}
	if _, e = restarted.ExecuteOne(context.Background(), command, effect); e != nil || calls != 1 {
		t.Fatal("duplicate effect", calls, e)
	}
	command.Payload = json.RawMessage(`{"op":"other"}`)
	if _, e = restarted.ExecuteOne(context.Background(), command, effect); e == nil || calls != 1 {
		t.Fatal("changed authority accepted")
	}
}

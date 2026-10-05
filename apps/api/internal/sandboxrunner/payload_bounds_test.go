package sandboxrunner

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestPayloadOversizeRejectedBeforeQueueAndEffects(t *testing.T) {
	payload, err := json.Marshal(strings.Repeat("x", PayloadLimit-1))
	if err != nil || len(payload) != PayloadLimit+1 || !json.Valid(payload) {
		t.Fatal("invalid oversized fixture", err)
	}
	broker, err := NewBroker("spiffe://tunnex/runner/payload-fixture")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if result, err := broker.Call(ctx, payload); !errors.Is(err, ErrInvalid) || result != nil {
		t.Fatal("oversized request was admitted", err)
	}
	broker.mu.Lock()
	queued := broker.pending != nil
	broker.mu.Unlock()
	if queued {
		t.Fatal("oversized request entered runner queue")
	}
	if response := request(broker, "/internal/sandbox-runners/v1/poll", nil, true); response.Code != http.StatusNoContent {
		t.Fatal("oversized request became available for execution", response.Code)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	client := Client{Store: LeaseStore{Root: root}}
	calls := 0
	command := Command{ID: uuid.New(), Deadline: time.Now().Add(5 * time.Second), Payload: payload}
	if _, err := client.ExecuteOne(ctx, command, func(context.Context, Command) (json.RawMessage, error) {
		calls++
		return json.RawMessage(`{"ok":true}`), nil
	}); !errors.Is(err, ErrInvalid) || calls != 0 {
		t.Fatal("oversized request reached an effect", calls, err)
	}
	if _, err := root.Stat(command.ID.String() + ".command.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("oversized request wrote durable execution state", err)
	}
	entries, err := os.ReadDir(root.Name())
	if err != nil || len(entries) != 0 {
		t.Fatal("oversized request changed runner control storage", err)
	}
}

func TestPayloadExactLimitDurableExecutionAndReplay(t *testing.T) {
	payload, err := json.Marshal(strings.Repeat("x", PayloadLimit-2))
	if err != nil || len(payload) != PayloadLimit {
		t.Fatal("invalid exact-bound fixture", err)
	}
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	command := Command{ID: uuid.New(), Deadline: time.Now().Add(10 * time.Second), Payload: payload}
	calls := 0
	effect := func(_ context.Context, got Command) (json.RawMessage, error) {
		calls++
		if len(got.Payload) != PayloadLimit {
			t.Fatal("exact-bound request truncated")
		}
		return json.RawMessage(`{"ok":true}`), nil
	}
	client := Client{Store: LeaseStore{Root: root}}
	reply, err := client.ExecuteOne(context.Background(), command, effect)
	if err != nil || reply.ID != command.ID || calls != 1 {
		t.Fatal("exact-bound request failed", calls, err)
	}
	restarted := Client{Store: LeaseStore{Root: root}}
	replayed, err := restarted.ExecuteOne(context.Background(), command, effect)
	if err != nil || replayed.ID != reply.ID || string(replayed.Payload) != string(reply.Payload) || calls != 1 {
		t.Fatal("exact-bound durable replay changed effect or response", calls, err)
	}
}

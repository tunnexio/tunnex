package sso

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

// flowState is the per-login server-side state, keyed by the opaque `state`
// value and returned via the callback. Held in Redis with a short TTL.
type flowState struct {
	Nonce    string    `json:"nonce"`
	Verifier string    `json:"verifier"` // PKCE code_verifier
	OrgID    uuid.UUID `json:"org_id"`
	Provider string    `json:"provider"`
}

// ErrFlowNotFound indicates an unknown/expired/replayed state.
var ErrFlowNotFound = errors.New("sso flow not found")

// FlowStore persists in-flight OIDC login state.
type FlowStore struct {
	rdb *redis.Client
	ttl time.Duration
}

// NewFlowStore builds a flow store (10-minute TTL is typical).
func NewFlowStore(rdb *redis.Client, ttl time.Duration) *FlowStore {
	return &FlowStore{rdb: rdb, ttl: ttl}
}

func flowKey(state string) string { return "ssoflow:" + state }

// Save stores the flow state under the opaque state value.
func (f *FlowStore) Save(ctx context.Context, state string, fs flowState) error {
	data, err := json.Marshal(fs)
	if err != nil {
		return err
	}
	return f.rdb.Set(ctx, flowKey(state), data, f.ttl).Err()
}

// Take atomically fetches and deletes the flow state (single-use — a replayed
// state fails).
func (f *FlowStore) Take(ctx context.Context, state string) (flowState, error) {
	data, err := f.rdb.GetDel(ctx, flowKey(state)).Bytes()
	if errors.Is(err, redis.Nil) {
		return flowState{}, ErrFlowNotFound
	}
	if err != nil {
		return flowState{}, err
	}
	var fs flowState
	if err := json.Unmarshal(data, &fs); err != nil {
		return flowState{}, ErrFlowNotFound
	}
	return fs, nil
}

package idpsync

import (
	"context"
	"encoding/json"
	"os"
	"strings"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

// fileDirectory is a FAKE, file-backed DirectoryProvider for box-walks / e2e — NOT for production.
// It RE-READS the JSON file on every call, so an operator can mutate the "directory" between sync
// legs (remove a member, flip a status, delete a group) and watch the reconciler converge — the
// same role a live Entra tenant plays, without one. It is wired only when TUNNEX_IDPSYNC_FAKE_DIR
// is set, behind a loud startup warning (see the enterprise wire).
//
// File shape:
//
//	{ "groups": { "grp-eng": [ {"external_id":"u-alice","email":"alice@acme.test","status":"active"} ] } }
//
// A group KEY that is absent → ErrGroupGone (deleted upstream). A member absent from a group's list
// → removed. status ∈ {active, disabled}.
type fileDirectory struct{ path string }

type fakeDirDoc struct {
	Groups map[string][]fakeMember `json:"groups"`
}

type fakeMember struct {
	ExternalID string `json:"external_id"`
	Email      string `json:"email"`
	Status     string `json:"status"`
}

// NewFileDirectory builds the file-backed fake provider.
func NewFileDirectory(path string) DirectoryProvider { return &fileDirectory{path: path} }

// FileProviderFactory returns a ProviderFactory that ignores the stored credential and serves the
// file — so the box-walk drives membership by editing JSON, no live Graph.
func FileProviderFactory(path string) ProviderFactory {
	return func(_ sqlc.IdpSyncConfig, _ string) (DirectoryProvider, error) {
		return NewFileDirectory(path), nil
	}
}

func (f *fileDirectory) load() (fakeDirDoc, error) {
	var doc fakeDirDoc
	b, err := os.ReadFile(f.path)
	if err != nil {
		return doc, err // a read error is TRANSIENT (fail-static), NOT ErrGroupGone
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		return doc, err
	}
	return doc, nil
}

func statusFromString(s string) UserStatus {
	if strings.EqualFold(s, "disabled") {
		return StatusDisabled
	}
	return StatusActive
}

func (f *fileDirectory) ListGroupMembers(_ context.Context, groupID string) ([]DirectoryMember, error) {
	doc, err := f.load()
	if err != nil {
		return nil, err
	}
	members, ok := doc.Groups[groupID]
	if !ok {
		return nil, ErrGroupGone // the group key is gone → authoritative empty
	}
	out := make([]DirectoryMember, 0, len(members))
	for _, m := range members {
		out = append(out, DirectoryMember{
			ExternalID: m.ExternalID,
			Email:      strings.ToLower(m.Email),
			Status:     statusFromString(m.Status),
		})
	}
	return out, nil
}

func (f *fileDirectory) ResolveUserStatus(_ context.Context, externalID string) (UserStatus, error) {
	doc, err := f.load()
	if err != nil {
		return StatusActive, err
	}
	for _, members := range doc.Groups {
		for _, m := range members {
			if m.ExternalID == externalID {
				return statusFromString(m.Status), nil
			}
		}
	}
	return StatusGone, nil // absent from every group → gone
}

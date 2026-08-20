package hostupgrade

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgtype"

	"github.com/tunnexio/tunnex/apps/api/db/sqlc"
)

const maxStateBytes = 4096

var (
	ErrUnavailable = errors.New("host updater unavailable")
	ErrBusy        = errors.New("another host upgrade is active")
	ErrInvalid     = errors.New("host upgrade state is invalid")
)

type Target struct {
	SourceSHA string
	Version   string
	Sequence  int64
}

type Status struct {
	RequestID      uuid.UUID
	State          string
	TargetSource   string
	TargetVersion  string
	BackupDump     string
	BackupManifest string
	ReasonCode     string
	UpdatedAt      time.Time
}

type AuditFunc func(context.Context, uuid.UUID, uuid.UUID, Target) error

type AuditStore interface {
	InsertAuditLog(context.Context, sqlc.InsertAuditLogParams) (sqlc.AuditLog, error)
}

func SQLAudit(q AuditStore) AuditFunc {
	return func(ctx context.Context, actor, requestID uuid.UUID, target Target) error {
		targetType := "control_plane_upgrade"
		targetID := requestID.String()
		metadata, err := json.Marshal(map[string]any{"source_sha": target.SourceSHA, "version": target.Version, "sequence": target.Sequence})
		if err != nil {
			return err
		}
		_, err = q.InsertAuditLog(ctx, sqlc.InsertAuditLogParams{
			OrgID: pgtype.UUID{}, ActorUserID: pgtype.UUID{Bytes: actor, Valid: true},
			Action: "control_plane.upgrade_requested", TargetType: &targetType, TargetID: &targetID, Metadata: metadata,
		})
		return err
	}
}

type Service struct {
	requestPath string
	statusPath  string
	audit       AuditFunc
	now         func() time.Time
}

func New(requestPath, statusPath string, audit AuditFunc) *Service {
	return &Service{requestPath: strings.TrimSpace(requestPath), statusPath: strings.TrimSpace(statusPath), audit: audit, now: time.Now}
}

func (s *Service) Available() bool {
	return s != nil && s.requestPath != "" && s.statusPath != ""
}

func (s *Service) Status() (Status, error) {
	if !s.Available() {
		return Status{}, ErrUnavailable
	}
	status, statusErr := readStatus(s.statusPath)
	pending, pendingErr := readRequest(s.requestPath)
	if pendingErr == nil {
		if statusErr == nil && status.RequestID == pending.RequestID {
			return status, nil
		}
		return pending, nil
	}
	if statusErr == nil {
		return status, nil
	}
	if errors.Is(statusErr, ErrUnavailable) && errors.Is(pendingErr, ErrUnavailable) {
		return Status{}, ErrUnavailable
	}
	return Status{}, ErrInvalid
}

func (s *Service) Request(ctx context.Context, actor uuid.UUID, target Target) (Status, bool, error) {
	if !s.Available() {
		return Status{}, false, ErrUnavailable
	}
	if actor == uuid.Nil || len(target.SourceSHA) != 40 || target.Sequence <= 0 || strings.TrimSpace(target.Version) == "" {
		return Status{}, false, ErrInvalid
	}
	if current, err := s.Status(); err == nil && current.TargetSource == target.SourceSHA &&
		(current.State == "requested" || current.State == "verifying" || current.State == "backing_up" ||
			current.State == "preflight" || current.State == "pulling" || current.State == "restarting" ||
			current.State == "health_check" || current.State == "healthy") {
		return current, false, nil
	}
	if _, err := os.Stat(s.requestPath); err == nil {
		return Status{}, false, ErrBusy
	} else if !errors.Is(err, os.ErrNotExist) {
		return Status{}, false, fmt.Errorf("inspect host upgrade request: %w", err)
	}

	requestID := uuid.New()
	createdAt := s.now().UTC()
	pending := s.requestPath + ".pending." + requestID.String()
	f, err := os.OpenFile(pending, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return Status{}, false, ErrBusy
		}
		return Status{}, false, fmt.Errorf("create host upgrade request: %w", err)
	}
	cleanup := true
	defer func() {
		_ = f.Close()
		if cleanup {
			_ = os.Remove(pending)
		}
	}()
	_, err = fmt.Fprintf(f, "request_id=%s\nsource_sha=%s\ntarget_version=%s\nsequence=%d\nrequested_by=%s\ncreated_at=%s\n",
		requestID, target.SourceSHA, target.Version, target.Sequence, actor, createdAt.Format(time.RFC3339))
	if err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return Status{}, false, fmt.Errorf("write host upgrade request: %w", err)
	}
	if s.audit == nil {
		return Status{}, false, errors.New("audit host upgrade request: recorder unavailable")
	}
	if err := s.audit(ctx, actor, requestID, target); err != nil {
		return Status{}, false, fmt.Errorf("audit host upgrade request: %w", err)
	}
	if err := os.Link(pending, s.requestPath); err != nil {
		if errors.Is(err, os.ErrExist) {
			return Status{}, false, ErrBusy
		}
		return Status{}, false, fmt.Errorf("publish host upgrade request: %w", err)
	}
	if err := os.Remove(pending); err != nil {
		return Status{}, false, fmt.Errorf("remove host upgrade staging request: %w", err)
	}
	cleanup = false
	return Status{RequestID: requestID, State: "requested", TargetSource: target.SourceSHA,
		TargetVersion: target.Version, UpdatedAt: createdAt}, true, nil
}

func readRequest(path string) (Status, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, ErrUnavailable
		}
		return Status{}, err
	}
	if info.Size() <= 0 || info.Size() > maxStateBytes {
		return Status{}, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, ErrUnavailable
		}
		return Status{}, err
	}
	defer f.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(f, maxStateBytes+1))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok || values[key] != "" {
			return Status{}, ErrInvalid
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Status{}, err
	}
	allowed := map[string]bool{"request_id": true, "source_sha": true, "target_version": true, "sequence": true, "requested_by": true, "created_at": true}
	if len(values) != len(allowed) {
		return Status{}, ErrInvalid
	}
	for key := range values {
		if !allowed[key] {
			return Status{}, ErrInvalid
		}
	}
	id, idErr := uuid.Parse(values["request_id"])
	actor, actorErr := uuid.Parse(values["requested_by"])
	created, timeErr := time.Parse(time.RFC3339, values["created_at"])
	sequence, sequenceErr := strconv.ParseInt(values["sequence"], 10, 64)
	if idErr != nil || actorErr != nil || actor == uuid.Nil || timeErr != nil || sequenceErr != nil || sequence <= 0 ||
		!validSourceSHA(values["source_sha"]) || strings.TrimSpace(values["target_version"]) == "" {
		return Status{}, ErrInvalid
	}
	return Status{RequestID: id, State: "requested", TargetSource: values["source_sha"], TargetVersion: values["target_version"], UpdatedAt: created}, nil
}

func validSourceSHA(value string) bool {
	if len(value) != 40 {
		return false
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

func readStatus(path string) (Status, error) {
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, ErrUnavailable
		}
		return Status{}, err
	}
	if info.Size() <= 0 || info.Size() > maxStateBytes {
		return Status{}, ErrInvalid
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Status{}, ErrUnavailable
		}
		return Status{}, err
	}
	defer f.Close()
	values := map[string]string{}
	scanner := bufio.NewScanner(io.LimitReader(f, maxStateBytes+1))
	for scanner.Scan() {
		line := scanner.Text()
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return Status{}, ErrInvalid
		}
		if _, duplicate := values[key]; duplicate {
			return Status{}, ErrInvalid
		}
		values[key] = value
	}
	if err := scanner.Err(); err != nil {
		return Status{}, err
	}
	allowed := map[string]bool{"request_id": true, "state": true, "target_source_sha": true, "target_version": true,
		"backup_dump": true, "backup_manifest": true, "reason_code": true, "updated_at": true}
	for key := range values {
		if !allowed[key] {
			return Status{}, ErrInvalid
		}
	}
	id, err := uuid.Parse(values["request_id"])
	if err != nil {
		return Status{}, ErrInvalid
	}
	updated, err := time.Parse(time.RFC3339, values["updated_at"])
	if err != nil || len(values["target_source_sha"]) != 40 {
		return Status{}, ErrInvalid
	}
	validState := map[string]bool{"requested": true, "verifying": true, "backing_up": true, "preflight": true,
		"pulling": true, "restarting": true, "health_check": true, "healthy": true, "failed": true}
	if !validState[values["state"]] {
		return Status{}, ErrInvalid
	}
	for _, name := range []string{values["backup_dump"], values["backup_manifest"]} {
		if name != "" && filepath.Base(name) != name {
			return Status{}, ErrInvalid
		}
	}
	return Status{RequestID: id, State: values["state"], TargetSource: values["target_source_sha"],
		TargetVersion: values["target_version"], BackupDump: values["backup_dump"], BackupManifest: values["backup_manifest"],
		ReasonCode: values["reason_code"], UpdatedAt: updated}, nil
}

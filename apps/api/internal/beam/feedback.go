package beam

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"image"
	_ "image/jpeg"
	"image/png"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

type FeedbackInput struct {
	Body             string `json:"body"`
	Status           string `json:"status"`
	ScreenshotBase64 string `json:"screenshot_base64,omitempty"`
}
type Feedback struct {
	ID            uuid.UUID `json:"id"`
	ShareID       uuid.UUID `json:"share_id"`
	AuthorID      uuid.UUID `json:"author_id"`
	AuthorName    string    `json:"author_name"`
	Body          string    `json:"body"`
	Status        string    `json:"status"`
	CreatedAt     time.Time `json:"created_at"`
	ScreenshotURL string    `json:"screenshot_url,omitempty"`
}

func sanitizedScreenshot(raw string) ([]byte, error) {
	if raw == "" {
		return nil, nil
	}
	if len(raw) > base64.StdEncoding.EncodedLen(262144) {
		return nil, invalid("Screenshot must be a PNG or JPEG of at most 256 KiB")
	}
	data, e := base64.StdEncoding.Strict().DecodeString(raw)
	if e != nil || len(data) > 262144 {
		return nil, invalid("Screenshot must be raw PNG or JPEG base64 of at most 256 KiB")
	}
	cfg, format, e := image.DecodeConfig(bytes.NewReader(data))
	if e != nil || (format != "png" && format != "jpeg") || cfg.Width < 1 || cfg.Height < 1 || cfg.Width > 2048 || cfg.Height > 2048 || cfg.Width*cfg.Height > 4000000 {
		return nil, invalid("Screenshot dimensions must be at most 2048 × 2048 (4 million pixels)")
	}
	img, _, e := image.Decode(bytes.NewReader(data))
	if e != nil {
		return nil, invalid("Invalid screenshot")
	}
	var out bytes.Buffer
	if e = png.Encode(&out, img); e != nil {
		return nil, invalid("Invalid screenshot")
	}
	if out.Len() > 262144 {
		return nil, invalid("Optimized screenshot must fit within 256 KiB")
	}
	return out.Bytes(), nil
}
func validateFeedback(in *FeedbackInput) ([]byte, error) {
	in.Body = strings.TrimSpace(in.Body)
	if !utf8.ValidString(in.Body) || utf8.RuneCountInString(in.Body) > 4000 || strings.ContainsRune(in.Body, '\x00') {
		return nil, invalid("Feedback must contain at most 4000 characters")
	}
	if in.Status != "comment" && in.Status != "approved" && in.Status != "changes_requested" {
		return nil, invalid("Select comment, approved or changes requested")
	}
	shot, e := sanitizedScreenshot(in.ScreenshotBase64)
	if e != nil {
		return nil, e
	}
	if in.Status == "comment" && in.Body == "" && len(shot) == 0 {
		return nil, invalid("Add a comment or screenshot")
	}
	return shot, nil
}

// Review content uses current browser identity, current grants and current policy.
// Owners may keep their own history; a withdrawn reviewer cannot read old feedback or images.
func (s *Service) feedbackAuthority(ctx context.Context, q reader, org, id uuid.UUID, a Actor, write bool) (Share, error) {
	if a.CredentialID != uuid.Nil || a.SessionID == "" {
		return Share{}, deny()
	}
	p, e := s.policy(ctx, q, org)
	if e != nil {
		return Share{}, e
	}
	if _, e = s.parent(ctx, q, org, a.ID, a.SessionID, p.RequireMFA); e != nil {
		return Share{}, e
	}
	r, e := scanShare(q.QueryRow(ctx, `SELECT `+shareColumns+` FROM beam_shares WHERE org_id=$1 AND id=$2`, org, id))
	if e != nil {
		return Share{}, missing()
	}
	if r.PublisherID == a.ID {
		if e = s.member(ctx, q, org, a.ID, rbac.PermBeamUse); e != nil {
			return Share{}, e
		}
		if write {
			if _, e = s.source(ctx, q, r, p); e != nil {
				return Share{}, e
			}
		}
		return r, nil
	}
	if s.reviewer(ctx, q, r, a.ID, p) != nil {
		return Share{}, missing()
	}
	if _, e = s.source(ctx, q, r, p); e != nil {
		return Share{}, missing()
	}
	return r, nil
}

const feedbackColumns = `f.id,f.share_id,f.author_id,u.name,f.body,f.status,f.created_at,(f.screenshot IS NOT NULL)`

func scanFeedback(row pgx.Row, org uuid.UUID) (Feedback, error) {
	var f Feedback
	var screenshot bool
	e := row.Scan(&f.ID, &f.ShareID, &f.AuthorID, &f.AuthorName, &f.Body, &f.Status, &f.CreatedAt, &screenshot)
	if screenshot {
		f.ScreenshotURL = fmt.Sprintf("/api/v1/organizations/%s/beam/shares/%s/feedback/%s/screenshot", org, f.ShareID, f.ID)
	}
	return f, e
}
func (s *Service) Feedback(ctx context.Context, org, id uuid.UUID, a Actor, limit, offset int) (Page[Feedback], error) {
	out := Page[Feedback]{Items: []Feedback{}, Limit: limit, Offset: offset, ServerTime: time.Now()}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return out, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.feedbackAuthority(ctx, tx, org, id, a, false); e != nil {
		return out, e
	}
	rows, e := tx.Query(ctx, `SELECT `+feedbackColumns+` FROM beam_feedback f JOIN users u ON u.id=f.author_id WHERE f.org_id=$1 AND f.share_id=$2 ORDER BY f.created_at DESC,f.id LIMIT $3 OFFSET $4`, org, id, limit, offset)
	if e != nil {
		return out, e
	}
	defer rows.Close()
	for rows.Next() {
		f, e := scanFeedback(rows, org)
		if e != nil {
			return out, e
		}
		out.Items = append(out.Items, f)
	}
	return out, rows.Err()
}
func (s *Service) AddFeedback(ctx context.Context, org, id uuid.UUID, a Actor, in FeedbackInput) (Feedback, error) {
	shot, e := validateFeedback(&in)
	if e != nil {
		return Feedback{}, e
	}
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return Feedback{}, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.feedbackAuthority(ctx, tx, org, id, a, true); e != nil {
		return Feedback{}, e
	}
	var count int
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_feedback WHERE org_id=$1 AND share_id=$2`, org, id).Scan(&count); e != nil {
		return Feedback{}, e
	}
	if count >= 500 {
		return Feedback{}, invalid("This preview has reached its 500 feedback item limit")
	}
	// Per-author rate limit prevents accidental repeat submissions and attachment flooding.
	if e = tx.QueryRow(ctx, `SELECT count(*) FROM beam_feedback WHERE org_id=$1 AND author_id=$2 AND created_at>now()-interval '1 minute'`, org, a.ID).Scan(&count); e != nil {
		return Feedback{}, e
	}
	if count >= 20 {
		return Feedback{}, invalid("Please wait before adding more feedback")
	}
	var fid uuid.UUID
	if e = tx.QueryRow(ctx, `INSERT INTO beam_feedback(org_id,share_id,author_id,body,status,screenshot) VALUES($1,$2,$3,$4,$5,$6) RETURNING id`, org, id, a.ID, in.Body, in.Status, shot).Scan(&fid); e != nil {
		return Feedback{}, e
	}
	f, e := scanFeedback(tx.QueryRow(ctx, `SELECT `+feedbackColumns+` FROM beam_feedback f JOIN users u ON u.id=f.author_id WHERE f.id=$1`, fid), org)
	if e != nil {
		return f, e
	}
	if e = audit(ctx, tx, org, a.ID, "feedback.created", id); e != nil {
		return f, e
	}
	return f, tx.Commit(ctx)
}
func (s *Service) FeedbackScreenshot(ctx context.Context, org, id, fid uuid.UUID, a Actor) ([]byte, error) {
	tx, e := s.transaction(ctx, org)
	if e != nil {
		return nil, e
	}
	defer tx.Rollback(ctx)
	if _, e = s.feedbackAuthority(ctx, tx, org, id, a, false); e != nil {
		return nil, e
	}
	var shot []byte
	if e = tx.QueryRow(ctx, `SELECT screenshot FROM beam_feedback WHERE org_id=$1 AND share_id=$2 AND id=$3 AND screenshot IS NOT NULL`, org, id, fid).Scan(&shot); e != nil {
		return nil, missing()
	}
	return shot, nil
}

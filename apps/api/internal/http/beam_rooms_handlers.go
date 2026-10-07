package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
)

type beamScreenshotResponse []byte

func serveBeamRooms(ctx context.Context, w http.ResponseWriter, r *http.Request, s *beam.Service, org uuid.UUID, a beam.Actor, path string) (any, bool, error) {
	if path == "projects" {
		if r.Method == http.MethodGet {
			l, o, e := beamPage(r)
			if e != nil {
				return nil, true, e
			}
			out, e := s.Projects(ctx, org, a, l, o)
			return out, true, e
		}
		if r.Method == http.MethodPost {
			var in beam.ProjectInput
			if e := beamDecode(w, r, &in); e != nil {
				return nil, true, e
			}
			out, e := s.SaveProject(ctx, org, uuid.Nil, a, in)
			return out, true, e
		}
	}
	if path == "notifications" && r.Method == http.MethodGet {
		l, o, e := beamPage(r)
		if e != nil {
			return nil, true, e
		}
		out, e := s.Notifications(ctx, org, a, l, o)
		return out, true, e
	}
	parts := strings.Split(path, "/")
	if len(parts) >= 2 && parts[0] == "projects" {
		id, e := uuid.Parse(parts[1])
		if e != nil {
			return nil, true, apierr.NotFound("beam_project_not_found", "Project not found")
		}
		if len(parts) == 2 {
			if r.Method == http.MethodGet {
				out, e := s.GetProject(ctx, org, id, a)
				return out, true, e
			}
			if r.Method == http.MethodPut {
				var in beam.ProjectInput
				if e := beamDecode(w, r, &in); e != nil {
					return nil, true, e
				}
				out, e := s.SaveProject(ctx, org, id, a, in)
				return out, true, e
			}
		}
		if len(parts) == 3 && parts[2] == "sessions" && r.Method == http.MethodGet {
			l, o, e := beamPage(r)
			if e != nil {
				return nil, true, e
			}
			out, e := s.ProjectSessions(ctx, org, id, a, l, o, r.URL.Query().Get("scope"))
			return out, true, e
		}
	}
	if len(parts) >= 3 && parts[0] == "shares" && parts[2] == "feedback" {
		id, e := uuid.Parse(parts[1])
		if e != nil {
			return nil, true, apierr.NotFound("beam_share_not_found", "Share not found")
		}
		if len(parts) == 3 {
			if r.Method == http.MethodGet {
				l, o, e := beamPage(r)
				if e != nil {
					return nil, true, e
				}
				out, e := s.Feedback(ctx, org, id, a, l, o)
				return out, true, e
			}
			if r.Method == http.MethodPost {
				var in beam.FeedbackInput
				if e := beamDecodeLimit(w, r, &in, 524288); e != nil {
					return nil, true, e
				}
				out, e := s.AddFeedback(ctx, org, id, a, in)
				return out, true, e
			}
		}
		if len(parts) == 5 && parts[4] == "screenshot" && r.Method == http.MethodGet {
			fid, e := uuid.Parse(parts[3])
			if e != nil {
				return nil, true, apierr.NotFound("beam_feedback_not_found", "Feedback not found")
			}
			shot, e := s.FeedbackScreenshot(ctx, org, id, fid, a)
			return beamScreenshotResponse(shot), true, e
		}
	}
	return nil, false, nil
}

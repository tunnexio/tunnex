package http

import (
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/beam"
	"net/http"
)

func beamOperator(r *http.Request) (uuid.UUID, error) {
	if len(r.Header.Values("Authorization")) > 0 {
		return uuid.Nil, apierr.Forbidden("human_session_required", "Installation serving settings require a human browser session")
	}
	if len(r.URL.Query()) != 0 {
		return uuid.Nil, apierr.BadRequest("beam_invalid", "Installation serving operations do not accept query targets")
	}
	return requireAppDomainsAdmin(r.Context())
}
func beamOperatorService(s *beam.Service) error {
	if s == nil {
		return apierr.New(503, "beam_unavailable", "Beam service unavailable")
	}
	return nil
}
func serveBeamReadiness(w http.ResponseWriter, r *http.Request, s *beam.Service) {
	if _, e := beamOperator(r); e != nil {
		apierr.Write(w, r, e)
		return
	}
	if e := beamOperatorService(s); e != nil {
		apierr.Write(w, r, e)
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, e := s.GetDomainReadiness(r.Context())
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		writeJSON(w, result)
	case http.MethodPost:
		var in struct {
			ExpectedVersion string `json:"expected_configuration_version"`
		}
		if e := beamDecode(w, r, &in); e != nil {
			apierr.Write(w, r, e)
			return
		}
		result, e := s.CheckDomainReadiness(r.Context(), in.ExpectedVersion)
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		writeJSON(w, result)
	default:
		w.Header().Set("Allow", "GET, POST")
		apierr.Write(w, r, apierr.New(405, "method_not_allowed", "Method not allowed"))
	}
}
func serveBeamDomainSettings(w http.ResponseWriter, r *http.Request, s *beam.Service) {
	actor, e := beamOperator(r)
	if e != nil {
		apierr.Write(w, r, e)
		return
	}
	if e := beamOperatorService(s); e != nil {
		apierr.Write(w, r, e)
		return
	}
	switch r.Method {
	case http.MethodGet:
		result, e := s.GetDomainSettings(r.Context())
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		writeJSON(w, result)
	case http.MethodPut:
		var in beam.DomainSettingsInput
		if e := beamDecode(w, r, &in); e != nil {
			apierr.Write(w, r, e)
			return
		}
		result, e := s.UpdateDomainSettings(r.Context(), actor, in)
		if e != nil {
			apierr.Write(w, r, e)
			return
		}
		writeJSON(w, result)
	default:
		w.Header().Set("Allow", "GET, PUT")
		apierr.Write(w, r, apierr.New(405, "method_not_allowed", "Method not allowed"))
	}
}

package http

import (
	"context"
	"errors"

	"github.com/go-chi/chi/v5/middleware"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
	"github.com/tunnexio/tunnex/apps/api/internal/mailsettings"
)

type emailSettingsRepository interface {
	Get(context.Context) (mailsettings.View, error)
	Save(context.Context, uuid.UUID, mailsettings.Update) (mailsettings.View, error)
	Test(context.Context, uuid.UUID, string, mailsettings.Update) error
	Configured(context.Context) (bool, error)
}

func emailSettingsError(err error) error {
	if err == nil {
		return nil
	}
	var known *apierr.Error
	if errors.As(err, &known) {
		return err
	}
	return apierr.New(503, "smtp_settings_unavailable", "Email settings are unavailable. Try again; no fallback provider was used.")
}
func emailSettingsView(v mailsettings.View) api.ServerEmailSettings {
	return api.ServerEmailSettings{Enabled: v.Enabled, Host: v.Host, Port: v.Port, From: v.From, Username: v.Username, PasswordConfigured: v.PasswordConfigured, Source: api.ServerEmailSettingsSource(v.Source), Revision: v.Revision}
}
func emailSettingsInput(v *api.ServerEmailSettingsInput) (mailsettings.Update, error) {
	if v == nil {
		return mailsettings.Update{}, apierr.BadRequest("smtp_settings_invalid", "Email settings are required.")
	}
	password := ""
	if v.Password != nil {
		password = *v.Password
	}
	return mailsettings.Update{Enabled: v.Enabled, Host: v.Host, Port: v.Port, From: v.From, Username: v.Username, Revision: v.Revision, PasswordAction: string(v.PasswordAction), Password: password}, nil
}
func (s apiServer) GetServerEmailSettings(ctx context.Context, _ api.GetServerEmailSettingsRequestObject) (api.GetServerEmailSettingsResponseObject, error) {
	if _, err := requireCPAdmin(ctx); err != nil {
		return nil, err
	}
	if s.emailSettings == nil {
		return nil, emailSettingsError(errors.New("not wired"))
	}
	v, err := s.emailSettings.Get(ctx)
	if err != nil {
		return nil, emailSettingsError(err)
	}
	return api.GetServerEmailSettings200JSONResponse{Body: emailSettingsView(v), Headers: api.GetServerEmailSettings200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
func (s apiServer) UpdateServerEmailSettings(ctx context.Context, req api.UpdateServerEmailSettingsRequestObject) (api.UpdateServerEmailSettingsResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.emailSettings == nil {
		return nil, emailSettingsError(errors.New("not wired"))
	}
	in, err := emailSettingsInput(req.Body)
	if err != nil {
		return nil, err
	}
	v, err := s.emailSettings.Save(ctx, p.UserID, in)
	if err != nil {
		return nil, emailSettingsError(err)
	}
	return api.UpdateServerEmailSettings200JSONResponse{Body: emailSettingsView(v), Headers: api.UpdateServerEmailSettings200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}
func (s apiServer) TestServerEmailSettings(ctx context.Context, req api.TestServerEmailSettingsRequestObject) (api.TestServerEmailSettingsResponseObject, error) {
	p, err := requireCPAdmin(ctx)
	if err != nil {
		return nil, err
	}
	if s.emailSettings == nil {
		return nil, emailSettingsError(errors.New("not wired"))
	}
	in, err := emailSettingsInput(req.Body)
	if err != nil {
		return nil, err
	}
	if err = s.emailSettings.Test(ctx, p.UserID, p.Email, in); err != nil {
		return nil, emailSettingsError(err)
	}
	return api.TestServerEmailSettings200JSONResponse{Body: struct {
		Accepted bool `json:"accepted"`
	}{Accepted: true}, Headers: api.TestServerEmailSettings200ResponseHeaders{XRequestId: middleware.GetReqID(ctx)}}, nil
}

package http

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/mailsettings"
	"testing"
)

type emailSettingsStub struct {
	calls     int
	recipient string
	failure   error
}

func (s *emailSettingsStub) Get(context.Context) (mailsettings.View, error) {
	s.calls++
	return mailsettings.View{Host: "smtp.example.test", PasswordConfigured: true}, s.failure
}
func (s *emailSettingsStub) Save(context.Context, uuid.UUID, mailsettings.Update) (mailsettings.View, error) {
	s.calls++
	return mailsettings.View{}, s.failure
}
func (s *emailSettingsStub) Test(_ context.Context, _ uuid.UUID, email string, _ mailsettings.Update) error {
	s.calls++
	s.recipient = email
	return s.failure
}
func (s *emailSettingsStub) Configured(context.Context) (bool, error) { return true, s.failure }
func TestEmailSettingsRequiresVerifiedServerAdministrator(t *testing.T) {
	for _, p := range []*authctx.Principal{nil, {UserID: uuid.New(), EmailVerified: true, Roles: map[uuid.UUID]string{uuid.New(): "owner"}}, {UserID: uuid.New(), CPAdmin: true}, {UserID: uuid.New(), CPAdmin: true, EmailVerified: true, MustChangePassword: true}} {
		ctx := context.Background()
		if p != nil {
			ctx = authctx.WithPrincipal(ctx, p)
		}
		stub := &emailSettingsStub{}
		server := apiServer{emailSettings: stub}
		if _, e := server.GetServerEmailSettings(ctx, api.GetServerEmailSettingsRequestObject{}); e == nil {
			t.Fatal("read permission bypass")
		}
		if _, e := server.UpdateServerEmailSettings(ctx, api.UpdateServerEmailSettingsRequestObject{}); e == nil {
			t.Fatal("write permission bypass")
		}
		if _, e := server.TestServerEmailSettings(ctx, api.TestServerEmailSettingsRequestObject{}); e == nil {
			t.Fatal("test permission bypass")
		}
		if stub.calls != 0 {
			t.Fatal("unauthorized repository access")
		}
	}
}
func TestEmailSettingsTestRecipientAndErrorRedaction(t *testing.T) {
	p := &authctx.Principal{UserID: uuid.New(), Email: "admin@example.test", EmailVerified: true, CPAdmin: true}
	ctx := authctx.WithPrincipal(context.Background(), p)
	stub := &emailSettingsStub{}
	server := apiServer{emailSettings: stub}
	if _, e := server.TestServerEmailSettings(ctx, api.TestServerEmailSettingsRequestObject{Body: &api.ServerEmailSettingsInput{}}); e != nil {
		t.Fatal(e)
	}
	if stub.recipient != p.Email {
		t.Fatal("test recipient is not authenticated administrator")
	}
	stub.failure = errors.New("password=never-disclose")
	_, err := server.GetServerEmailSettings(ctx, api.GetServerEmailSettingsRequestObject{})
	if err == nil || err.Error() == stub.failure.Error() {
		t.Fatal("raw configuration error escaped")
	}
}

func TestEmailMetadataReadFailureIsUnknownWithoutBreakingOtherMetadata(t *testing.T) {
	s := apiServer{smtpConfigured: true, emailSettings: &emailSettingsStub{failure: errors.New("unavailable")}}
	response, err := s.GetMeta(context.Background(), api.GetMetaRequestObject{})
	if err != nil {
		t.Fatal("email read failure blocked unrelated metadata", err)
	}
	if response.(api.GetMeta200JSONResponse).Body.SmtpConfigured != nil {
		t.Fatal("failed read reused installer state instead of unknown")
	}
	s.emailSettings = &emailSettingsStub{}
	response, err = s.GetMeta(context.Background(), api.GetMetaRequestObject{})
	if err != nil {
		t.Fatal(err)
	}
	configured := response.(api.GetMeta200JSONResponse).Body.SmtpConfigured
	if configured == nil || !*configured {
		t.Fatal("saved setting was not reflected in metadata")
	}
}

package http

import (
	"bytes"
	"context"
	"encoding/base64"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/authctx"
	"github.com/tunnexio/tunnex/apps/api/internal/licence"
	"github.com/tunnexio/tunnex/apps/api/internal/rbac"
)

func appIconHTTPFixture(t *testing.T) string {
	return appIconHTTPFixtureSized(t, 16)
}

func appIconHTTPFixtureSized(t *testing.T, size int) string {
	t.Helper()
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewNRGBA(image.Rect(0, 0, size, size))); err != nil {
		t.Fatal(err)
	}
	return "data:image/png;base64," + base64.StdEncoding.EncodeToString(encoded.Bytes())
}

func TestAppAccessIconInputPresence(t *testing.T) {
	empty, imageData := "", appIconHTTPFixture(t)
	org := uuid.New()
	ctx := authctx.WithPrincipal(context.Background(), appAccessPrincipal(org, rbac.RoleOwner))
	for _, tc := range []struct {
		name  string
		image *string
	}{
		{"omitted", nil}, {"removed", &empty}, {"uploaded", &imageData},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &appAccessRecorder{}
			s := apiServer{appAccess: f, licence: licence.NewTestManager("trial", time.Now().Add(time.Hour))}
			_, err := s.UpdateAppAccessApplication(ctx, api.UpdateAppAccessApplicationRequestObject{OrgId: org, AppId: uuid.New(), Body: &api.AppAccessUpdateDraftInput{Name: "Icon", Icon: "app", IconDataUrl: tc.image, GatewayId: uuid.New(), OriginUrl: "https://origin", PublicHostname: "icons.apps.example.net", IdleTimeoutSeconds: 60, AbsoluteTimeoutSeconds: 300, ExpectedVersion: 1}})
			if err != nil || f.calls != 1 || f.input.IconDataURLSet != (tc.image != nil) {
				t.Fatal("update lost field presence", err)
			}
			if tc.image != nil && f.input.IconDataURL != *tc.image {
				t.Fatal("update changed image")
			}
			create := appAccessInput(api.AppAccessDraftInput{IconDataUrl: tc.image})
			if create.IconDataURLSet != f.input.IconDataURLSet || create.IconDataURL != f.input.IconDataURL {
				t.Fatal("create and update interpret image differently")
			}
		})
	}
}

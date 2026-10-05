package http

import (
	"context"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"testing"
)

func TestMetaSandboxModuleState(t *testing.T) {
	for _, state := range []string{"", "disabled", "enabled", "draining"} {
		s := apiServer{sandboxModuleState: state}
		got, err := s.GetMeta(context.Background(), api.GetMetaRequestObject{})
		if err != nil {
			t.Fatal(err)
		}
		want := state
		if want == "" {
			want = "disabled"
		}
		v := got.(api.GetMeta200JSONResponse).Body.SandboxModuleState
		if v == nil || string(*v) != want {
			t.Fatal(v, want)
		}
	}
}

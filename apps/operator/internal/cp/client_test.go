package cp

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestClientHonestErrors — the deciding feature (S10.2 3a): a CP 4xx becomes an *APIError carrying the CP's
// own code + message (the reconciler renders it verbatim into a non-Ready CR condition — honest status),
// while a 5xx / transport error is a PLAIN (retryable) error, NOT an APIError (the reconciler keeps last-good
// and requeues). That branch is the whole difference between GitOps that governs and GitOps that lies.
func TestClientHonestErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tnxm_test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/k8s/clusters"):
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"id":"c1","name":"prod","dns_vip":"100.64.0.2"}`)
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/policies"):
			w.WriteHeader(http.StatusForbidden) // enterprise-gated grant in the open build
			io.WriteString(w, `{"error":{"code":"edition_required","message":"Zero Trust is an enterprise feature"}}`)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/services"):
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "boom")
		}
	}))
	defer srv.Close()
	c := New(srv.URL, "tnxm_test", "org1")
	ctx := context.Background()

	// 2xx → parsed (derived truth the reconciler puts in STATUS).
	cl, err := c.RegisterCluster(ctx, RegisterClusterRequest{Name: "prod"})
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if cl.ID != "c1" || cl.DnsVip != "100.64.0.2" {
		t.Fatalf("2xx body must parse, got %+v", cl)
	}

	// 4xx → *APIError with the code + message carried verbatim (honest-status source).
	if _, err := c.CreateGrant(ctx, CreateGrantRequest{DstKind: "k8s_service"}); true {
		ae := AsAPIError(err)
		if ae == nil || ae.Status != 403 || ae.Code != "edition_required" {
			t.Fatalf("a 4xx must be an *APIError naming the code, got %v", err)
		}
		if ae.Message == "" {
			t.Fatal("the CP message must be carried verbatim for honest status")
		}
	}

	// 5xx → a PLAIN error (retryable), NEVER an *APIError — the reconciler keeps last-good + requeues.
	if _, err := c.ExposeService(ctx, "c1", ExposeServiceRequest{Name: "x"}); err == nil {
		t.Fatal("a 5xx must error")
	} else if AsAPIError(err) != nil {
		t.Fatal("a 5xx must NOT be an *APIError — it is retryable (keep-last), not a client error")
	}
}

// TestClientAuthAndOrgPath — every call carries the machine bearer and is org-scoped in the path.
func TestClientAuthAndOrgPath(t *testing.T) {
	var gotAuth, gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth, gotPath = r.Header.Get("Authorization"), r.URL.Path
		io.WriteString(w, "[]")
	}))
	defer srv.Close()
	if _, err := New(srv.URL, "tnxm_abc", "org-42").ListClusters(context.Background()); err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer tnxm_abc" {
		t.Fatalf("machine bearer must be sent, got %q", gotAuth)
	}
	if gotPath != "/api/v1/organizations/org-42/k8s/clusters" {
		t.Fatalf("call must be org-scoped in the path, got %q", gotPath)
	}
}

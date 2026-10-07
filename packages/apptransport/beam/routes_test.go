package beam

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRoutesFixedTargetsLongestPrefixAndBoundaries(t *testing.T) {
	root := Target{Protocol: "http", Address: "127.0.0.1", Port: 3000, Routes: []Route{{"/api", Target{Protocol: "http", Address: "127.0.0.1", Port: 8080}}, {"/api/v2", Target{Protocol: "http", Address: "127.0.0.1", Port: 8081}}}}
	for path, port := range map[string]int{"/": 3000, "/api": 8080, "/api/orders": 8080, "/api/v2/orders": 8081, "/apiary": 3000} {
		got, e := TargetForPath(root, path)
		if e != nil || got.Port != port {
			t.Fatalf("%s got%v err%v", path, got, e)
		}
	}
	for _, prefix := range []string{"/", "//api", "/api/", "/api/../admin", "/api%2fadmin", "http://remote", "/api?q=1"} {
		if ValidPathPrefix(prefix) {
			t.Fatalf("unsafe prefix %s", prefix)
		}
	}
	root.Routes[0].Target.Address = "169.254.169.254"
	if ValidateTarget(root) == nil {
		t.Fatal("remote route accepted")
	}
	root.Routes[0].Target.Address = "127.0.0.1"
	root.Routes[1].PathPrefix = "/api"
	if ValidateTarget(root) == nil {
		t.Fatal("duplicate route accepted")
	}
}
func TestRoutesActualTLSChannelPreservesAPIPath(t *testing.T) {
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "api:"+r.URL.RequestURI())
		if r.Header.Get("X-App-Digest") != "" {
			t.Error("authority leaked")
		}
	}))
	defer api.Close()
	f := fixture(t, false, false, time.Minute, Route{PathPrefix: "/api", Target: targetOf(t, api, "")})
	for requestPath, want := range map[string]string{"/api/orders": "api:/api/orders", "/apiary": "local Beam app", "/": "local Beam app"} {
		peer, response, _ := f.dial(requestPath, nil)
		data, e := io.ReadAll(response.Body)
		response.Body.Close()
		peer.Close()
		if e != nil || string(data) != want {
			t.Fatalf("%s=%s err%v", requestPath, data, e)
		}
	}
}

func TestRoutesReadinessRequiresEveryLocalOrigin(t *testing.T) {
	frontend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer frontend.Close()
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	target := targetOf(t, frontend, "")
	target.Routes = []Route{{"/api", targetOf(t, api, "")}}
	if e := CheckTarget(context.Background(), target); e != nil {
		t.Fatal(e)
	}
	api.Close()
	if e := CheckTarget(context.Background(), target); e == nil {
		t.Fatal("unavailable API was reported ready")
	}
	if e := CheckTarget(context.Background(), targetOf(t, frontend, "")); e != nil {
		t.Fatal("root app should remain ready")
	}
}

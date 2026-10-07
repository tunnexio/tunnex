package cli

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestBeamParseRoutesAndProject(t *testing.T) {
	args := []string{"publish", "--org", beamTestOrg, "--port", "3000", "--name", "Frontend", "--reviewer-user", beamTestReviewer, "--route", "/api=8080", "--route", "/api/v2=8081", "--project", beamTestShare}
	command, e := parseBeam(args, new(bytes.Buffer))
	if e != nil {
		t.Fatal(e)
	}
	if command.project != beamTestShare || len(command.target.Routes) != 2 || command.target.Routes[0].Target.Port != 8080 || command.target.Routes[0].Target.Address != "127.0.0.1" {
		t.Fatalf("bad route binding%+v", command)
	}
	for _, bad := range []string{"/=8080", "/api=remote", "/api=65536", "/api/../admin=80", "http://evil=80"} {
		testArgs := append([]string{}, args[:len(args)-6]...)
		testArgs = append(testArgs, "--route", bad)
		if _, e := parseBeam(testArgs, new(bytes.Buffer)); e == nil {
			t.Fatalf("accepted %s", bad)
		}
	}
	duplicate := append(append([]string{}, args...), "--route", "/api=8000")
	if _, e := parseBeam(duplicate, new(bytes.Buffer)); e == nil {
		t.Fatal("duplicate route accepted")
	}
}
func TestBeamRoutesRefuseOldServerBeforeCreate(t *testing.T) {
	api, _, deps, _ := beamFixture()
	e := runBeam(context.Background(), []string{"publish", "--org", beamTestOrg, "--port", "3000", "--name", "Frontend", "--reviewer-user", beamTestReviewer, "--route", "/api=8080"}, new(bytes.Buffer), "dev", deps)
	if e == nil || !strings.Contains(e.Error(), "server update required") {
		t.Fatalf("got%v", e)
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if api.creates != 0 {
		t.Fatal("created share on old server")
	}
}

func TestBeamConnectorRejectsTargetDigestDowngrade(t *testing.T) {
	api, _, deps, _ := beamFixture()
	api.connector.ShareVersion = api.share.Version + 1
	if !beamConnectorMatches(api.connector, api.share, deps.clock()) {
		t.Fatal("bad fixture")
	}
	api.share.Target.Routes = []beamRoute{{"/api", beamTarget{Protocol: "http", Address: "127.0.0.1", Port: 8080}}}
	if beamConnectorMatches(api.connector, api.share, deps.clock()) {
		t.Fatal("route change did not change binding authority")
	}
}

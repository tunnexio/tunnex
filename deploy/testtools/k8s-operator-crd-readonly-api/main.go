// Command k8s-operator-crd-readonly-api serves the minimum read-only
// Kubernetes discovery and CRD GET surface needed by Helm's lookup function.
// It is a contract-test fixture, not a Kubernetes API emulator.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
)

const crdCollectionPath = "/apis/apiextensions.k8s.io/v1/customresourcedefinitions/"

type fixture struct {
	Objects map[string]json.RawMessage `json:"objects"`
}

type readOnlyAPI struct {
	fixture fixture
	log     *os.File
	logMu   sync.Mutex
}

func main() {
	fixturePath := flag.String("fixture", "", "JSON file containing CRD objects keyed by metadata.name")
	addressPath := flag.String("address-file", "", "file to receive the fixture server URL")
	requestLogPath := flag.String("request-log", "", "file to receive one METHOD PATH entry per request")
	flag.Parse()
	if *fixturePath == "" || *addressPath == "" || *requestLogPath == "" {
		log.Fatal("--fixture, --address-file, and --request-log are required")
	}

	rawFixture, err := os.ReadFile(*fixturePath)
	if err != nil {
		log.Fatal(err)
	}
	var data fixture
	if err := json.Unmarshal(rawFixture, &data); err != nil {
		log.Fatalf("decode fixture: %v", err)
	}
	if data.Objects == nil {
		data.Objects = map[string]json.RawMessage{}
	}
	for name, object := range data.Objects {
		if name == "" || !json.Valid(object) {
			log.Fatalf("fixture contains invalid object for %q", name)
		}
	}

	requestLog, err := os.OpenFile(*requestLogPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		log.Fatal(err)
	}
	defer requestLog.Close()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	address := "http://" + listener.Addr().String()
	if err := os.WriteFile(*addressPath, []byte(address+"\n"), 0o600); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{Handler: &readOnlyAPI{fixture: data, log: requestLog}}
	if err := server.Serve(listener); err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}

func (api *readOnlyAPI) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	api.record(request.Method, request.URL.Path)
	response.Header().Set("Content-Type", "application/json")
	if request.Method != http.MethodGet {
		writeStatus(response, http.StatusMethodNotAllowed, "MethodNotAllowed", "fixture accepts read-only GET requests")
		return
	}

	switch request.URL.Path {
	case "/version":
		writeJSON(response, http.StatusOK, map[string]any{
			"major": "1", "minor": "31", "gitVersion": "v1.31.0",
			"gitCommit": "readonly-fixture", "gitTreeState": "clean",
			"buildDate": "2026-09-05T00:00:00Z", "goVersion": "go1.25.13",
			"compiler": "gc", "platform": "fixture/fixture",
		})
	case "/api":
		writeJSON(response, http.StatusOK, map[string]any{
			"apiVersion": "v1", "kind": "APIVersions", "versions": []string{"v1"},
			"serverAddressByClientCIDRs": []any{},
		})
	case "/api/v1":
		writeJSON(response, http.StatusOK, map[string]any{
			"apiVersion": "v1", "kind": "APIResourceList", "groupVersion": "v1", "resources": []any{},
		})
	case "/apis":
		writeJSON(response, http.StatusOK, map[string]any{
			"apiVersion": "v1", "kind": "APIGroupList",
			"groups": []any{map[string]any{
				"name":             "apiextensions.k8s.io",
				"versions":         []any{map[string]any{"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"}},
				"preferredVersion": map[string]any{"groupVersion": "apiextensions.k8s.io/v1", "version": "v1"},
			}},
		})
	case "/apis/apiextensions.k8s.io/v1":
		writeJSON(response, http.StatusOK, map[string]any{
			"apiVersion": "v1", "kind": "APIResourceList", "groupVersion": "apiextensions.k8s.io/v1",
			"resources": []any{map[string]any{
				"name": "customresourcedefinitions", "singularName": "", "namespaced": false,
				"kind": "CustomResourceDefinition", "verbs": []string{"get", "list"},
			}},
		})
	default:
		if strings.HasPrefix(request.URL.Path, crdCollectionPath) {
			name := strings.TrimPrefix(request.URL.Path, crdCollectionPath)
			if object, found := api.fixture.Objects[name]; found && !strings.Contains(name, "/") {
				response.WriteHeader(http.StatusOK)
				_, _ = response.Write(object)
				_, _ = response.Write([]byte{'\n'})
				return
			}
			writeStatus(response, http.StatusNotFound, "NotFound", fmt.Sprintf("customresourcedefinition %q not found", name))
			return
		}
		writeStatus(response, http.StatusNotFound, "NotFound", fmt.Sprintf("fixture path %q not found", request.URL.Path))
	}
}

func (api *readOnlyAPI) record(method, path string) {
	api.logMu.Lock()
	defer api.logMu.Unlock()
	if _, err := fmt.Fprintf(api.log, "%s %s\n", method, path); err != nil {
		log.Printf("write request log: %v", err)
	}
}

func writeJSON(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	if err := json.NewEncoder(response).Encode(value); err != nil {
		log.Printf("write response: %v", err)
	}
}

func writeStatus(response http.ResponseWriter, status int, reason, message string) {
	writeJSON(response, status, map[string]any{
		"apiVersion": "v1", "kind": "Status", "status": "Failure",
		"reason": reason, "message": message, "code": status,
	})
}

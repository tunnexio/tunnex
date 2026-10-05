package sandboxes

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"golang.org/x/crypto/ssh"
)

// These portable fixtures exercise the forwarding protocol through HTTP
// handlers. Actual socket ownership/SO_PEERCRED remains the existing Linux
// WorkerRPCClient boundary; there is no provider, namespace or live credential.
type forwarderHTTPTransport struct{ handler http.Handler }

func (f forwarderHTTPTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	out := httptest.NewRecorder()
	f.handler.ServeHTTP(out, r)
	return out.Result(), nil
}
func newForwarderFixture(t *testing.T, handler http.Handler) (*UnixControlForwarder, BoundedRuntimeBinding, ssh.PublicKey) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b := persistentTestBinding()
	forwarder, err := NewUnixControlForwarder("/run/tunnex-sandbox-qual/api/control.sock", 1101, signer.PublicKey(), b)
	if err != nil {
		t.Fatal(err)
	}
	// Replace only the OS transport, leaving production forwarding intact.
	forwarder.client.Transport = forwarderHTTPTransport{handler}
	forwarder.client.Timeout = time.Second
	return forwarder, b, signer.PublicKey()
}
func forwarderCommand(payload []byte) sandboxrunner.Command {
	return sandboxrunner.Command{ID: uuid.New(), Deadline: time.Now().Add(time.Second), Payload: payload}
}

func TestUnixControlForwarderPreservesWireGenerationAndActorDenial(t *testing.T) {
	id := uuid.New()
	payload := []byte(`{ "Version": 1, "Operation": "start", "ID": "` + id.String() + `", "Generation": 47 }`)
	actorReply := []byte("{\"Version\":1,\"Error\":\"forbidden\"}\n")
	var seen []byte
	var deadline time.Time
	f, _, _ := newForwarderFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.String() != "http://sandbox-worker/v1/control" || r.URL.RawQuery != "" || r.Header.Get("Content-Type") != "application/json" {
			t.Error("forwarder changed fixed actor endpoint")
		}
		deadline, _ = r.Context().Deadline()
		var err error
		seen, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		_, _ = w.Write(actorReply)
	}))
	command := forwarderCommand(payload)
	reply, err := f.ForwardRemoteControl(context.Background(), command)
	if err != nil || !bytes.Equal(seen, payload) || !bytes.Equal(reply, actorReply) || !deadline.Equal(command.Deadline) {
		t.Fatal("raw command/generation/deadline or stable actor denial changed", err)
	}
	var got workerRequest
	if json.Unmarshal(seen, &got) != nil || got.Generation != 47 || got.ID != id || got.Version != 1 {
		t.Fatal("controller's original generation was replaced")
	}
}

func TestUnixControlForwarderRejectsInvalidRequestsBeforeActor(t *testing.T) {
	var calls atomic.Int32
	f, _, _ := newForwarderFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { calls.Add(1); _, _ = w.Write([]byte(`{"Version":1}`)) }))
	id := uuid.New().String()
	valid := []byte(`{"Version":1,"Operation":"inspect","ID":"` + id + `","Generation":4}`)
	for _, scenario := range []struct {
		name    string
		command sandboxrunner.Command
	}{
		{"version", forwarderCommand([]byte(`{"Version":2,"Operation":"inspect","ID":"` + id + `","Generation":4}`))},
		{"unknown field", forwarderCommand([]byte(`{"Version":1,"Operation":"inspect","ID":"` + id + `","Generation":4,"PID":123}`))},
		{"trailing JSON", forwarderCommand(append(append([]byte(nil), valid...), []byte(` {}`)...))},
		{"malformed", forwarderCommand([]byte(`{"Version":1`))},
		{"missing effect ID", forwarderCommand([]byte(`{"Version":1,"Operation":"start","Generation":4}`))},
		{"zero generation", forwarderCommand([]byte(`{"Version":1,"Operation":"start","ID":"` + id + `","Generation":0}`))},
		{"mutated ping", forwarderCommand([]byte(`{"Version":1,"Operation":"ping","Generation":4}`))},
		{"oversize", forwarderCommand([]byte(`{"Version":1,"Operation":"` + strings.Repeat("x", workerRPCLimit) + `","ID":"` + id + `","Generation":4}`))},
		{"missing command ID", sandboxrunner.Command{Deadline: time.Now().Add(time.Second), Payload: valid}},
		{"expired", sandboxrunner.Command{ID: uuid.New(), Deadline: time.Now().Add(-time.Second), Payload: valid}},
		{"unbounded deadline", sandboxrunner.Command{ID: uuid.New(), Deadline: time.Now().Add(31 * time.Second), Payload: valid}},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := f.ForwardRemoteControl(context.Background(), scenario.command); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid command forwarded", err)
			}
		})
	}
	if calls.Load() != 0 {
		t.Fatal("invalid request reached actor")
	}
}

func TestUnixControlForwarderRefusesRedirectAwayFromFixedEndpoint(t *testing.T) {
	var calls atomic.Int32
	f, _, _ := newForwarderFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Location", "http://foreign/other-control")
		w.WriteHeader(http.StatusTemporaryRedirect)
	}))
	if _, err := f.ForwardRemoteControl(context.Background(), forwarderCommand([]byte(`{"Version":1,"Operation":"ping"}`))); !errors.Is(err, ErrDisabled) || calls.Load() != 1 {
		t.Fatal("forwarder followed actor redirect", err, calls.Load())
	}
}

func TestUnixControlForwarderPinsExactPingAndResponseProtocol(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b := persistentTestBinding()
	pin := string(ssh.MarshalAuthorizedKey(signer.PublicKey()))
	valid := workerResponse{Version: workerRPCVersion, Binding: &b, HostPublicKey: pin}
	foreign := b
	foreign.GatewayID = uuid.New()
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongProbe, err := ssh.NewSignerFromKey(other)
	if err != nil {
		t.Fatal(err)
	}
	encode := func(v any) []byte {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, scenario := range []struct {
		name   string
		status int
		body   []byte
		want   error
	}{
		{"pinned", 200, encode(valid), nil},
		{"wrong binding", 200, encode(workerResponse{Version: 1, Binding: &foreign, HostPublicKey: pin}), ErrDisabled},
		{"wrong probe", 200, encode(workerResponse{Version: 1, Binding: &b, HostPublicKey: string(ssh.MarshalAuthorizedKey(wrongProbe.PublicKey()))}), ErrDisabled},
		{"missing binding", 200, encode(workerResponse{Version: 1, HostPublicKey: pin}), ErrDisabled},
		{"version", 200, encode(workerResponse{Version: 2, Binding: &b, HostPublicKey: pin}), ErrConflict},
		{"unknown field", 200, []byte(`{"Version":1,"Exec":"sh"}`), ErrConflict},
		{"unknown private error", 200, []byte(`{"Version":1,"Error":"private diagnostic"}`), ErrConflict},
		{"malformed", 200, []byte(`{"Version":1`), ErrConflict},
		{"trailing", 200, append(encode(valid), []byte(` {}`)...), ErrConflict},
		{"oversize", 200, []byte(`{"Version":1,"HostPublicKey":"` + strings.Repeat("x", workerRPCLimit) + `"}`), ErrConflict},
		{"HTTP denial", 403, []byte("private diagnostic"), ErrDisabled},
		{"structured unavailability", 200, []byte(`{"Version":1,"Error":"unavailable"}`), nil},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			f, err := NewUnixControlForwarder("/run/tunnex-sandbox-qual/api/control.sock", 1101, signer.PublicKey(), b)
			if err != nil {
				t.Fatal(err)
			}
			f.client = &http.Client{Transport: forwarderHTTPTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(scenario.status)
				_, _ = w.Write(scenario.body)
			})}}
			got, err := f.ForwardRemoteControl(context.Background(), forwarderCommand([]byte(`{"Version":1,"Operation":"ping"}`)))
			if !errors.Is(err, scenario.want) {
				t.Fatal("unexpected reply acceptance", err)
			}
			if scenario.want == nil && !bytes.Equal(got, scenario.body) {
				t.Fatal("valid actor reply changed")
			}
			if scenario.want != nil && len(got) != 0 {
				t.Fatal("rejected actor reply escaped")
			}
		})
	}
}

func TestUnixControlForwarderHealthRemainsReentrantDuringEnrollment(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	defer close(release)
	var b BoundedRuntimeBinding
	var probe ssh.PublicKey
	f, b, probe := newForwarderFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var in workerRequest
		if json.NewDecoder(r.Body).Decode(&in) != nil {
			t.Error("invalid forwarded payload")
			w.WriteHeader(400)
			return
		}
		if in.Operation == "enroll" {
			close(entered)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte(`{"Version":1,"Error":"unavailable"}`))
			return
		}
		if in.Operation != "ping" {
			t.Error("unexpected forwarding operation")
			w.WriteHeader(400)
			return
		}
		_ = json.NewEncoder(w).Encode(workerResponse{Version: 1, Binding: &b, HostPublicKey: string(ssh.MarshalAuthorizedKey(probe))})
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	effectDone := make(chan error, 1)
	go func() {
		_, err := f.ForwardRemoteControl(ctx, forwarderCommand([]byte(`{"Version":1,"Operation":"enroll","ID":"`+uuid.NewString()+`","Generation":12}`)))
		effectDone <- err
	}()
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("effect never reached actor")
	}
	healthDone := make(chan error, 1)
	go func() {
		_, err := f.ForwardRemoteControl(ctx, forwarderCommand([]byte(`{"Version":1,"Operation":"ping"}`)))
		healthDone <- err
	}()
	select {
	case err := <-healthDone:
		if err != nil {
			t.Fatal("nested actor health failed", err)
		}
	case <-ctx.Done():
		t.Fatal("health blocked behind enrollment")
	}
	select {
	case err := <-effectDone:
		t.Fatal("enrollment completed without release", err)
	default:
	}
	release <- struct{}{}
	select {
	case err := <-effectDone:
		if err != nil {
			t.Fatal("released actor enrollment did not reply", err)
		}
	case <-ctx.Done():
		t.Fatal("released enrollment remained pending")
	}
}

func TestUnixControlForwarderHonorsCallerAndCommandDeadlines(t *testing.T) {
	for _, callerShorter := range []bool{false, true} {
		t.Run(map[bool]string{false: "command", true: "caller"}[callerShorter], func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			command := forwarderCommand([]byte(`{"Version":1,"Operation":"inspect","ID":"` + uuid.NewString() + `","Generation":3}`))
			want := time.Now().Add(40 * time.Millisecond)
			if callerShorter {
				ctx, cancel = context.WithDeadline(ctx, want)
				defer cancel()
			} else {
				command.Deadline = want
			}
			var actual time.Time
			f, _, _ := newForwarderFixture(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				actual, _ = r.Context().Deadline()
				<-r.Context().Done()
				w.WriteHeader(http.StatusServiceUnavailable)
			}))
			if _, err := f.ForwardRemoteControl(ctx, command); !errors.Is(err, ErrDisabled) {
				t.Fatal("expired actor request reported success", err)
			}
			if !actual.Equal(want) {
				t.Fatal("forwarder extended the caller/command deadline")
			}
		})
	}
}

func TestUnixControlForwarderConstructorPinsAndRejectsLegacyMode(t *testing.T) {
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	b := persistentTestBinding()
	for _, scenario := range []struct {
		name, path string
		uid        uint32
		probe      ssh.PublicKey
		binding    BoundedRuntimeBinding
	}{
		{"relative socket", "control.sock", 1101, signer.PublicKey(), b},
		{"zero actor UID", "/run/tunnex-sandbox-qual/api/control.sock", 0, signer.PublicKey(), b},
		{"missing probe", "/run/tunnex-sandbox-qual/api/control.sock", 1101, nil, b},
		{"legacy trial", "/run/tunnex-sandbox-qual/api/control.sock", 1101, signer.PublicKey(), boundedTestBinding()},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			if _, err := NewUnixControlForwarder(scenario.path, scenario.uid, scenario.probe, scenario.binding); !errors.Is(err, ErrInvalid) {
				t.Fatal("invalid split constructor admitted", err)
			}
		})
	}
	originalReply, _ := json.Marshal(workerResponse{Version: 1, Binding: &b, HostPublicKey: string(ssh.MarshalAuthorizedKey(signer.PublicKey()))})
	f, err := NewUnixControlForwarder("/run/tunnex-sandbox-qual/api/control.sock", 1101, signer.PublicKey(), b)
	if err != nil {
		t.Fatal(err)
	}
	transport, ok := f.client.Transport.(*http.Transport)
	if !ok || !transport.DisableKeepAlives || transport.DialContext == nil || transport.MaxResponseHeaderBytes != 4096 {
		t.Fatal("constructor bypassed existing UID-pinned Unix transport")
	}
	b.Profiles[0].QualificationEvidence = "changed-after-construction"
	f.client = &http.Client{Transport: forwarderHTTPTransport{http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write(originalReply) })}}
	if _, err = f.ForwardRemoteControl(context.Background(), forwarderCommand([]byte(`{"Version":1,"Operation":"ping"}`))); err != nil {
		t.Fatal("caller mutation replaced fixed operator binding", err)
	}
}

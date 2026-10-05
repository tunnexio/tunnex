package sandboxes

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/sandboxrunner"
	"golang.org/x/crypto/ssh"
)

// UnixControlForwarder is the opt-in split transport's only local effect
// boundary. The existing Unix client authenticates the actor socket and kernel
// peer UID. The actor alone owns providers, files, lifecycle pins and leases.
// There is deliberately no effect lock here: nested bootstrap health must be
// able to reach the actor while an enrollment request is still pending.
type UnixControlForwarder struct {
	client         *http.Client
	binding        BoundedRuntimeBinding
	probePublicKey string
}

func NewUnixControlForwarder(socket string, actorUID uint32, probe ssh.PublicKey, binding BoundedRuntimeBinding) (*UnixControlForwarder, error) {
	if !binding.Persistent() || binding.Validate() != nil || probe == nil {
		return nil, ErrInvalid
	}
	actor, err := NewWorkerRPCClient(socket, actorUID, probe)
	if err != nil {
		return nil, err
	}
	actor.client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	// Freeze the operator's pins, including pointer/slice fields, rather than
	// allowing later configuration mutation to change a successful health reply.
	binding.Profiles = append([]QualifiedRuntimeProfile(nil), binding.Profiles...)
	if binding.RemoteTerminal != nil {
		copy := *binding.RemoteTerminal
		binding.RemoteTerminal = &copy
	}
	if binding.DevReservation != nil {
		copy := *binding.DevReservation
		binding.DevReservation = &copy
	}
	return &UnixControlForwarder{client: actor.client, binding: binding, probePublicKey: string(ssh.MarshalAuthorizedKey(probe))}, nil
}

// ForwardRemoteControl preserves the already admitted command's original wire
// payload. WorkerRPCClient.call is intentionally not used: its local grants map
// would replace the generation carried by the controller's durable command.
func (f *UnixControlForwarder) ForwardRemoteControl(ctx context.Context, command sandboxrunner.Command) (json.RawMessage, error) {
	now := time.Now()
	if f == nil || f.client == nil || ctx == nil || command.ID == uuid.Nil || !command.Deadline.After(now) || command.Deadline.Sub(now) > 30*time.Second || len(command.Payload) == 0 || len(command.Payload) > workerRPCLimit || len(command.Payload) > sandboxrunner.PayloadLimit {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(command.Payload))
	d.DisallowUnknownFields()
	var in workerRequest
	if d.Decode(&in) != nil || d.Decode(new(any)) != io.EOF || in.Version != workerRPCVersion || in.Operation == "" {
		return nil, ErrInvalid
	}
	ping := reflect.DeepEqual(in, workerRequest{Version: workerRPCVersion, Operation: "ping"})
	if in.Operation == "ping" && !ping || !ping && (in.ID == uuid.Nil || in.Generation < 1) {
		return nil, ErrInvalid
	}
	requestCtx, cancel := context.WithDeadline(ctx, command.Deadline)
	defer cancel()
	req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, "http://sandbox-worker/v1/control", bytes.NewReader(command.Payload))
	if err != nil {
		return nil, ErrInvalid
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := f.client.Do(req)
	if err != nil {
		return nil, ErrDisabled
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, ErrDisabled
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, workerRPCLimit+1))
	if err != nil || len(body) > workerRPCLimit || len(body) > sandboxrunner.PayloadLimit {
		return nil, ErrConflict
	}
	d = json.NewDecoder(bytes.NewReader(body))
	d.DisallowUnknownFields()
	var out workerResponse
	if d.Decode(&out) != nil || d.Decode(new(any)) != io.EOF || out.Version != workerRPCVersion {
		return nil, ErrConflict
	}
	switch out.Error {
	case "", "missing", "invalid", "conflict", "forbidden", "unavailable":
	default:
		return nil, ErrConflict
	}
	if ping && out.Error == "" && (out.Binding == nil || !bindingEqual(*out.Binding, f.binding) || out.HostPublicKey != f.probePublicKey) {
		return nil, ErrDisabled
	}
	// Structured actor denials must reach the controller as replies rather than
	// becoming an unanswered remote command. No binding result is cached here.
	return json.RawMessage(body), nil
}

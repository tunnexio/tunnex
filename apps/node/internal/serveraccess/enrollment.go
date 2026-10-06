package serveraccess

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/node/internal/control"
	"github.com/tunnexio/tunnex/packages/apptransport/bootstrap"
	"golang.org/x/crypto/ssh"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

type setupKey struct {
	private ed25519.PrivateKey
	signer  ssh.Signer
	running bool
	cancel  context.CancelFunc
}

// RunEnrollment is independent of terminal session credentials. Keys never touch disk.
func RunEnrollment(ctx context.Context, c *control.Client) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var mu sync.Mutex
	keys := map[string]*setupKey{}
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, k := range keys {
			if k.cancel != nil {
				k.cancel()
			}
			if !k.running {
				clear(k.private)
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			var jobs []bootstrap.Job
			if c.TerminalRPC(ctx, "GET", "enrollments", nil, &jobs) != nil {
				// No authority refresh means running provisioning channels are closed immediately.
				mu.Lock()
				for _, key := range keys {
					if key.cancel != nil {
						key.cancel()
					}
				}
				mu.Unlock()
				continue
			}
			wanted := map[string]bool{}
			for _, j := range jobs {
				if _, e := uuid.Parse(j.ID); e != nil || !j.ExpiresAt.After(time.Now()) {
					continue
				}
				wanted[j.ID] = true
				mu.Lock()
				key := keys[j.ID]
				if key == nil && j.State == "preparing" && len(keys) < 16 {
					_, private, e := ed25519.GenerateKey(rand.Reader)
					if e == nil {
						signer, e := ssh.NewSignerFromKey(private)
						if e == nil {
							key = &setupKey{private: private, signer: signer}
							keys[j.ID] = key
						} else {
							clear(private)
						}
					}
				}
				mu.Unlock()
				if key == nil {
					if j.State == "queued" || j.State == "running" {
						c.TerminalRPC(ctx, "POST", "enrollments/"+j.ID, bootstrap.Report{Result: "gateway_key_lost"}, nil)
					}
					continue
				}
				if j.State == "preparing" {
					c.TerminalRPC(ctx, "POST", "enrollments/"+j.ID, bootstrap.Report{PublicKey: string(ssh.MarshalAuthorizedKey(key.signer.PublicKey()))}, nil)
				}
				if j.State == "queued" {
					mu.Lock()
					if key.running {
						mu.Unlock()
						continue
					}
					key.running = true
					runCtx, cancel := context.WithDeadline(ctx, j.ExpiresAt)
					key.cancel = cancel
					mu.Unlock()
					if c.TerminalRPC(ctx, "POST", "enrollments/"+j.ID, bootstrap.Report{Result: "running"}, nil) != nil {
						cancel()
						continue
					}
					go func(j bootstrap.Job, key *setupKey) {
						defer cancel()
						defer clear(key.private)
						result, e := executeEnrollment(runCtx, c, j, key.signer)
						code := "ok"
						if e != nil {
							code = classifyResult(e)
							if code == "failed" {
								code = "setup_failed"
							}
						}
						reportCtx, stop := context.WithTimeout(context.Background(), 2*time.Second)
						defer stop()
						c.TerminalRPC(reportCtx, "POST", "enrollments/"+j.ID, bootstrap.Report{Result: code, Setup: result}, nil)
					}(j, key)
				}
			}
			mu.Lock()
			for id, key := range keys {
				if !wanted[id] {
					if key.cancel != nil {
						key.cancel()
					}
					if !key.running {
						clear(key.private)
					}
					delete(keys, id)
				}
			}
			mu.Unlock()
		}
	}
}
func validateSetupJob(j bootstrap.Job) error {
	ip, e := netip.ParseAddr(j.IP)
	if e != nil || !ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.Zone() != "" || j.Port < 1 || j.Port > 65535 || j.Account == "root" || j.Account == "" || len(j.Script) == 0 || len(j.Script) > 131072 {
		return errors.New("invalid setup material")
	}
	return nil
}
func executeEnrollment(ctx context.Context, c *control.Client, j bootstrap.Job, signer ssh.Signer) (*bootstrap.Result, error) {
	if e := validateSetupJob(j); e != nil {
		return nil, e
	}
	ip, _ := netip.ParseAddr(j.IP)
	if e := c.TerminalDestination(ctx, ip); e != nil {
		return nil, e
	}
	bounded, cancel := context.WithTimeout(ctx, 110*time.Second)
	defer cancel()
	raw, e := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(bounded, "tcp", net.JoinHostPort(j.IP, strconv.Itoa(j.Port)))
	if e != nil {
		return nil, e
	}
	defer raw.Close()
	go func() { <-bounded.Done(); raw.Close() }()
	raw.SetDeadline(time.Now().Add(5 * time.Second))
	config := &ssh.ClientConfig{User: j.Account, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyAlgorithms: []string{ssh.KeyAlgoED25519}, HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
		if ssh.FingerprintSHA256(key) != j.Fingerprint {
			return errHostKeyMismatch
		}
		return nil
	}}
	conn, chans, reqs, e := ssh.NewClientConn(raw, net.JoinHostPort(j.IP, strconv.Itoa(j.Port)), config)
	if e != nil {
		return nil, e
	}
	raw.SetDeadline(time.Time{})
	client := ssh.NewClient(conn, chans, reqs)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		return nil, e
	}
	defer session.Close()
	session.Stdin = strings.NewReader(j.Script)
	output := &boundedSetupOutput{}
	session.Stdout = output
	session.Stderr = output
	// The target-side forced command verifies the exact installer digest before execution.
	if e = session.Run("tunnex-enroll"); e != nil {
		return nil, e
	}
	return parseSetupOutput(output.Bytes())
}

type boundedSetupOutput struct {
	sync.Mutex
	bytes.Buffer
}

func (b *boundedSetupOutput) Write(p []byte) (int, error) {
	b.Lock()
	defer b.Unlock()
	if b.Len()+len(p) > 65536 {
		return 0, errors.New("setup output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func parseSetupOutput(output []byte) (*bootstrap.Result, error) {
	const begin = "BEGIN TUNNEX SSH RESULT\n"
	const end = "\nEND TUNNEX SSH RESULT"
	a := bytes.Index(output, []byte(begin))
	if a < 0 {
		return nil, errors.New("missing setup result")
	}
	output = output[a+len(begin):]
	b := bytes.Index(output, []byte(end))
	if b < 0 {
		return nil, errors.New("missing setup result end")
	}
	var result bootstrap.Result
	decoder := json.NewDecoder(bytes.NewReader(output[:b]))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(&result); e != nil {
		return nil, e
	}
	return &result, nil
}

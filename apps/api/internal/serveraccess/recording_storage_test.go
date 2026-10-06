package serveraccess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	secret "github.com/tunnexio/tunnex/apps/api/internal/crypto"
)

func storageInput(t *testing.T, c recordingStorageConfig) api.ServerAccessRecordingStorageInput {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	var in api.ServerAccessRecordingStorageInput
	if err = json.Unmarshal(raw, &in); err != nil {
		t.Fatal(err)
	}
	return in
}
func TestRecordingStoragePostgresDefaultAndExplicitSelection(t *testing.T) {
	org := uuid.New()
	service := &Service{}
	config, err := service.openRecordingStorage(org, nil)
	if err != nil || config.Org != org || config.Kind != "postgres" {
		t.Fatal("unconfigured recording storage must default to PostgreSQL")
	}
	view, err := storageView(config)
	if err != nil || string(view.Kind) != "postgres" {
		t.Fatal("public default must match PostgreSQL capture storage")
	}
	old := recordingStorageConfig{Org: org, Kind: "s3", Endpoint: "https://objects.example", Bucket: "recordings", Region: "us-east-1", AccessKeyID: "example", SecretAccessKey: "old-secret"}
	selected, err := mergeStorageInput(org, storageInput(t, config), old)
	if err != nil || selected.Kind != "postgres" || selected.Endpoint != "" || selected.SecretAccessKey != "" {
		t.Fatal("explicit PostgreSQL selection inherited an external destination")
	}
}

func TestRecordingStorageDestinationAndCredentialBoundaries(t *testing.T) {
	t.Setenv("TUNNEX_SERVER_ACCESS_STORAGE_ALLOW_INSECURE", "")
	org := uuid.New()
	c := recordingStorageConfig{Org: org, Kind: "s3", Endpoint: "https://objects.example", Bucket: "recordings", Region: "us-east-1", AccessKeyID: "example", SecretAccessKey: "private-secret", Prefix: "terminal/v1"}
	if err := validateStorage(c); err != nil {
		t.Fatal(err)
	}
	saved := c
	c.SecretAccessKey = ""
	got, err := mergeStorageInput(org, storageInput(t, c), saved)
	if err != nil || got.SecretAccessKey != saved.SecretAccessKey {
		t.Fatal("same destination did not preserve omitted credential")
	}
	c.Endpoint = "https://different.example"
	if _, err = mergeStorageInput(org, storageInput(t, c), saved); err == nil {
		t.Fatal("new endpoint inherited old secret")
	}
	c = saved
	c.AccessKeyID = "other"
	c.SecretAccessKey = ""
	if _, err = mergeStorageInput(org, storageInput(t, c), saved); err == nil {
		t.Fatal("new credential identity inherited old secret")
	}
	c = saved
	empty := ""
	in := storageInput(t, c)
	in.SecretAccessKey = &empty
	if _, err = mergeStorageInput(org, in, saved); err == nil {
		t.Fatal("explicit empty credential preserved the secret")
	}
	for _, endpoint := range []string{"http://objects.example", "http://127.0.0.1:9000", "https://user:pass@objects.example", "https://objects.example?token=secret", "https://objects.example/a/../b", "https://objects.example/%2e%2e/private", "https://169.254.169.254", "https://objects.example/#fragment"} {
		c = saved
		c.Endpoint = endpoint
		if validateStorage(c) == nil {
			t.Fatalf("unsafe endpoint accepted: %s", endpoint)
		}
	}
	for _, prefix := range []string{"../escape", "/absolute", "a/../b", "a//b", "a/", "a\\b"} {
		c = saved
		c.Prefix = prefix
		if validateStorage(c) == nil {
			t.Fatalf("unsafe prefix accepted: %s", prefix)
		}
	}
	t.Setenv("TUNNEX_SERVER_ACCESS_STORAGE_ALLOW_INSECURE", "true")
	c = saved
	c.Endpoint = "http://127.0.0.1:9000"
	if validateStorage(c) != nil {
		t.Fatal("explicit local emulator endpoint refused")
	}
	c.Endpoint = "http://10.0.0.2:9000"
	if validateStorage(c) == nil {
		t.Fatal("insecure remote endpoint accepted")
	}
	view, err := storageView(saved)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(view)
	if bytes.Contains(raw, []byte("private-secret")) || bytes.Contains(raw, []byte("secret_access_key")) || bytes.Contains(raw, []byte("account_key")) {
		t.Fatal("secret reached public view")
	}
}
func TestRecordingStorageSnapshotIsEncryptedAndTenantBound(t *testing.T) {
	master := bytes.Repeat([]byte{3}, 32)
	sealer, err := secret.NewSealer(master)
	if err != nil {
		t.Fatal(err)
	}
	svc := &Service{sealer: sealer}
	org := uuid.New()
	c := recordingStorageConfig{Org: org, Kind: "s3", Endpoint: "https://objects.example", Bucket: "recordings", Region: "us-east-1", AccessKeyID: "example", SecretAccessKey: "hidden"}
	raw, _ := json.Marshal(c)
	sealed, err := sealer.Seal(raw)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "hidden") {
		t.Fatal("unencrypted snapshot")
	}
	store, err := svc.loadRecordingStorage(context.Background(), org, []byte(sealed))
	if err != nil || store == nil {
		t.Fatal("valid snapshot refused")
	}
	if _, err = svc.loadRecordingStorage(context.Background(), uuid.New(), []byte(sealed)); err == nil {
		t.Fatal("foreign tenant accepted snapshot")
	}
	b := []byte(sealed)
	b[len(b)/2] ^= 1
	if _, err = svc.loadRecordingStorage(context.Background(), org, b); err == nil {
		t.Fatal("tampered snapshot accepted")
	}
	store, err = svc.loadRecordingStorage(context.Background(), org, nil)
	if err != nil || store != nil {
		t.Fatal("empty snapshot did not select PostgreSQL")
	}
}
func TestFilesystemRecordingStorageDurabilityIsolationAndSymlinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	org, id := uuid.New(), uuid.New()
	store := &filesystemRecordingStore{c: recordingStorageConfig{Org: org, Kind: "filesystem", Path: root, Prefix: "recordings"}}
	ctx := context.Background()
	data := []byte("encrypted chunk bytes")
	if err = store.Put(ctx, org, id, 0, data); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, org, id, 0)
	if err != nil || !bytes.Equal(got, data) {
		t.Fatal("filesystem read differs")
	}
	key, _ := recordingObjectKey(store.c, org, id, 0)
	info, err := os.Stat(filepath.Join(root, key))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("chunk permissions not private")
	}
	if err = store.Put(ctx, uuid.New(), id, 0, data); err == nil {
		t.Fatal("foreign tenant write accepted")
	}
	if _, err = store.Get(ctx, org, id, -1); err == nil {
		t.Fatal("invalid sequence accepted")
	}
	if err = store.Put(ctx, org, id, 0, bytes.Repeat([]byte{1}, recordingObjectLimit+1)); err == nil {
		t.Fatal("oversized chunk accepted")
	}
	if err = store.Probe(ctx); err != nil {
		t.Fatal(err)
	}
	if err = store.Delete(ctx, org, id, 0); err != nil {
		t.Fatal(err)
	}
	if err = store.Delete(ctx, org, id, 0); err != nil {
		t.Fatal("missing chunk delete not idempotent")
	}
	outsider, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(outsider, "sensitive")
	if err = os.WriteFile(target, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Symlink(target, filepath.Join(root, key)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.Get(ctx, org, id, 0); err == nil {
		t.Fatal("symlink target read accepted")
	}
	if err = store.Put(ctx, org, id, 0, []byte("overwrite")); err == nil {
		t.Fatal("symlink write accepted")
	}
	if err = store.Delete(ctx, org, id, 0); err == nil {
		t.Fatal("symlink delete accepted")
	}
	preserved, _ := os.ReadFile(target)
	if !bytes.Equal(preserved, data) {
		t.Fatal("outside target changed")
	}
	linkRoot := filepath.Join(root, "root-link")
	if err = os.Symlink(outsider, linkRoot); err != nil {
		t.Fatal(err)
	}
	linked := &filesystemRecordingStore{c: recordingStorageConfig{Org: org, Kind: "filesystem", Path: linkRoot}}
	if err = linked.Put(ctx, org, id, 0, data); err == nil {
		t.Fatal("symlink root accepted")
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err = store.Put(cancelled, org, id, 1, data); err == nil {
		t.Fatal("cancelled write accepted")
	}
}
func TestS3PublishedAWSVector(t *testing.T) {
	// AWS's published GET Object /test.txt, range bytes=0-9, 20130524 vector.
	// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
	req, _ := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	req.Header.Set("Range", "bytes=0-9")
	now := time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC)
	c := recordingStorageConfig{Region: "us-east-1", AccessKeyID: "AKIAIOSFODNN7EXAMPLE", SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"}
	signS3(req, c, nil, now)
	if !strings.HasSuffix(req.Header.Get("Authorization"), "Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41") {
		t.Fatal("signature differs from published AWS vector")
	}
}
func TestAzureCanonicalContractVector(t *testing.T) {
	// Expected HMAC computed independently with Python hashlib from the Microsoft
	// documented 12-line SharedKey layout, sorted x-ms headers and resource path.
	req, _ := http.NewRequest(http.MethodPut, "https://testaccount.blob.core.windows.net/container/example.bin", bytes.NewReader([]byte("data")))
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("x-ms-blob-type", "BlockBlob")
	c := recordingStorageConfig{AccountName: "testaccount", AccountKey: base64.StdEncoding.EncodeToString([]byte("01234567890123456789012345678901"))}
	now := time.Date(2015, 6, 26, 23, 39, 12, 0, time.UTC)
	if err := signAzure(req, c, now); err != nil {
		t.Fatal(err)
	}
	if req.Header.Get("Authorization") != "SharedKey testaccount:dpqsJogShNjXx/W9anf1wgo/dAK9ux2V2PWkQJR38mM=" {
		t.Fatal("Azure signature differs from independent canonical contract vector")
	}
}
func TestObjectRecordingStorageAuthenticatedRoundtrip(t *testing.T) {
	t.Setenv("TUNNEX_SERVER_ACCESS_STORAGE_ALLOW_INSECURE", "true")
	for _, kind := range []string{"s3", "gcs", "azure"} {
		t.Run(kind, func(t *testing.T) {
			org, id := uuid.New(), uuid.New()
			var mu sync.Mutex
			objects := map[string][]byte{}
			var bad atomic.Bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				body, _ := io.ReadAll(r.Body)
				wantPrefix := "AWS4-HMAC-SHA256 Credential=example/"
				if kind == "azure" {
					wantPrefix = "SharedKey testaccount:"
				}
				if !strings.HasPrefix(r.Header.Get("Authorization"), wantPrefix) || strings.Contains(r.Header.Get("Authorization"), "private-secret") {
					bad.Store(true)
					w.WriteHeader(403)
					return
				}
				if kind != "azure" {
					digest := sha256.Sum256(body)
					if r.Header.Get("x-amz-content-sha256") != hex.EncodeToString(digest[:]) {
						bad.Store(true)
					}
					if kind == "gcs" && !strings.Contains(r.Header.Get("Authorization"), "/auto/s3/aws4_request") {
						bad.Store(true)
					}
				}
				if r.Method == http.MethodPut && kind == "azure" && r.Header.Get("x-ms-blob-type") != "BlockBlob" {
					bad.Store(true)
				}
				if !strings.Contains(r.URL.Path, "/recordings/terminal/"+org.String()+"/") {
					bad.Store(true)
				}
				mu.Lock()
				defer mu.Unlock()
				switch r.Method {
				case http.MethodPut:
					objects[r.URL.Path] = bytes.Clone(body)
					w.WriteHeader(201)
				case http.MethodGet:
					if data, ok := objects[r.URL.Path]; ok {
						w.Write(data)
					} else {
						w.WriteHeader(404)
					}
				case http.MethodDelete:
					if _, ok := objects[r.URL.Path]; ok {
						delete(objects, r.URL.Path)
						w.WriteHeader(204)
					} else {
						w.WriteHeader(404)
					}
				}
			}))
			defer server.Close()
			c := recordingStorageConfig{Org: org, Kind: kind, Endpoint: server.URL, Bucket: "recordings", Prefix: "terminal", Region: "us-east-1", AccessKeyID: "example", SecretAccessKey: "private-secret"}
			if kind == "gcs" {
				c.Region = ""
			}
			if kind == "azure" {
				c.Region = ""
				c.AccessKeyID = ""
				c.SecretAccessKey = ""
				c.AccountName = "testaccount"
				c.AccountKey = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
			}
			store, err := newRecordingStore(c)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			data := []byte("encrypted object bytes")
			if err = store.Put(ctx, org, id, 0, data); err != nil {
				t.Fatal(err)
			}
			got, err := store.Get(ctx, org, id, 0)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatal("roundtrip mismatch")
			}
			if err = store.Probe(ctx); err != nil {
				t.Fatal(err)
			}
			if err = store.Delete(ctx, org, id, 0); err != nil {
				t.Fatal(err)
			}
			if err = store.Delete(ctx, org, id, 0); err != nil {
				t.Fatal("missing object delete not idempotent")
			}
			if err = store.Put(ctx, uuid.New(), id, 0, data); err == nil {
				t.Fatal("foreign tenant uploaded object")
			}
			if bad.Load() {
				t.Fatal("request authentication or tenant key boundary failed")
			}
			mu.Lock()
			defer mu.Unlock()
			if len(objects) != 0 {
				t.Fatal("probe left object payload")
			}
		})
	}
}
func TestObjectRecordingStorageBoundsRedirectAndRedaction(t *testing.T) {
	t.Setenv("TUNNEX_SERVER_ACCESS_STORAGE_ALLOW_INSECURE", "true")
	org, id := uuid.New(), uuid.New()
	var leaked atomic.Int32
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaked.Add(1) }))
	defer destination.Close()
	for _, mode := range []string{"redirect", "oversize", "forbidden", "stalled"} {
		t.Run(mode, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch mode {
				case "redirect":
					http.Redirect(w, r, destination.URL, 307)
				case "oversize":
					w.Write(bytes.Repeat([]byte{1}, recordingObjectLimit+1))
				case "forbidden":
					w.WriteHeader(403)
					w.Write([]byte("private-secret diagnostic"))
				case "stalled":
					<-r.Context().Done()
				}
			}))
			defer server.Close()
			store, err := newRecordingStore(recordingStorageConfig{Org: org, Kind: "s3", Endpoint: server.URL, Bucket: "recordings", Region: "us-east-1", AccessKeyID: "example", SecretAccessKey: "private-secret"})
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
			defer cancel()
			started := time.Now()
			_, err = store.Get(ctx, org, id, 0)
			if err == nil || strings.Contains(err.Error(), "private-secret") {
				t.Fatal("failure was accepted or leaked credential")
			}
			if time.Since(started) > time.Second {
				t.Fatal("request cancellation not bounded")
			}
		})
	}
	if leaked.Load() != 0 {
		t.Fatal("redirect forwarded authenticated request")
	}
}

func TestFilesystemRecordingConcurrentDirectoryReplacement(t *testing.T) {
	// Repeatedly replace either the configured root or the tenant subtree with a
	// symlink carrying a plausible matching session/chunk. Reads/writes may fail
	// during replacement, but must never touch the alternate directory's payload.
	for _, boundary := range []string{"configured_root", "tenant_subtree"} {
		t.Run(boundary, func(t *testing.T) {
			base, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			root := filepath.Join(base, "mounted")
			if err = os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			org, id := uuid.New(), uuid.New()
			store := &filesystemRecordingStore{c: recordingStorageConfig{Org: org, Kind: "filesystem", Path: root}}
			good, bad := []byte("correct tenant ciphertext"), []byte("OTHER TENANT ciphertext")
			if err = store.Put(context.Background(), org, id, 0, good); err != nil {
				t.Fatal(err)
			}
			key, _ := recordingObjectKey(store.c, org, id, 0)
			target := root
			alternate := filepath.Join(base, "alternate")
			foreignFile := filepath.Join(alternate, key)
			if boundary == "tenant_subtree" {
				target = filepath.Join(root, org.String())
				alternate = filepath.Join(root, uuid.NewString())
				foreignFile = filepath.Join(alternate, id.String(), "000000.bin")
			}
			if err = os.MkdirAll(filepath.Dir(foreignFile), 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(foreignFile, bad, 0600); err != nil {
				t.Fatal(err)
			}
			backup := target + "-original"
			var running atomic.Bool
			running.Store(true)
			done := make(chan error, 1)
			started := make(chan struct{})
			var swaps atomic.Int32
			var escapedDuringWrite atomic.Bool
			go func() {
				for running.Load() {
					if err := os.Rename(target, backup); err != nil {
						done <- err
						return
					}
					if err := os.Symlink(alternate, target); err != nil {
						_ = os.Rename(backup, target)
						done <- err
						return
					}
					if swaps.Add(1) == 1 {
						close(started)
					}
					// A write against the actively substituted path must fail closed.
					if err := store.Put(context.Background(), org, id, 0, good); err == nil {
						escapedDuringWrite.Store(true)
					}
					// Give concurrent readers opportunities to overlap the substituted path.
					for i := 0; i < 3; i++ {
						time.Sleep(time.Microsecond)
					}
					if err := os.Remove(target); err != nil {
						done <- err
						return
					}
					if err := os.Rename(backup, target); err != nil {
						done <- err
						return
					}
				}
				done <- nil
			}()
			select {
			case <-started:
			case err := <-done:
				t.Fatal(err)
			}
			var escaped atomic.Bool
			var readers sync.WaitGroup
			for i := 0; i < 4; i++ {
				readers.Add(1)
				go func() {
					defer readers.Done()
					for j := 0; j < 200; j++ {
						data, err := store.Get(context.Background(), org, id, 0)
						if err == nil && !bytes.Equal(data, good) {
							escaped.Store(true)
						}
					}
				}()
			}
			readers.Wait()
			running.Store(false)
			if err = <-done; err != nil {
				t.Fatal(err)
			}
			if escaped.Load() || escapedDuringWrite.Load() {
				t.Fatal("directory replacement exposed another tenant payload or accepted aliased write")
			}
			preserved, err := os.ReadFile(foreignFile)
			if err != nil || !bytes.Equal(preserved, bad) {
				t.Fatal("directory replacement redirected a write")
			}
		})
	}
}

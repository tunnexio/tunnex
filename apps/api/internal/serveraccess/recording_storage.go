package serveraccess

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/tunnexio/tunnex/apps/api/internal/api"
	"github.com/tunnexio/tunnex/apps/api/internal/apierr"
)

// Each recording keeps this encrypted destination snapshot. Credentials never
// use ambient cloud SDK/environment providers or enter the public projection.
type recordingStorageConfig struct {
	Org             uuid.UUID `json:"org_id"`
	Kind            string    `json:"kind"`
	Path            string    `json:"path,omitempty"`
	Endpoint        string    `json:"endpoint,omitempty"`
	Bucket          string    `json:"bucket,omitempty"`
	Region          string    `json:"region,omitempty"`
	Prefix          string    `json:"prefix,omitempty"`
	AccessKeyID     string    `json:"access_key_id,omitempty"`
	SecretAccessKey string    `json:"secret_access_key,omitempty"`
	AccountName     string    `json:"account_name,omitempty"`
	AccountKey      string    `json:"account_key,omitempty"`
}

type recordingStore interface {
	Put(context.Context, uuid.UUID, uuid.UUID, int, []byte) error
	Get(context.Context, uuid.UUID, uuid.UUID, int) ([]byte, error)
	Delete(context.Context, uuid.UUID, uuid.UUID, int) error
	Probe(context.Context) error
}

const recordingObjectLimit = 64 << 10

func storageUnavailable() error {
	return apierr.New(503, "recording_storage_unavailable", "Recording storage operation failed")
}
func invalidStorage() error {
	return apierr.BadRequest("invalid_recording_storage", "Invalid recording storage configuration")
}

func (s *Service) savedRecordingStorage(ctx context.Context, org uuid.UUID) (recordingStorageConfig, error) {
	c := recordingStorageConfig{Org: org, Kind: "postgres"}
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT recording_storage_sealed FROM server_access_settings WHERE org_id=$1`, org).Scan(&sealed)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && len(sealed) == 0 {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	return s.openRecordingStorage(org, sealed)
}
func (s *Service) openRecordingStorage(org uuid.UUID, sealed []byte) (recordingStorageConfig, error) {
	c := recordingStorageConfig{Org: org, Kind: "postgres"}
	if len(sealed) == 0 {
		return c, nil
	}
	raw, err := s.sealer.Open(string(sealed))
	if err != nil {
		return c, storageUnavailable()
	}
	defer clear(raw)
	if json.Unmarshal(raw, &c) != nil || c.Org != org {
		return c, storageUnavailable()
	}
	return c, nil
}
func storageView(c recordingStorageConfig) (api.ServerAccessRecordingStorage, error) {
	var out api.ServerAccessRecordingStorage
	// Only explicitly selected nonsecret fields can reach this response.
	raw, err := json.Marshal(map[string]any{"kind": c.Kind, "path": c.Path, "endpoint": c.Endpoint, "bucket": c.Bucket, "region": c.Region, "prefix": c.Prefix, "access_key_id": c.AccessKeyID, "account_name": c.AccountName, "credentials_configured": (c.Kind == "s3" || c.Kind == "gcs") && c.SecretAccessKey != "" || c.Kind == "azure" && c.AccountKey != ""})
	if err == nil {
		err = json.Unmarshal(raw, &out)
	}
	return out, err
}
func (s *Service) GetRecordingStorage(ctx context.Context, org uuid.UUID) (api.ServerAccessRecordingStorage, error) {
	var out api.ServerAccessRecordingStorage
	if err := s.available(); err != nil {
		return out, err
	}
	c, err := s.savedRecordingStorage(ctx, org)
	if err != nil {
		return out, err
	}
	return storageView(c)
}
func sameStorageDestination(a, b recordingStorageConfig) bool {
	return a.Kind == b.Kind && a.Path == b.Path && a.Endpoint == b.Endpoint && a.Bucket == b.Bucket && a.Region == b.Region && a.Prefix == b.Prefix && a.AccessKeyID == b.AccessKeyID && a.AccountName == b.AccountName
}
func mergeStorageInput(org uuid.UUID, in api.ServerAccessRecordingStorageInput, saved recordingStorageConfig) (recordingStorageConfig, error) {
	raw, err := json.Marshal(in)
	if err != nil {
		return recordingStorageConfig{}, invalidStorage()
	}
	var c recordingStorageConfig
	if json.Unmarshal(raw, &c) != nil {
		return c, invalidStorage()
	}
	c.Org = org
	var fields map[string]json.RawMessage
	_ = json.Unmarshal(raw, &fields)
	if sameStorageDestination(c, saved) {
		if v, ok := fields["secret_access_key"]; !ok || string(v) == "null" {
			c.SecretAccessKey = saved.SecretAccessKey
		}
		if v, ok := fields["account_key"]; !ok || string(v) == "null" {
			c.AccountKey = saved.AccountKey
		}
	}
	if err = validateStorage(c); err != nil {
		return c, err
	}
	return c, nil
}
func (s *Service) ConfigureRecordingStorage(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessRecordingStorageInput) (api.ServerAccessRecordingStorage, error) {
	var out api.ServerAccessRecordingStorage
	if err := s.available(); err != nil {
		return out, err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return out, err
	}
	defer tx.Rollback(ctx)
	// Serializes read/merge/save, so omitted credentials cannot race a destination edit.
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtext('server_access_storage'),hashtext($1))`, org.String()); err != nil {
		return out, err
	}
	saved, err := s.savedRecordingStorage(ctx, org)
	if err != nil {
		return out, err
	}
	c, err := mergeStorageInput(org, in, saved)
	if err != nil {
		return out, err
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return out, err
	}
	defer clear(raw)
	sealed, err := s.sealer.Seal(raw)
	if err != nil {
		return out, err
	}
	// A valid destination is saved without pretending a probe or readiness passed.
	tag, err := tx.Exec(ctx, `UPDATE server_access_settings SET recording_storage_sealed=$2 WHERE org_id=$1`, org, []byte(sealed))
	if err != nil {
		return out, err
	}
	if tag.RowsAffected() != 1 {
		return out, missing()
	}
	if err = s.audit(ctx, tx, org, actor, "recording_storage_configured", org, map[string]any{"kind": c.Kind}); err != nil {
		return out, err
	}
	if err = tx.Commit(ctx); err != nil {
		return out, err
	}
	return storageView(c)
}
func (s *Service) TestRecordingStorage(ctx context.Context, org, actor uuid.UUID, in api.ServerAccessRecordingStorageInput) error {
	if err := s.available(); err != nil {
		return err
	}
	saved, err := s.savedRecordingStorage(ctx, org)
	if err != nil {
		return err
	}
	c, err := mergeStorageInput(org, in, saved)
	if err != nil {
		return err
	}
	store, err := newRecordingStore(c)
	if err != nil {
		return err
	}
	if store != nil {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if err = store.Probe(bounded); err != nil {
			return storageUnavailable()
		}
	}
	// PostgreSQL availability is checked via the same configured recording table.
	if store == nil {
		if _, err = s.pool.Exec(ctx, `SELECT 1 FROM server_access_recordings LIMIT 0`); err != nil {
			return storageUnavailable()
		}
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	if err = s.audit(ctx, tx, org, actor, "recording_storage_checked", org, map[string]any{"kind": c.Kind, "status": "passed"}); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
func (s *Service) loadRecordingStorage(ctx context.Context, org uuid.UUID, sealed []byte) (recordingStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := s.openRecordingStorage(org, sealed)
	if err != nil {
		return nil, err
	}
	return newRecordingStore(c)
}

var storageSegment = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
var azureAccount = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
var azureContainer = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)

func validateStorage(c recordingStorageConfig) error {
	if c.Org == uuid.Nil {
		return invalidStorage()
	}
	if len(c.Prefix) > 256 || strings.HasPrefix(c.Prefix, "/") || strings.HasSuffix(c.Prefix, "/") {
		return invalidStorage()
	}
	if c.Prefix != "" {
		for _, part := range strings.Split(c.Prefix, "/") {
			if part == "." || part == ".." || !storageSegment.MatchString(part) {
				return invalidStorage()
			}
		}
	}
	switch c.Kind {
	case "postgres":
		if c.Path != "" || c.Endpoint != "" || c.Bucket != "" || c.Region != "" || c.Prefix != "" || c.AccessKeyID != "" || c.SecretAccessKey != "" || c.AccountName != "" || c.AccountKey != "" {
			return invalidStorage()
		}
	case "filesystem":
		if !filepath.IsAbs(c.Path) || filepath.Clean(c.Path) != c.Path || c.Path == "/" || len(c.Path) > 1024 || c.Endpoint != "" || c.Bucket != "" || c.Region != "" || c.AccessKeyID != "" || c.SecretAccessKey != "" || c.AccountName != "" || c.AccountKey != "" {
			return invalidStorage()
		}
		for _, special := range []string{"/proc", "/sys", "/dev"} {
			if c.Path == special || strings.HasPrefix(c.Path, special+"/") {
				return invalidStorage()
			}
		}
	case "s3", "gcs", "azure":
		if c.Path != "" || !storageSegment.MatchString(c.Bucket) || c.Bucket == "." || c.Bucket == ".." {
			return invalidStorage()
		}
		if _, err := storageEndpoint(c.Endpoint); err != nil {
			return err
		}
		if c.Kind == "s3" || c.Kind == "gcs" {
			if !(storageSegment.MatchString(c.Region) || c.Kind == "gcs" && c.Region == "") || len(c.AccessKeyID) < 1 || len(c.AccessKeyID) > 256 || len(c.SecretAccessKey) < 1 || len(c.SecretAccessKey) > 4096 || strings.ContainsAny(c.AccessKeyID, "\r\n /,") || c.AccountName != "" || c.AccountKey != "" {
				return invalidStorage()
			}
		} else {
			k, err := base64.StdEncoding.DecodeString(c.AccountKey)
			if err != nil || len(k) < 16 || len(k) > 128 || !azureAccount.MatchString(c.AccountName) || !azureContainer.MatchString(c.Bucket) || strings.Contains(c.Bucket, "--") || c.AccessKeyID != "" || c.SecretAccessKey != "" || c.Region != "" {
				return invalidStorage()
			}
		}
	default:
		return invalidStorage()
	}
	return nil
}
func storageEndpoint(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" || strings.ContainsAny(u.Path, "\\\x00") || path.Clean(u.Path) != "." && path.Clean(u.Path) != u.Path && strings.TrimSuffix(u.Path, "/") != path.Clean(u.Path) {
		return nil, invalidStorage()
	}
	// Generated object keys use only unreserved characters. Restrict optional
	// endpoint base paths to the same alphabet so Go URL escaping exactly matches
	// the AWS canonical URI and Azure encoded-resource contract.
	for _, part := range strings.Split(strings.Trim(u.Path, "/"), "/") {
		if part != "" && (part == "." || part == ".." || !storageSegment.MatchString(part)) {
			return nil, invalidStorage()
		}
	}
	host := u.Hostname()
	ip := net.ParseIP(host)
	local := strings.EqualFold(host, "localhost") || ip != nil && ip.IsLoopback()
	if u.Scheme != "https" && !(u.Scheme == "http" && local && os.Getenv("TUNNEX_SERVER_ACCESS_STORAGE_ALLOW_INSECURE") == "true") {
		return nil, invalidStorage()
	}
	if ip != nil && (ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsMulticast()) {
		return nil, invalidStorage()
	}
	return u, nil
}
func newRecordingStore(c recordingStorageConfig) (recordingStore, error) {
	if err := validateStorage(c); err != nil {
		return nil, err
	}
	if c.Kind == "postgres" {
		return nil, nil
	}
	if c.Kind == "filesystem" {
		return &filesystemRecordingStore{c: c}, nil
	}
	u, err := storageEndpoint(c.Endpoint)
	if err != nil {
		return nil, err
	}
	if c.Kind == "gcs" && c.Region == "" {
		c.Region = "auto"
	}
	return &objectRecordingStore{c: c, endpoint: u, client: recordingHTTPClient}, nil
}

// Shared, bounded transport avoids allocating a TLS pool for every captured chunk.
var recordingHTTPClient = &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{
	Proxy: nil, TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, MaxIdleConns: 8,
	MaxIdleConnsPerHost: 2, MaxConnsPerHost: 16, IdleConnTimeout: 30 * time.Second,
	ResponseHeaderTimeout: time.Second,
}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}

func recordingObjectKey(c recordingStorageConfig, org, id uuid.UUID, seq int) (string, error) {
	if org != c.Org || org == uuid.Nil || id == uuid.Nil || seq < 0 || seq > recordingEventLimit {
		return "", invalidStorage()
	}
	key := org.String() + "/" + id.String() + "/" + fmt.Sprintf("%06d.bin", seq)
	if c.Prefix != "" {
		key = c.Prefix + "/" + key
	}
	return key, nil
}
func storageProbe(ctx context.Context, store recordingStore, org uuid.UUID) error {
	id := uuid.New()
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return storageUnavailable()
	}
	// A reserved sequence in a random session namespace cannot collide with capture.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = store.Delete(cleanup, org, id, recordingEventLimit)
	}()
	if err := store.Put(ctx, org, id, recordingEventLimit, data); err != nil {
		return err
	}
	actual, err := store.Get(ctx, org, id, recordingEventLimit)
	if err != nil || !bytes.Equal(actual, data) {
		return storageUnavailable()
	}
	return store.Delete(ctx, org, id, recordingEventLimit)
}

type filesystemRecordingStore struct{ c recordingStorageConfig }

func (f *filesystemRecordingStore) Probe(ctx context.Context) error {
	return storageProbe(ctx, f, f.c.Org)
}

type objectRecordingStore struct {
	c        recordingStorageConfig
	endpoint *url.URL
	client   *http.Client
}

func (o *objectRecordingStore) request(ctx context.Context, method string, org, id uuid.UUID, seq int, data []byte) ([]byte, error) {
	key, err := recordingObjectKey(o.c, org, id, seq)
	if err != nil {
		return nil, err
	}
	return o.requestObject(ctx, method, key, data, recordingObjectLimit)
}
func (o *objectRecordingStore) requestObject(ctx context.Context, method, key string, data []byte, limit int) ([]byte, error) {
	if method == http.MethodPut && (len(data) == 0 || len(data) > limit) {
		return nil, invalidStorage()
	}
	u := *o.endpoint
	u.Path = strings.TrimSuffix(u.Path, "/") + "/" + o.c.Bucket + "/" + key
	req, err := http.NewRequestWithContext(ctx, method, u.String(), bytes.NewReader(data))
	if err != nil {
		return nil, storageUnavailable()
	}
	if method == http.MethodPut {
		req.Header.Set("Content-Type", "application/octet-stream")
	}
	if o.c.Kind == "s3" || o.c.Kind == "gcs" {
		signS3(req, o.c, data, time.Now().UTC())
	} else {
		if method == http.MethodPut {
			req.Header.Set("x-ms-blob-type", "BlockBlob")
		}
		if err = signAzure(req, o.c, time.Now().UTC()); err != nil {
			return nil, storageUnavailable()
		}
	}
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, storageUnavailable()
	}
	defer resp.Body.Close()
	if method == http.MethodDelete && resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, storageUnavailable()
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, int64(limit)+1))
	if err != nil || len(body) > limit {
		return nil, storageUnavailable()
	}
	return body, nil
}
func (o *objectRecordingStore) Put(ctx context.Context, org, id uuid.UUID, seq int, data []byte) error {
	_, err := o.request(ctx, http.MethodPut, org, id, seq, data)
	return err
}
func (o *objectRecordingStore) Get(ctx context.Context, org, id uuid.UUID, seq int) ([]byte, error) {
	return o.request(ctx, http.MethodGet, org, id, seq, nil)
}
func (o *objectRecordingStore) Delete(ctx context.Context, org, id uuid.UUID, seq int) error {
	_, err := o.request(ctx, http.MethodDelete, org, id, seq, nil)
	return err
}
func (o *objectRecordingStore) Probe(ctx context.Context) error { return storageProbe(ctx, o, o.c.Org) }
func storageHMAC(key []byte, value string) []byte {
	h := hmac.New(sha256.New, key)
	_, _ = h.Write([]byte(value))
	return h.Sum(nil)
}

// AWS SigV4 single-payload scheme, including payload digest (no UNSIGNED-PAYLOAD).
// https://docs.aws.amazon.com/AmazonS3/latest/developerguide/sig-v4-header-based-auth.html
func signS3(req *http.Request, c recordingStorageConfig, payload []byte, now time.Time) {
	sum := sha256.Sum256(payload)
	digest := hex.EncodeToString(sum[:])
	stamp := now.Format("20060102T150405Z")
	date := now.Format("20060102")
	req.Header.Set("x-amz-date", stamp)
	req.Header.Set("x-amz-content-sha256", digest)
	names := []string{"host", "x-amz-content-sha256", "x-amz-date"}
	if req.Header.Get("Range") != "" {
		names = append(names, "range")
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		canonical.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	signed := strings.Join(names, ";")
	request := req.Method + "\n" + req.URL.EscapedPath() + "\n" + req.URL.Query().Encode() + "\n" + canonical.String() + "\n" + signed + "\n" + digest
	requestSum := sha256.Sum256([]byte(request))
	scope := date + "/" + c.Region + "/s3/aws4_request"
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + scope + "\n" + hex.EncodeToString(requestSum[:])
	key := storageHMAC([]byte("AWS4"+c.SecretAccessKey), date)
	key = storageHMAC(key, c.Region)
	key = storageHMAC(key, "s3")
	key = storageHMAC(key, "aws4_request")
	signature := hex.EncodeToString(storageHMAC(key, toSign))
	clear(key)
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.AccessKeyID+"/"+scope+",SignedHeaders="+signed+",Signature="+signature)
}

// Azure Blob SharedKey, modern empty-zero Content-Length convention.
// https://learn.microsoft.com/en-us/rest/api/storageservices/authorize-with-shared-key
func signAzure(req *http.Request, c recordingStorageConfig, now time.Time) error {
	key, err := base64.StdEncoding.DecodeString(c.AccountKey)
	if err != nil {
		return invalidStorage()
	}
	defer clear(key)
	req.Header.Set("x-ms-date", now.Format(http.TimeFormat))
	req.Header.Set("x-ms-version", "2023-11-03")
	length := ""
	if req.ContentLength > 0 {
		length = strconv.FormatInt(req.ContentLength, 10)
	}
	values := []string{req.Method, req.Header.Get("Content-Encoding"), req.Header.Get("Content-Language"), length, req.Header.Get("Content-MD5"), req.Header.Get("Content-Type"), "", req.Header.Get("If-Modified-Since"), req.Header.Get("If-Match"), req.Header.Get("If-None-Match"), req.Header.Get("If-Unmodified-Since"), req.Header.Get("Range")}
	var names []string
	for k := range req.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-ms-") {
			names = append(names, strings.ToLower(k))
		}
	}
	sort.Strings(names)
	var canonical strings.Builder
	for _, name := range names {
		canonical.WriteString(name + ":" + strings.Join(strings.Fields(req.Header.Get(name)), " ") + "\n")
	}
	resource := "/" + c.AccountName + req.URL.EscapedPath()
	query := req.URL.Query()
	names = nil
	for k := range query {
		names = append(names, strings.ToLower(k))
	}
	sort.Strings(names)
	for _, k := range names {
		v := query[k]
		sort.Strings(v)
		resource += "\n" + k + ":" + strings.Join(v, ",")
	}
	signature := base64.StdEncoding.EncodeToString(storageHMAC(key, strings.Join(values, "\n")+"\n"+canonical.String()+resource))
	req.Header.Set("Authorization", "SharedKey "+c.AccountName+":"+signature)
	return nil
}

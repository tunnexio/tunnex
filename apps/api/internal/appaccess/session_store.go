package appaccess

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strconv"
	"time"

	"github.com/google/uuid"
	"github.com/redis/go-redis/v9"
)

var ErrAppSessionMissing = errors.New("app session unavailable")
var ErrAppSessionCapacity = errors.New("app session capacity exceeded")

// AppSessionRecord contains no plaintext browser/parent token. ParentSealed is
// decrypted only for authoritative native-parent validation, never projections.
type AppSessionRecord struct {
	InstallationGeneration uuid.UUID    `json:"installation_generation"`
	ID                     uuid.UUID    `json:"id"`
	UserID                 uuid.UUID    `json:"user_id"`
	Binding                RouteBinding `json:"binding"`
	Label                  string       `json:"label"`
	ParentHash             string       `json:"parent_hash"`
	ParentSealed           string       `json:"parent_sealed"`
	ParentEpoch            int64        `json:"parent_epoch"`
	AuthMethod             string       `json:"auth_method"`
	CreatedAt              time.Time    `json:"created_at"`
	ExpiresAt              time.Time    `json:"expires_at"`
	IdleMillis             int64        `json:"idle_millis"`
}
type LaunchRecord struct {
	AppSessionRecord
	NonceHash      string    `json:"nonce_hash"`
	RelativeTarget string    `json:"relative_target"`
	CodeExpiresAt  time.Time `json:"code_expires_at"`
}
type AppSessionStore struct {
	rdb *redis.Client
	now func() time.Time
}

func NewAppSessionStore(rdb *redis.Client) *AppSessionStore {
	return &AppSessionStore{rdb: rdb, now: time.Now}
}
func randomAppSecret(prefix string) (string, error) {
	raw := make([]byte, 32)
	if _, e := rand.Read(raw); e != nil {
		return "", e
	}
	return prefix + base64.RawURLEncoding.EncodeToString(raw), nil
}
func secretHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}
func validAppSecret(raw, prefix string) bool {
	if len(raw) != len(prefix)+43 || len(raw) < len(prefix) || raw[:len(prefix)] != prefix {
		return false
	}
	b, e := base64.RawURLEncoding.DecodeString(raw[len(prefix):])
	return e == nil && len(b) == 32 && prefix+base64.RawURLEncoding.EncodeToString(b) == raw
}
func launchKey(code string) string      { return "aa:launch:" + secretHash(code) }
func appSessionKey(token string) string { return "aa:session:" + secretHash(token) }
func sessionIDKey(id uuid.UUID) string  { return "aa:session-id:" + id.String() }
func sessionUserIndex(org, user uuid.UUID, generation ...uuid.UUID) string {
	g := uuid.Nil
	if len(generation) == 1 {
		g = generation[0]
	}
	return "aa:session-user:" + g.String() + ":" + org.String() + ":" + user.String()
}
func pendingIndexes(r PendingLaunch) []string {
	prefix := r.InstallationGeneration.String() + ":"
	return []string{"aa:pending-global:" + prefix, "aa:pending-proxy:" + prefix + r.ProxyID.String(), "aa:pending-app:" + prefix + r.Binding.OrgID.String() + ":" + r.Binding.AppID.String()}
}
func sessionIndexes(r AppSessionRecord) []string {
	return []string{sessionUserIndex(r.Binding.OrgID, r.UserID, r.InstallationGeneration), "aa:session-org:" + r.InstallationGeneration.String() + ":" + r.Binding.OrgID.String(), "aa:session-app:" + r.InstallationGeneration.String() + ":" + r.Binding.OrgID.String() + ":" + r.Binding.AppID.String(), "aa:session-parent:" + r.InstallationGeneration.String() + ":" + r.ParentHash}
}

const createLaunchLua = `
if redis.call('GET',KEYS[3])~=ARGV[5] or redis.call('PTTL',KEYS[3])<=0 then return -1 end
local now=tonumber(ARGV[2]); redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',now)
for _,key in ipairs(redis.call('ZRANGE',KEYS[2],0,15)) do if redis.call('EXISTS',key)==0 then redis.call('ZREM',KEYS[2],key) end end
if redis.call('ZCARD',KEYS[2])>=16 then return 0 end
if redis.call('EXISTS',KEYS[1])~=0 then return 0 end
redis.call('DEL',KEYS[3]);for i=4,#KEYS do redis.call('ZREM',KEYS[i],KEYS[3]) end;redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[3])
redis.call('ZADD',KEYS[2],ARGV[4],KEYS[1]);redis.call('PEXPIRE',KEYS[2],60000)
return 1`

func (s *AppSessionStore) CreateLaunch(ctx context.Context, r LaunchRecord, pendingRaw string) (string, error) {
	if s == nil || s.rdb == nil || r.InstallationGeneration == uuid.Nil {
		return "", ErrAppSessionMissing
	}
	code, e := randomAppSecret("")
	if e != nil {
		return "", e
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return "", e
	}
	now := s.now()
	ttl := r.CodeExpiresAt.Sub(now).Milliseconds()
	if ttl <= 0 || ttl > 60000 {
		return "", ErrAppSessionMissing
	}
	var pending PendingLaunch
	if json.Unmarshal([]byte(pendingRaw), &pending) != nil || pending.InstallationGeneration != r.InstallationGeneration || pending.NonceHash != r.NonceHash || pending.Binding != r.Binding || pending.RelativeTarget != r.RelativeTarget {
		return "", ErrAppSessionMissing
	}
	keys := append([]string{launchKey(code), "aa:launch-parent:" + r.InstallationGeneration.String() + ":" + r.ParentHash, pendingKey(r.NonceHash)}, pendingIndexes(pending)...)
	ok, e := s.rdb.Eval(ctx, createLaunchLua, keys, string(raw), now.UnixMilli(), ttl, r.CodeExpiresAt.UnixMilli(), pendingRaw).Int()
	if e != nil {
		return "", e
	}
	if ok == -1 {
		return "", ErrAppSessionMissing
	}
	if ok != 1 {
		return "", ErrAppSessionCapacity
	}
	return code, nil
}

const peekAppLua = `local data=redis.call('GET',KEYS[1]);if not data then return nil end;local ttl=redis.call('PTTL',KEYS[1]);if ttl<=0 then return nil end;return {data,ttl}`

func (s *AppSessionStore) LoadLaunch(ctx context.Context, code string) (LaunchRecord, string, error) {
	var r LaunchRecord
	if !validAppSecret(code, "") || s == nil || s.rdb == nil {
		return r, "", ErrAppSessionMissing
	}
	data, e := s.rdb.Eval(ctx, peekAppLua, []string{launchKey(code)}).Slice()
	if errors.Is(e, redis.Nil) {
		e = ErrAppSessionMissing
	}
	if e != nil {
		return r, "", e
	}
	if len(data) != 2 {
		return r, "", ErrAppSessionMissing
	}
	raw, ok := data[0].(string)
	if !ok || json.Unmarshal([]byte(raw), &r) != nil || !r.CodeExpiresAt.After(s.now()) {
		return r, "", ErrAppSessionMissing
	}
	return r, raw, nil
}

const redeemAppLua = `
if redis.call('GET',KEYS[1])~=ARGV[1] or redis.call('PTTL',KEYS[1])<=0 then return 0 end
local now=tonumber(ARGV[3]);redis.call('ZREMRANGEBYSCORE',KEYS[4],'-inf',now)
for _,id in ipairs(redis.call('ZRANGE',KEYS[4],0,31)) do local sk=redis.call('GET','aa:session-id:'..id);if not sk or redis.call('EXISTS',sk)==0 then redis.call('ZREM',KEYS[4],id) end end
if redis.call('ZCARD',KEYS[4])>=32 then return -1 end
if redis.call('EXISTS',KEYS[2])~=0 or redis.call('EXISTS',KEYS[3])~=0 then return 0 end
local ttl=tonumber(ARGV[4]);local absolute=tonumber(ARGV[5])-now
if ttl>absolute then ttl=absolute end;if ttl<=0 then return 0 end
redis.call('DEL',KEYS[1]);redis.call('SET',KEYS[2],ARGV[2],'PX',ttl)
redis.call('SET',KEYS[3],KEYS[2],'PX',ttl)
for i=4,#KEYS do redis.call('ZREMRANGEBYSCORE',KEYS[i],'-inf',now);redis.call('ZADD',KEYS[i],now+ttl,ARGV[6]);local existing=redis.call('PTTL',KEYS[i]);if existing<ttl then redis.call('PEXPIRE',KEYS[i],ttl) end end
return 1`

func (s *AppSessionStore) Redeem(ctx context.Context, code, expectedRaw string, r AppSessionRecord) (string, error) {
	if s == nil || s.rdb == nil || r.InstallationGeneration == uuid.Nil || !validAppSecret(code, "") {
		return "", ErrAppSessionMissing
	}
	token, e := randomAppSecret("tnxas_")
	if e != nil {
		return "", e
	}
	r.ID = uuid.New()
	raw, e := json.Marshal(r)
	if e != nil {
		return "", e
	}
	keys := []string{launchKey(code), appSessionKey(token), sessionIDKey(r.ID)}
	keys = append(keys, sessionIndexes(r)...)
	ok, e := s.rdb.Eval(ctx, redeemAppLua, keys, expectedRaw, string(raw), s.now().UnixMilli(), r.IdleMillis, r.ExpiresAt.UnixMilli(), r.ID.String()).Int()
	if e != nil {
		return "", e
	}
	if ok == -1 {
		return "", ErrAppSessionCapacity
	}
	if ok != 1 {
		return "", ErrAppSessionMissing
	}
	return token, nil
}
func (s *AppSessionStore) Peek(ctx context.Context, token string) (AppSessionRecord, time.Time, error) {
	var r AppSessionRecord
	if !validAppSecret(token, "tnxas_") || s == nil || s.rdb == nil {
		return r, time.Time{}, ErrAppSessionMissing
	}
	return s.peekKey(ctx, appSessionKey(token))
}
func (s *AppSessionStore) peekKey(ctx context.Context, key string) (AppSessionRecord, time.Time, error) {
	var r AppSessionRecord
	start := s.now()
	data, e := s.rdb.Eval(ctx, peekAppLua, []string{key}).Slice()
	if errors.Is(e, redis.Nil) {
		e = ErrAppSessionMissing
	}
	if e != nil {
		return r, time.Time{}, e
	}
	if len(data) != 2 {
		return r, time.Time{}, ErrAppSessionMissing
	}
	raw, ok := data[0].(string)
	ttl, okTTL := data[1].(int64)
	if !ok || !okTTL || ttl <= 0 || json.Unmarshal([]byte(raw), &r) != nil || r.ID == uuid.Nil || r.ParentEpoch <= 0 || r.IdleMillis <= 0 || !r.ExpiresAt.After(start) {
		return r, time.Time{}, ErrAppSessionMissing
	}
	until := start.Add(time.Duration(ttl) * time.Millisecond)
	if r.ExpiresAt.Before(until) {
		until = r.ExpiresAt
	}
	if !until.After(s.now()) {
		return r, time.Time{}, ErrAppSessionMissing
	}
	return r, until, nil
}

const touchAppLua = `local data=redis.call('GET',KEYS[1]);if not data or data~=ARGV[1] or redis.call('GET',KEYS[2])~=KEYS[1] then return 0 end;local ttl=redis.call('PTTL',KEYS[1]);if ttl<=0 then return 0 end;local now=tonumber(ARGV[2]);local remaining=tonumber(ARGV[3])-now;local idle=tonumber(ARGV[4]);if idle>remaining then idle=remaining end;if idle<=0 then return 0 end;redis.call('PEXPIRE',KEYS[1],idle);redis.call('PEXPIRE',KEYS[2],idle);for i=3,#KEYS do redis.call('ZADD',KEYS[i],now+idle,ARGV[5]);if redis.call('PTTL',KEYS[i])<idle then redis.call('PEXPIRE',KEYS[i],idle) end end;return idle`

func (s *AppSessionStore) TouchForeground(ctx context.Context, token string, r AppSessionRecord) (time.Time, error) {
	if s == nil || s.rdb == nil || !validAppSecret(token, "tnxas_") {
		return time.Time{}, ErrAppSessionMissing
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return time.Time{}, e
	}
	start := s.now()
	keys := []string{appSessionKey(token), sessionIDKey(r.ID)}
	keys = append(keys, sessionIndexes(r)...)
	ttl, e := s.rdb.Eval(ctx, touchAppLua, keys, string(raw), start.UnixMilli(), r.ExpiresAt.UnixMilli(), r.IdleMillis, r.ID.String()).Int64()
	if e != nil {
		return time.Time{}, e
	}
	if ttl <= 0 {
		return time.Time{}, ErrAppSessionMissing
	}
	return start.Add(time.Duration(ttl) * time.Millisecond), nil
}
func (s *AppSessionStore) List(ctx context.Context, org, user uuid.UUID, limit, offset int32, generation ...uuid.UUID) ([]AppSessionRecord, error) {
	if s == nil || s.rdb == nil || limit < 1 || limit > 100 || offset < 0 || offset > 10000 {
		return nil, ErrAppSessionMissing
	}
	out := []AppSessionRecord{}
	key := sessionUserIndex(org, user, generation...)
	now := s.now()
	if e := s.rdb.ZRemRangeByScore(ctx, key, "-inf", strconv.FormatInt(now.UnixMilli(), 10)).Err(); e != nil {
		return nil, e
	}
	ids, e := s.rdb.ZRange(ctx, key, int64(offset), int64(offset+limit-1)).Result()
	if e != nil {
		return nil, e
	}
	for _, value := range ids {
		id, e := uuid.Parse(value)
		if e != nil {
			return nil, ErrAppSessionMissing
		}
		sessionKey, e := s.rdb.Get(ctx, sessionIDKey(id)).Result()
		if errors.Is(e, redis.Nil) {
			continue
		}
		if e != nil {
			return nil, e
		}
		r, _, e := s.peekKey(ctx, sessionKey)
		if errors.Is(e, ErrAppSessionMissing) {
			continue
		}
		if e != nil {
			return nil, e
		}
		if r.Binding.OrgID != org || r.UserID != user {
			return nil, ErrAppSessionMissing
		}
		if len(generation) == 1 && r.InstallationGeneration != generation[0] {
			continue
		}
		out = append(out, r)
	}
	return out, nil
}

const revokeAppLua = `if redis.call('GET',KEYS[1])~=ARGV[1] then return 0 end;redis.call('DEL',KEYS[1],KEYS[2]);for i=3,#KEYS do redis.call('ZREM',KEYS[i],ARGV[2]) end;return 1`

func (s *AppSessionStore) RecordByID(ctx context.Context, id uuid.UUID) (AppSessionRecord, error) {
	if s == nil || s.rdb == nil {
		return AppSessionRecord{}, ErrAppSessionMissing
	}
	key, err := s.rdb.Get(ctx, sessionIDKey(id)).Result()
	if errors.Is(err, redis.Nil) {
		return AppSessionRecord{}, ErrAppSessionMissing
	}
	if err != nil {
		return AppSessionRecord{}, err
	}
	r, _, err := s.peekKey(ctx, key)
	if err == nil && r.ID != id {
		return AppSessionRecord{}, ErrAppSessionMissing
	}
	return r, err
}

func (s *AppSessionStore) RevokeOwn(ctx context.Context, org, user, id uuid.UUID) error {
	if s == nil || s.rdb == nil {
		return ErrAppSessionMissing
	}
	key, e := s.rdb.Get(ctx, sessionIDKey(id)).Result()
	if errors.Is(e, redis.Nil) {
		return ErrAppSessionMissing
	}
	if e != nil {
		return e
	}
	r, _, e := s.peekKey(ctx, key)
	if e != nil {
		return e
	}
	if r.Binding.OrgID != org || r.UserID != user {
		return ErrAppSessionMissing
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	keys := []string{key, sessionIDKey(id)}
	keys = append(keys, sessionIndexes(r)...)
	ok, e := s.rdb.Eval(ctx, revokeAppLua, keys, string(raw), id.String()).Int()
	if e != nil {
		return e
	}
	if ok != 1 {
		return ErrAppSessionMissing
	}
	return nil
}

type appStreamRecord struct {
	InstallationGeneration uuid.UUID    `json:"installation_generation"`
	SessionKey             string       `json:"session_key"`
	Binding                RouteBinding `json:"binding"`
	CredentialID           uuid.UUID    `json:"credential_id"`
	CredentialVersion      int64        `json:"credential_version"`
	LeaseUntil             time.Time    `json:"lease_until"`
}

const createStreamLua = `if redis.call('GET',KEYS[3])~=ARGV[5] or redis.call('PTTL',KEYS[3])<=0 then return -1 end;local now=tonumber(ARGV[2]);redis.call('ZREMRANGEBYSCORE',KEYS[2],'-inf',now);if redis.call('ZCARD',KEYS[2])>=16 then return 0 end;if redis.call('EXISTS',KEYS[1])~=0 then return 0 end;redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[3]);redis.call('ZADD',KEYS[2],ARGV[4],KEYS[1]);redis.call('PEXPIRE',KEYS[2],4000);return 1`

func (s *AppSessionStore) createStream(ctx context.Context, token string, proxy AuthenticatedProxy, binding RouteBinding, until time.Time, captured ...AppSessionRecord) (uuid.UUID, error) {
	id := uuid.New()
	now := s.now()
	ttl := until.Sub(now).Milliseconds()
	if ttl <= 0 || ttl > 4000 {
		return uuid.Nil, ErrAppSessionMissing
	}
	sessionRecord, _, e := s.Peek(ctx, token)
	if len(captured) == 1 {
		sessionRecord = captured[0]
	}
	if e != nil {
		return uuid.Nil, e
	}
	if sessionRecord.InstallationGeneration == uuid.Nil {
		return uuid.Nil, ErrAppSessionMissing
	}
	r := appStreamRecord{InstallationGeneration: sessionRecord.InstallationGeneration, SessionKey: appSessionKey(token), Binding: binding, CredentialID: proxy.CredentialID, CredentialVersion: proxy.CredentialVersion, LeaseUntil: until}
	raw, e := json.Marshal(r)
	if e != nil {
		return uuid.Nil, e
	}
	expectedSession, e := json.Marshal(sessionRecord)
	if e != nil {
		return uuid.Nil, e
	}
	ok, e := s.rdb.Eval(ctx, createStreamLua, []string{"aa:stream:" + id.String(), "aa:stream-session:" + secretHash(token), appSessionKey(token)}, string(raw), now.UnixMilli(), ttl, until.UnixMilli(), string(expectedSession)).Int()
	if e != nil {
		return uuid.Nil, e
	}
	if ok == -1 {
		return uuid.Nil, ErrAppSessionMissing
	}
	if ok != 1 {
		return uuid.Nil, ErrAppSessionCapacity
	}
	return id, nil
}
func (s *AppSessionStore) loadStream(ctx context.Context, id uuid.UUID) (appStreamRecord, string, error) {
	var r appStreamRecord
	raw, e := s.rdb.Get(ctx, "aa:stream:"+id.String()).Result()
	if errors.Is(e, redis.Nil) {
		return r, "", ErrAppSessionMissing
	}
	if e != nil {
		return r, "", e
	}
	if json.Unmarshal([]byte(raw), &r) != nil || r.InstallationGeneration == uuid.Nil || !r.LeaseUntil.After(s.now()) {
		return r, "", ErrAppSessionMissing
	}
	return r, raw, nil
}

const renewStreamLua = `if redis.call('GET',KEYS[3])~=ARGV[5] or redis.call('PTTL',KEYS[3])<=0 then return 0 end;if redis.call('GET',KEYS[1])~=ARGV[1] or redis.call('PTTL',KEYS[1])<=0 then return 0 end;redis.call('SET',KEYS[1],ARGV[2],'PX',ARGV[3]);redis.call('ZADD',KEYS[2],ARGV[4],KEYS[1]);redis.call('PEXPIRE',KEYS[2],4000);return 1`

func (s *AppSessionStore) renewStream(ctx context.Context, id uuid.UUID, expected string, r appStreamRecord, until time.Time, captured ...AppSessionRecord) error {
	now := s.now()
	ttl := until.Sub(now).Milliseconds()
	if ttl <= 0 || ttl > 4000 {
		return ErrAppSessionMissing
	}
	r.LeaseUntil = until
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	const prefix = "aa:session:"
	if len(r.SessionKey) != len(prefix)+64 || r.SessionKey[:len(prefix)] != prefix {
		return ErrAppSessionMissing
	}
	sessionRecord, _, e := s.peekKey(ctx, r.SessionKey)
	if len(captured) == 1 {
		sessionRecord = captured[0]
	}
	if e != nil {
		return e
	}
	if sessionRecord.InstallationGeneration == uuid.Nil || sessionRecord.InstallationGeneration != r.InstallationGeneration {
		return ErrAppSessionMissing
	}
	expectedSession, e := json.Marshal(sessionRecord)
	if e != nil {
		return e
	}
	ok, e := s.rdb.Eval(ctx, renewStreamLua, []string{"aa:stream:" + id.String(), "aa:stream-session:" + r.SessionKey[len(prefix):], r.SessionKey}, expected, string(raw), ttl, until.UnixMilli(), string(expectedSession)).Int()
	if e != nil {
		return e
	}
	if ok != 1 {
		return ErrAppSessionMissing
	}
	return nil
}

// PendingLaunch contains a hash of the browser nonce, never the nonce itself.
type PendingLaunch struct {
	InstallationGeneration uuid.UUID    `json:"installation_generation"`
	Binding                RouteBinding `json:"binding"`
	NonceHash              string       `json:"nonce_hash"`
	RelativeTarget         string       `json:"relative_target"`
	ProxyID                uuid.UUID    `json:"proxy_id"`
	ProxyVersion           int64        `json:"proxy_version"`
	ExpiresAt              time.Time    `json:"expires_at"`
}

func pendingKey(hash string) string { return "aa:pending:" + hash }

const registerPendingLua = `
local now=tonumber(ARGV[2]);if redis.call('EXISTS',KEYS[1])~=0 then return 0 end
for i=2,#KEYS do redis.call('ZREMRANGEBYSCORE',KEYS[i],'-inf',now);local cap=tonumber(ARGV[i+3]);if redis.call('ZCARD',KEYS[i])>=cap then return -1 end end
redis.call('SET',KEYS[1],ARGV[1],'PX',ARGV[3])
for i=2,#KEYS do redis.call('ZADD',KEYS[i],ARGV[4],KEYS[1]);redis.call('PEXPIRE',KEYS[i],600000) end
return 1`

func (s *AppSessionStore) RegisterPending(ctx context.Context, r PendingLaunch) error {
	if r.InstallationGeneration == uuid.Nil {
		return ErrAppSessionMissing
	}
	raw, e := json.Marshal(r)
	if e != nil {
		return e
	}
	now := s.now()
	ttl := r.ExpiresAt.Sub(now).Milliseconds()
	if ttl <= 0 || ttl > 600000 {
		return ErrAppSessionMissing
	}
	keys := append([]string{pendingKey(r.NonceHash)}, pendingIndexes(r)...)
	ok, e := s.rdb.Eval(ctx, registerPendingLua, keys, string(raw), now.UnixMilli(), ttl, r.ExpiresAt.UnixMilli(), 4096, 1024, 256).Int()
	if e != nil {
		return e
	}
	if ok == -1 {
		return ErrAppSessionCapacity
	}
	if ok != 1 {
		return ErrAppSessionMissing
	}
	return nil
}
func (s *AppSessionStore) LoadPending(ctx context.Context, hash string) (PendingLaunch, string, error) {
	var r PendingLaunch
	raw, e := s.rdb.Get(ctx, pendingKey(hash)).Result()
	if errors.Is(e, redis.Nil) {
		return r, "", ErrAppSessionMissing
	}
	if e != nil {
		return r, "", e
	}
	if json.Unmarshal([]byte(raw), &r) != nil || !r.ExpiresAt.After(s.now()) {
		return r, "", ErrAppSessionMissing
	}
	return r, raw, nil
}

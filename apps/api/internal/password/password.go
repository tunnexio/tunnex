// Package password hashes and verifies passwords with argon2id, storing each
// hash in PHC string format ($argon2id$v=19$m=..,t=..,p=..$salt$hash) so the
// parameters travel WITH the hash. That enables transparent rehash-on-login:
// when a stored hash was made with weaker params than current policy, the caller
// re-hashes at the next successful login (see NeedsRehash).
package password

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Params are the argon2id cost parameters. Defaults follow current OWASP
// guidance (a floor); raise Memory/Time if boot benchmarks allow.
type Params struct {
	Memory  uint32 // KiB
	Time    uint32 // iterations
	Threads uint8
	SaltLen uint32
	KeyLen  uint32
}

// Default is the current policy. NeedsRehash compares stored params against it.
var Default = Params{
	Memory:  19 * 1024, // 19 MiB
	Time:    2,
	Threads: 1,
	SaltLen: 16,
	KeyLen:  32,
}

// MinPasswordLen is the minimum acceptable password length.
const MinPasswordLen = 12

var (
	ErrMismatch      = errors.New("password does not match")
	ErrInvalidHash   = errors.New("malformed password hash")
	ErrPasswordShort = fmt.Errorf("password must be at least %d characters", MinPasswordLen)
)

// Hash hashes password with the Default params and returns a PHC string.
func Hash(password string) (string, error) {
	return hashWith(password, Default)
}

func hashWith(password string, p Params) (string, error) {
	salt := make([]byte, p.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	key := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, p.KeyLen)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, p.Memory, p.Time, p.Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

// Verify checks password against a PHC hash in constant time. It returns
// needsRehash=true when the stored params are weaker than Default.
func Verify(password, phc string) (needsRehash bool, err error) {
	p, salt, key, err := decode(phc)
	if err != nil {
		return false, err
	}
	computed := argon2.IDKey([]byte(password), salt, p.Time, p.Memory, p.Threads, uint32(len(key)))
	if subtle.ConstantTimeCompare(computed, key) != 1 {
		return false, ErrMismatch
	}
	return weaker(p, Default), nil
}

// DummyVerify performs a hash to equalize timing when a user is not found,
// mitigating account enumeration via response time. Its result is ignored.
func DummyVerify(password string) {
	_ = argon2.IDKey([]byte(password), make([]byte, Default.SaltLen),
		Default.Time, Default.Memory, Default.Threads, Default.KeyLen)
}

func weaker(got, want Params) bool {
	return got.Memory < want.Memory || got.Time < want.Time || got.KeyLen < want.KeyLen
}

func decode(phc string) (Params, []byte, []byte, error) {
	parts := strings.Split(phc, "$")
	// ["", "argon2id", "v=19", "m=..,t=..,p=..", salt, hash]
	if len(parts) != 6 || parts[1] != "argon2id" {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return Params{}, nil, nil, ErrInvalidHash
	}
	var p Params
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &p.Memory, &p.Time, &p.Threads); err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return Params{}, nil, nil, ErrInvalidHash
	}
	p.SaltLen = uint32(len(salt))
	p.KeyLen = uint32(len(key))
	return p, salt, key, nil
}

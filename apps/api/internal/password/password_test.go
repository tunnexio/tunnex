package password

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	h, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if !strings.HasPrefix(h, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC prefix: %s", h)
	}
	needsRehash, err := Verify("correct horse battery staple", h)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if needsRehash {
		t.Fatal("fresh hash should not need rehash")
	}
}

func TestVerifyWrongPassword(t *testing.T) {
	h, _ := Hash("correct horse battery staple")
	if _, err := Verify("wrong password here!!", h); err != ErrMismatch {
		t.Fatalf("want ErrMismatch, got %v", err)
	}
}

func TestSaltIsRandom(t *testing.T) {
	a, _ := Hash("same-password-x")
	b, _ := Hash("same-password-x")
	if a == b {
		t.Fatal("identical hashes for same password — salt not random")
	}
}

func TestNeedsRehashOnWeakerParams(t *testing.T) {
	weak := Params{Memory: 8 * 1024, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}
	h, err := hashWith("stored-with-weak-params", weak)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	needsRehash, err := Verify("stored-with-weak-params", h)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !needsRehash {
		t.Fatal("weaker stored params should trigger rehash")
	}
}

func TestVerifyRejectsMalformed(t *testing.T) {
	for _, bad := range []string{"", "notphc", "$argon2id$bad", "$bcrypt$v=1$x$y$z"} {
		if _, err := Verify("x", bad); err != ErrInvalidHash {
			t.Errorf("Verify(%q): want ErrInvalidHash, got %v", bad, err)
		}
	}
}

package sandboxes

import (
	"bytes"
	"crypto/rsa"
	"sort"

	"golang.org/x/crypto/ssh"
)

// NormalizeSSHPublicKeys admits ordinary public keys only; never key options,
// certificates, private material or commands. Comments are not persisted.
func NormalizeSSHPublicKeys(inputs []string, maximum int) ([]string, error) {
	if maximum < 1 || maximum > 8 || len(inputs) == 0 || len(inputs) > maximum {
		return nil, ErrInvalid
	}
	keys := make([]string, 0, len(inputs))
	seen := map[string]bool{}
	for _, input := range inputs {
		if len(input) > 8192 {
			return nil, ErrInvalid
		}
		key, _, options, rest, err := ssh.ParseAuthorizedKey([]byte(input))
		if err != nil || len(options) > 0 || len(bytes.TrimSpace(rest)) > 0 {
			return nil, ErrInvalid
		}
		switch key.Type() {
		case ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521:
		case ssh.KeyAlgoRSA:
			cryptoKey, ok := key.(ssh.CryptoPublicKey)
			if !ok {
				return nil, ErrInvalid
			}
			rsaKey, ok := cryptoKey.CryptoPublicKey().(*rsa.PublicKey)
			if !ok || rsaKey.N.BitLen() < 2048 {
				return nil, ErrInvalid
			}
		default:
			return nil, ErrInvalid
		}
		value := string(ssh.MarshalAuthorizedKey(key))
		if seen[value] {
			return nil, ErrInvalid
		}
		seen[value] = true
		keys = append(keys, value)
	}
	sort.Strings(keys)
	return keys, nil
}

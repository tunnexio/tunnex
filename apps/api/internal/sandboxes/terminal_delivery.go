package sandboxes

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"io/fs"
	"os"
	"strings"

	"github.com/google/uuid"
	"golang.org/x/crypto/ssh"
)

const terminalConfig = `Port 22
ListenAddress 0.0.0.0
HostKey /run/tunnex-ssh/host_key
AuthorizedKeysFile /run/tunnex-ssh/authorized_keys
PidFile /tmp/tunnex-sshd.pid
AllowUsers sandbox
AuthenticationMethods publickey
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
PermitEmptyPasswords no
UsePAM no
PermitRootLogin no
DisableForwarding yes
PermitTunnel no
PermitUserEnvironment no
PermitUserRC no
StrictModes yes
PrintMotd no
Subsystem sftp /usr/lib/openssh/sftp-server
`

type TerminalDelivery struct {
	Directory          string
	HostPublicKey      string
	HostKeyFingerprint string
}

// MaterializeTerminal requires the same exclusive per-sandbox root/lifecycle
// lease as skill delivery. approvedKeys are public keys supplied by trusted
// current authorization, including a dedicated readiness probe identity.
// It never reads a human's private key or overwrites a persisted host identity.
func MaterializeTerminal(root *os.Root, approvedKeys []string) (TerminalDelivery, error) {
	if root == nil || len(approvedKeys) == 0 || len(approvedKeys) > 8 {
		return TerminalDelivery{}, ErrInvalid
	}
	normalized, err := NormalizeSSHPublicKeys(approvedKeys, 8)
	if err != nil {
		return TerminalDelivery{}, err
	}
	authorized := []byte(strings.Join(normalized, ""))
	if _, err := root.Lstat("terminal"); err == nil {
		return verifyTerminal(root, "terminal", authorized)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return TerminalDelivery{}, err
	}
	stage := ".tunnex-terminal-stage-" + uuid.NewString()
	if err := root.Mkdir(stage, 0700); err != nil {
		return TerminalDelivery{}, err
	}
	defer root.RemoveAll(stage) //nolint:errcheck
	owned, err := root.OpenRoot(stage)
	if err != nil {
		return TerminalDelivery{}, err
	}
	defer owned.Close()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return TerminalDelivery{}, err
	}
	block, err := ssh.MarshalPrivateKey(private, "")
	if err != nil {
		return TerminalDelivery{}, err
	}
	for name, content := range map[string][]byte{"sshd_config": []byte(terminalConfig), "authorized_keys": authorized, "host_key": pem.EncodeToMemory(block)} {
		file, err := owned.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return TerminalDelivery{}, err
		}
		_, writeErr := file.Write(content)
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		if err = errors.Join(writeErr, closeErr); err != nil {
			return TerminalDelivery{}, err
		}
	}
	out, err := verifyTerminal(root, stage, authorized)
	if err != nil {
		return TerminalDelivery{}, err
	}
	if err = syncTerminalDirectory(owned); err != nil {
		return TerminalDelivery{}, err
	}
	if err = root.Rename(stage, "terminal"); err != nil {
		return TerminalDelivery{}, err
	}
	if err = syncTerminalDirectory(root); err != nil {
		return TerminalDelivery{}, err
	}
	out.Directory = "terminal"
	return out, nil
}

func syncTerminalDirectory(root *os.Root) error {
	file, err := root.Open(".")
	if err != nil {
		return err
	}
	defer file.Close()
	return file.Sync()
}

func verifyTerminal(root *os.Root, directory string, authorized []byte) (TerminalDelivery, error) {
	info, err := root.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode().Perm()&0077 != 0 {
		return TerminalDelivery{}, ErrConflict
	}
	owned, err := root.OpenRoot(directory)
	if err != nil {
		return TerminalDelivery{}, err
	}
	defer owned.Close()
	dir, err := owned.Open(".")
	if err != nil {
		return TerminalDelivery{}, err
	}
	entries, readErr := dir.ReadDir(-1)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(entries) != 3 {
		return TerminalDelivery{}, ErrConflict
	}
	contents := map[string][]byte{}
	for _, entry := range entries {
		name := entry.Name()
		if name != "host_key" && name != "authorized_keys" && name != "sshd_config" {
			return TerminalDelivery{}, ErrConflict
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() < 1 || info.Size() > 65536 {
			return TerminalDelivery{}, ErrConflict
		}
		content, err := owned.ReadFile(name)
		if err != nil {
			return TerminalDelivery{}, err
		}
		contents[name] = content
	}
	if !bytes.Equal(contents["authorized_keys"], authorized) || !bytes.Equal(contents["sshd_config"], []byte(terminalConfig)) {
		return TerminalDelivery{}, ErrConflict
	}
	signer, err := ssh.ParsePrivateKey(contents["host_key"])
	if err != nil || signer.PublicKey().Type() != ssh.KeyAlgoED25519 {
		return TerminalDelivery{}, ErrConflict
	}
	return TerminalDelivery{directory, string(ssh.MarshalAuthorizedKey(signer.PublicKey())), ssh.FingerprintSHA256(signer.PublicKey())}, nil
}

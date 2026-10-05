package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
)

func deliveryFixture() []SkillFile {
	dir := "skills/sandbox-" + uuid.NewString() + "/"
	files := []SkillFile{{Path: dir + "SKILL.md", Content: []byte("Instructions remain inert: $(touch /tmp/never-run)\n")}, {Path: dir + "config.json", Content: []byte(`{}`)}}
	for i := range files {
		hash := sha256.Sum256(files[i].Content)
		files[i].Digest = hex.EncodeToString(hash[:])
	}
	return files
}
func TestSkillDeliveryIdempotentAndPreservesUnrelatedWorkspace(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err = os.WriteFile(filepath.Join(dir, "user-notes"), []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	files := deliveryFixture()
	a, err := MaterializeSkillBundle(root, files)
	if err != nil {
		t.Fatal(err)
	}
	b, err := MaterializeSkillBundle(root, []SkillFile{files[1], files[0]})
	if err != nil || a != b {
		t.Fatal("retry changed delivery", err)
	}
	info, err := os.Stat(filepath.Join(dir, a.Directory, files[0].Path))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("file permissions", err)
	}
	notes, err := os.ReadFile(filepath.Join(dir, "user-notes"))
	if err != nil || string(notes) != "keep" {
		t.Fatal("unrelated file changed", err)
	}
	if err = os.WriteFile(filepath.Join(dir, a.Directory, files[0].Path), []byte("modified"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = MaterializeSkillBundle(root, files); !errors.Is(err, ErrConflict) {
		t.Fatal("mutated delivery overwritten", err)
	}
}
func TestSkillDeliveryRejectsTraversalDigestMissingPairAndSymlinks(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	files := deliveryFixture()
	for _, bad := range [][]SkillFile{
		{{Path: "../outside", Content: files[0].Content, Digest: files[0].Digest}},
		{{Path: files[0].Path, Content: files[0].Content, Digest: "wrong"}, files[1]},
		{files[0]},
		{files[0], files[0]},
	} {
		if _, err = MaterializeSkillBundle(root, bad); !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid bundle wrote files", err)
		}
	}
	a, err := MaterializeSkillBundle(root, files)
	if err != nil {
		t.Fatal(err)
	}
	if err = root.Remove(a.Directory + "/" + files[0].Path); err != nil {
		t.Fatal(err)
	}
	if err = root.Symlink("config.json", a.Directory+"/"+files[0].Path); err != nil {
		t.Fatal(err)
	}
	if _, err = MaterializeSkillBundle(root, files); !errors.Is(err, ErrConflict) {
		t.Fatal("symlink delivery accepted", err)
	}
}

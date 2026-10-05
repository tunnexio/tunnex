package sandboxes

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/google/uuid"
)

type SkillDelivery struct {
	Directory string
	Digest    string
	Files     int
}
type deliveredFile struct {
	Path   string `json:"path"`
	Digest string `json:"digest"`
}

// MaterializeSkillBundle requires an exclusively trusted, per-sandbox root
// capability and the sandbox lifecycle lease. Workloads must have no write
// access during delivery. It performs no installs, execution or chown/mounts.
func MaterializeSkillBundle(root *os.Root, files []SkillFile) (SkillDelivery, error) {
	if root == nil || len(files) > 32 {
		return SkillDelivery{}, ErrInvalid
	}
	copyFiles := make([]SkillFile, 0, len(files))
	seen := map[string]bool{}
	pairs := map[string]int{}
	for _, file := range files {
		parts := strings.Split(file.Path, "/")
		if len(parts) != 3 || parts[0] != "skills" || !strings.HasPrefix(parts[1], "sandbox-") || (parts[2] != "SKILL.md" && parts[2] != "config.json") || seen[file.Path] {
			return SkillDelivery{}, ErrInvalid
		}
		id, err := uuid.Parse(strings.TrimPrefix(parts[1], "sandbox-"))
		if err != nil || id == uuid.Nil || parts[1] != "sandbox-"+id.String() || len(file.Content) > 65536 || !utf8.Valid(file.Content) || bytes.IndexByte(file.Content, 0) >= 0 {
			return SkillDelivery{}, ErrInvalid
		}
		digest := sha256.Sum256(file.Content)
		if file.Digest != hex.EncodeToString(digest[:]) {
			return SkillDelivery{}, ErrInvalid
		}
		if parts[2] == "config.json" {
			var config map[string]string
			if json.Unmarshal(file.Content, &config) != nil || config == nil || len(config) > 16 {
				return SkillDelivery{}, ErrInvalid
			}
			for key, value := range config {
				if !skillKey.MatchString(key) || !skillText(value, 80) {
					return SkillDelivery{}, ErrInvalid
				}
			}
		}
		seen[file.Path] = true
		pairs[parts[1]]++
		copyFiles = append(copyFiles, SkillFile{file.Path, bytes.Clone(file.Content), file.Digest})
	}
	for _, count := range pairs {
		if count != 2 {
			return SkillDelivery{}, ErrInvalid
		}
	}
	sort.Slice(copyFiles, func(i, j int) bool { return copyFiles[i].Path < copyFiles[j].Path })
	manifest := make([]deliveredFile, 0, len(copyFiles))
	for _, file := range copyFiles {
		manifest = append(manifest, deliveredFile{file.Path, file.Digest})
	}
	raw, _ := json.Marshal(manifest)
	hash := sha256.Sum256(raw)
	delivery := SkillDelivery{"skills-" + hex.EncodeToString(hash[:]), hex.EncodeToString(hash[:]), len(copyFiles)}
	if _, err := root.Lstat(delivery.Directory); err == nil {
		return delivery, verifySkillDelivery(root, delivery.Directory, raw, copyFiles)
	} else if !errors.Is(err, fs.ErrNotExist) {
		return SkillDelivery{}, err
	}
	stage := ".tunnex-skills-stage-" + uuid.NewString()
	if err := root.Mkdir(stage, 0700); err != nil {
		return SkillDelivery{}, err
	}
	// The generated staging path is owned by this call, never a user path.
	defer root.RemoveAll(stage) //nolint:errcheck
	stageRoot, err := root.OpenRoot(stage)
	if err != nil {
		return SkillDelivery{}, err
	}
	defer stageRoot.Close()
	if err = stageRoot.Mkdir("skills", 0700); err != nil {
		return SkillDelivery{}, err
	}
	if len(copyFiles) > 0 {
		for group := range pairs {
			if err = stageRoot.Mkdir("skills/"+group, 0700); err != nil {
				return SkillDelivery{}, err
			}
		}
	}
	write := func(name string, content []byte) error {
		file, err := stageRoot.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		_, err = file.Write(content)
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err != nil {
			return err
		}
		return closeErr
	}
	for _, file := range copyFiles {
		if err = write(file.Path, file.Content); err != nil {
			return SkillDelivery{}, err
		}
	}
	if err = write("manifest.json", raw); err != nil {
		return SkillDelivery{}, err
	}
	if err = verifySkillDelivery(root, stage, raw, copyFiles); err != nil {
		return SkillDelivery{}, err
	}
	syncDirectory := func(r *os.Root, name string) error {
		dir, e := r.Open(name)
		if e != nil {
			return e
		}
		defer dir.Close()
		return dir.Sync()
	}
	for group := range pairs {
		if err = syncDirectory(stageRoot, "skills/"+group); err != nil {
			return SkillDelivery{}, err
		}
	}
	if err = syncDirectory(stageRoot, "skills"); err != nil {
		return SkillDelivery{}, err
	}
	if err = syncDirectory(stageRoot, "."); err != nil {
		return SkillDelivery{}, err
	}
	if err = root.Rename(stage, delivery.Directory); err != nil {
		return SkillDelivery{}, err
	}
	if err = syncDirectory(root, "."); err != nil {
		return SkillDelivery{}, err
	}
	return delivery, nil
}

func verifySkillDelivery(root *os.Root, directory string, manifest []byte, files []SkillFile) error {
	info, err := root.Lstat(directory)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return ErrConflict
	}
	owned, err := root.OpenRoot(directory)
	if err != nil {
		return err
	}
	defer owned.Close()
	expected := map[string]bool{".": true, "manifest.json": true, "skills": true}
	contents := map[string][]byte{"manifest.json": manifest}
	for _, file := range files {
		expected[file.Path] = true
		contents[file.Path] = file.Content
		for parent := path.Dir(file.Path); parent != "."; parent = path.Dir(parent) {
			expected[parent] = true
		}
	}
	visited := map[string]bool{}
	err = fs.WalkDir(owned.FS(), ".", func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !expected[name] || entry.Type()&os.ModeSymlink != 0 {
			return ErrConflict
		}
		visited[name] = true
		if entry.IsDir() {
			return nil
		}
		if !entry.Type().IsRegular() {
			return ErrConflict
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Size() != int64(len(contents[name])) {
			return ErrConflict
		}
		data, e := owned.ReadFile(name)
		if e != nil {
			return e
		}
		if !bytes.Equal(data, contents[name]) {
			return ErrConflict
		}
		return nil
	})
	if err != nil {
		return err
	}
	if len(visited) != len(expected) {
		return ErrConflict
	}
	return nil
}

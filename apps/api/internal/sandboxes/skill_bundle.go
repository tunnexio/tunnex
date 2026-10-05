package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// SkillFile is inert bundle content. A qualified adapter must write it only in
// its owned unprivileged workspace, verify Digest, and never interpret config as
// shell/environment source. This function performs no installs or filesystem IO.
type SkillFile struct {
	Path    string
	Content []byte
	Digest  string
}

func PrepareSkillBundle(selected []SkillSelection, approved map[string]SkillRevision, requested, cap []Scope) ([]SkillFile, error) {
	normalized, err := normalizeSkills(selected)
	if err != nil {
		return nil, err
	}
	out := []SkillFile{}
	for _, selection := range normalized {
		revision, ok := approved[selection.RevisionID.String()]
		if !ok {
			return nil, ErrDisabled
		}
		if err = validateSelection(selection, revision, requested, cap); err != nil {
			return nil, err
		}
		// Paths derive only from canonical UUIDs, never user titles or config values.
		root := "skills/sandbox-" + revision.ID.String() + "/"
		description, _ := json.Marshal(revision.Description)
		instructions := []byte("---\nname: sandbox-" + revision.ID.String() + "\ndescription: " + string(description) + "\n---\n\n" + revision.Instructions)
		config, _ := json.Marshal(selection.Configuration)
		for _, file := range []SkillFile{{Path: root + "SKILL.md", Content: instructions}, {Path: root + "config.json", Content: config}} {
			hash := sha256.Sum256(file.Content)
			file.Digest = hex.EncodeToString(hash[:])
			out = append(out, file)
		}
	}
	return out, nil
}

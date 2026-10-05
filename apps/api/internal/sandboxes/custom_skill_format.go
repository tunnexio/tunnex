package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"github.com/google/uuid"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

var customSkillName = regexp.MustCompile(`^[a-z0-9]+(?:-[a-z0-9]+)*$`)

// parseCustomSkill is deliberately a minimal scalar front-matter format, not
// general YAML. Imported instructions remain inert untrusted content.
func parseCustomSkill(document string, id uuid.UUID, version int) (SkillRevision, string, error) {
	if len(document) == 0 || len(document) > 32768 || !utf8.ValidString(document) || strings.ContainsRune(document, 0) {
		return SkillRevision{}, "", ErrInvalid
	}
	document = strings.ReplaceAll(document, "\r\n", "\n")
	lines := strings.Split(document, "\n")
	if len(lines) < 5 || lines[0] != "---" {
		return SkillRevision{}, "", ErrInvalid
	}
	metadata := map[string]string{}
	end := -1
	for i := 1; i < len(lines) && i < 12; i++ {
		if lines[i] == "---" {
			end = i
			break
		}
		parts := strings.SplitN(lines[i], ":", 2)
		if len(parts) != 2 {
			return SkillRevision{}, "", ErrInvalid
		}
		key, value := strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
		if (key != "name" && key != "description") || metadata[key] != "" || value == "" {
			return SkillRevision{}, "", ErrInvalid
		}
		if strings.HasPrefix(value, "\"") {
			decoded, err := strconv.Unquote(value)
			if err != nil {
				return SkillRevision{}, "", ErrInvalid
			}
			value = decoded
		} else if strings.ContainsAny(value, "\"'[]{}&*!>|#") {
			return SkillRevision{}, "", ErrInvalid
		}
		metadata[key] = value
	}
	name, description := metadata["name"], metadata["description"]
	if end < 0 || len(metadata) != 2 || len(name) > 64 || !customSkillName.MatchString(name) || !skillText(description, 256) {
		return SkillRevision{}, "", ErrInvalid
	}
	instructions := strings.Join(lines[end+1:], "\n")
	if strings.TrimSpace(instructions) == "" {
		return SkillRevision{}, "", ErrInvalid
	}
	hash := sha256.Sum256([]byte(instructions))
	revision := SkillRevision{ID: id, Name: name, Description: description, Version: strconv.Itoa(version), Instructions: instructions, Digest: hex.EncodeToString(hash[:]), RequiredScope: []Scope{}, Fields: []SkillField{}}
	if validateSkill(revision) != nil {
		return SkillRevision{}, "", ErrInvalid
	}
	return revision, document, nil
}

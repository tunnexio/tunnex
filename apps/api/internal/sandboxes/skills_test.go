package sandboxes

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/google/uuid"
	"strings"
	"testing"
)

func testSkill() SkillRevision {
	instructions := "# Readonly workspace guide\nUse the existing terminal tools.\n"
	hash := sha256.Sum256([]byte(instructions))
	return SkillRevision{ID: uuid.New(), Name: "Fixture instructions", Version: "1", Description: "Disposable approved fixture", Instructions: instructions, Digest: hex.EncodeToString(hash[:]), RequiredScope: []Scope{{CIDR: "10.1.0.0/16", Protocol: "tcp", PortLow: 22, PortHigh: 22}}, Fields: []SkillField{{Key: "format", Label: "Format", Choices: []string{"short", "long"}, Required: true}}}
}

func TestApprovedSkillBundleIsInertDeterministicAndBounded(t *testing.T) {
	r := testSkill()
	selection := []SkillSelection{{r.ID, map[string]string{"format": "short"}}}
	approved := map[string]SkillRevision{r.ID.String(): r}
	files, err := PrepareSkillBundle(selection, approved, r.RequiredScope, r.RequiredScope)
	if err != nil || len(files) != 2 {
		t.Fatal("bundle unavailable", err)
	}
	for _, file := range files {
		if !strings.HasPrefix(file.Path, "skills/sandbox-"+r.ID.String()+"/") || strings.Contains(file.Path, "..") {
			t.Fatal("unsafe path")
		}
		hash := sha256.Sum256(file.Content)
		if file.Digest != hex.EncodeToString(hash[:]) {
			t.Fatal("content integrity missing")
		}
	}
	if !strings.Contains(string(files[0].Content), r.Instructions) {
		t.Fatal("approved instructions changed")
	}
	var config map[string]string
	if json.Unmarshal(files[1].Content, &config) != nil || config["format"] != "short" {
		t.Fatal("configuration was not inert JSON")
	}
	if _, err = PrepareSkillBundle(selection, nil, r.RequiredScope, r.RequiredScope); err != ErrDisabled {
		t.Fatal("unapproved bundle produced")
	}
	r.Instructions += "changed"
	approved[r.ID.String()] = r
	if _, err = PrepareSkillBundle(selection, approved, r.RequiredScope, r.RequiredScope); err == nil {
		t.Fatal("changed approved digest accepted")
	}
}
func TestSkillConfigurationAndScopeRemainBounded(t *testing.T) {
	revision := testSkill()
	selection := SkillSelection{revision.ID, map[string]string{"format": "short"}}
	scope := revision.RequiredScope
	if err := validateSelection(selection, revision, scope, scope); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*SkillSelection, *SkillRevision){
		"missing required": func(s *SkillSelection, _ *SkillRevision) { s.Configuration = map[string]string{} },
		"unapproved choice": func(s *SkillSelection, _ *SkillRevision) {
			s.Configuration = map[string]string{"format": "arbitrary command"}
		},
		"unknown secret input": func(s *SkillSelection, _ *SkillRevision) {
			s.Configuration = map[string]string{"format": "short", "token": "secret"}
		},
		"digest mismatch": func(_ *SkillSelection, r *SkillRevision) { r.Instructions += "changed" },
		"duplicate field": func(_ *SkillSelection, r *SkillRevision) { r.Fields = append(r.Fields, r.Fields[0]) },
		"broader scope": func(_ *SkillSelection, r *SkillRevision) {
			r.RequiredScope = []Scope{{CIDR: "0.0.0.0/0", Protocol: "any"}}
		},
	} {
		t.Run(name, func(t *testing.T) {
			r := testSkill()
			s := SkillSelection{r.ID, map[string]string{"format": "short"}}
			change(&s, &r)
			if err := validateSelection(s, r, scope, scope); err == nil {
				t.Fatal("unbounded selection accepted")
			}
		})
	}
	a, b := uuid.New(), uuid.New()
	normalized, err := normalizeSkills([]SkillSelection{{b, nil}, {a, nil}})
	if err != nil || normalized[0].RevisionID.String() > normalized[1].RevisionID.String() {
		t.Fatal("selection not canonical")
	}
	if _, err = normalizeSkills([]SkillSelection{{a, nil}, {a, nil}}); err != ErrInvalid {
		t.Fatal("duplicate selection accepted")
	}
}

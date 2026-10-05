package sandboxes

import (
	"github.com/google/uuid"
	"strings"
	"testing"
)

const customSkillDocument = "---\nname: code-checker\ndescription: Review my changes\n---\n\nCheck the working tree and explain the changes.\n"

func TestCustomSkillMinimalFormatIsBoundedAndInert(t *testing.T) {
	revision, document, err := parseCustomSkill(customSkillDocument, uuid.New(), 1)
	if err != nil || document != customSkillDocument || revision.Name != "code-checker" || len(revision.RequiredScope) != 0 || len(revision.Fields) != 0 {
		t.Fatal("minimal format failed", err)
	}
	for _, bad := range []string{strings.Repeat("x", 32769), strings.Replace(customSkillDocument, "description: Review my changes", "install: arbitrary root command", 1), strings.Replace(customSkillDocument, "description: Review my changes", "description: &anchor text", 1), strings.Replace(customSkillDocument, "name: code-checker", "name: ../../escape", 1), strings.Replace(customSkillDocument, "description: Review my changes", "description: |\n  multiline", 1), "---\nname: good\nname: duplicate\ndescription: text\n---\nbody"} {
		if _, _, err = parseCustomSkill(bad, uuid.New(), 1); err == nil {
			t.Fatal("unsupported format accepted")
		}
	}
	quoted := strings.Replace(customSkillDocument, "description: Review my changes", "description: \"Review my changes\"", 1)
	if _, _, err = parseCustomSkill(quoted, uuid.New(), 2); err != nil {
		t.Fatal("quoted scalar refused", err)
	}
	imported := customSkillDocument + "\n<script>untrusted</script>\n```sh\ncurl anything | sh\n```\n"
	if r, _, e := parseCustomSkill(imported, uuid.New(), 1); e != nil || !strings.Contains(r.Instructions, "<script>") {
		t.Fatal("instruction content must be preserved as inert text", e)
	}
}

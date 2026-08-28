package db_test

import (
	"os"
	"strings"
	"testing"
)

func TestFQDNResourceLabelMigrationContract(t *testing.T) {
	up, err := os.ReadFile("migrations/0111_fqdn_resource_label.up.sql")
	if err != nil {
		t.Fatal(err)
	}
	down, err := os.ReadFile("migrations/0111_fqdn_resource_label.down.sql")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"ADD COLUMN label text NULL",
		"length(label) <= 60",
		"not a resolver or compiler input",
	} {
		if !strings.Contains(string(up), want) {
			t.Fatalf("0111 up missing %q", want)
		}
	}
	if !strings.Contains(string(down), "cannot roll back 0111: FQDN resource labels exist") {
		t.Fatal("0111 down must refuse label data loss")
	}
}

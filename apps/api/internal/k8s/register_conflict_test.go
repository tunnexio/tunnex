package k8s

import (
	"strings"
	"testing"
)

// Each uniqueness rule on a cluster gets its own message. The connector rule in particular is not about
// the name or the range, and saying so sent people to the wrong field.
func TestRegisterClusterConflictNamesTheRule(t *testing.T) {
	for constraint, want := range map[string]string{
		"k8s_clusters_connector_node_unique": "already serves another cluster",
		"k8s_clusters_org_id_name_key":       "with that name already exists",
		"k8s_clusters_org_id_vip_range_key":  "with that address range already exists",
		"something_new":                      "name or VIP range",
	} {
		if got := registerClusterConflict(constraint).Error(); !strings.Contains(got, want) {
			t.Errorf("%s: %q lacks %q", constraint, got, want)
		}
	}
	if got := registerClusterConflict("k8s_clusters_connector_node_unique").Error(); !strings.Contains(got, "connector_in_use") {
		t.Errorf("connector conflict must carry its own code: %s", got)
	}
}

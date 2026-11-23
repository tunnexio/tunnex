package v1alpha1

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"
)

// The generated CRD is what the API server enforces when a TunnexNamespaceExposure is applied. This test
// reads the manifest that ships (config/crd, byte-identical to the Helm chart's copy apart from two
// annotations; the chart contract test proves that) and checks the admission rules it carries.
//
// It checks that each rule is PRESENT and exercises the regular expressions. It does not run the CEL
// rules: that needs an API server, and none is part of this suite.

type schemaNode struct {
	Type                 string                `json:"type"`
	Properties           map[string]schemaNode `json:"properties"`
	Required             []string              `json:"required"`
	Enum                 []string              `json:"enum"`
	Default              any                   `json:"default"`
	Pattern              string                `json:"pattern"`
	MaxLength            *int                  `json:"maxLength"`
	MinLength            *int                  `json:"minLength"`
	MaxItems             *int                  `json:"maxItems"`
	MaxProperties        *int                  `json:"maxProperties"`
	Items                *schemaNode           `json:"items"`
	AdditionalProperties *schemaNode           `json:"additionalProperties"`
	ListType             string                `json:"x-kubernetes-list-type"`
	Validations          []struct {
		Rule    string `json:"rule"`
		Message string `json:"message"`
	} `json:"x-kubernetes-validations"`
}

func loadNamespaceExposureSpec(t *testing.T) (schemaNode, schemaNode) {
	t.Helper()
	raw, err := os.ReadFile("../../config/crd/tunnex.io_tunnexnamespaceexposures.yaml")
	if err != nil {
		t.Fatal(err)
	}
	var crd struct {
		Spec struct {
			Scope string `json:"scope"`
			Names struct {
				Kind   string `json:"kind"`
				Plural string `json:"plural"`
			} `json:"names"`
			Versions []struct {
				Name         string `json:"name"`
				Served       bool   `json:"served"`
				Storage      bool   `json:"storage"`
				Subresources struct {
					Status *struct{} `json:"status"`
				} `json:"subresources"`
				Schema struct {
					OpenAPIV3Schema schemaNode `json:"openAPIV3Schema"`
				} `json:"schema"`
			} `json:"versions"`
		} `json:"spec"`
	}
	if err := yaml.Unmarshal(raw, &crd); err != nil {
		t.Fatal(err)
	}
	if crd.Spec.Scope != "Namespaced" || crd.Spec.Names.Kind != "TunnexNamespaceExposure" || crd.Spec.Names.Plural != "tunnexnamespaceexposures" || len(crd.Spec.Versions) != 1 {
		t.Fatalf("CRD identity = %+v", crd.Spec.Names)
	}
	v := crd.Spec.Versions[0]
	if v.Name != "v1alpha1" || !v.Served || !v.Storage || v.Subresources.Status == nil {
		t.Fatalf("version = %+v; status must be a subresource so a spec write cannot forge Ready", v)
	}
	root := v.Schema.OpenAPIV3Schema
	return root.Properties["spec"], root.Properties["status"]
}

func hasRule(node schemaNode, rule string) bool {
	for _, v := range node.Validations {
		if v.Rule == rule && v.Message != "" {
			return true
		}
	}
	return false
}

func TestNamespaceExposureCRDAdmissionRules(t *testing.T) {
	spec, status := loadNamespaceExposureSpec(t)

	if strings.Join(spec.Required, ",") != "cluster,namespace" {
		t.Fatalf("required = %v", spec.Required)
	}
	// Nothing in the schema keeps unknown fields: a field this version does not know is refused or
	// pruned, never silently honoured as something else.
	if len(spec.Properties) != 5 {
		t.Fatalf("spec fields = %d, want cluster, namespace, selector, excludedServices, deletionPolicy", len(spec.Properties))
	}

	// namespace: one DNS label, immutable, never a system or Tunnex namespace.
	ns := spec.Properties["namespace"]
	if ns.Type != "string" || ns.MaxLength == nil || *ns.MaxLength != 63 || ns.Pattern == "" {
		t.Fatalf("namespace schema = %+v", ns)
	}
	nsPattern := regexp.MustCompile(ns.Pattern)
	for _, ok := range []string{"shop", "payments-eu", "a", "x1"} {
		if !nsPattern.MatchString(ok) {
			t.Errorf("namespace %q refused by the pattern", ok)
		}
	}
	for _, bad := range []string{"", "*", "shop,billing", "Shop", "-shop", "shop-", "a b", "shop/*"} {
		if nsPattern.MatchString(bad) {
			t.Errorf("namespace %q accepted by the pattern: a rule names exactly one namespace", bad)
		}
	}
	for _, rule := range []string{
		"self == oldSelf",
		"!(self in ['kube-system', 'kube-public', 'kube-node-lease'])",
		"self != 'tunnex' && !self.startsWith('tunnex-')",
	} {
		if !hasRule(ns, rule) {
			t.Errorf("namespace is missing the admission rule %q", rule)
		}
	}

	// cluster: required, bounded, immutable.
	cluster := spec.Properties["cluster"]
	if cluster.MinLength == nil || *cluster.MinLength != 1 || cluster.MaxLength == nil || !hasRule(cluster, "self == oldSelf") {
		t.Fatalf("cluster schema = %+v", cluster)
	}

	// selector: a FLAT map of at most 8 label values. An object value (matchLabels, matchExpressions)
	// is a type error, so a set-based selector cannot be written and dropped.
	selector := spec.Properties["selector"]
	if selector.Type != "object" || selector.MaxProperties == nil || *selector.MaxProperties != 8 || len(selector.Properties) != 0 ||
		selector.AdditionalProperties == nil || selector.AdditionalProperties.Type != "string" ||
		selector.AdditionalProperties.MaxLength == nil || *selector.AdditionalProperties.MaxLength != 63 {
		t.Fatalf("selector schema = %+v", selector)
	}
	value := regexp.MustCompile(selector.AdditionalProperties.Pattern)
	for _, ok := range []string{"", "web", "My_App.v2", "1"} {
		if !value.MatchString(ok) {
			t.Errorf("label value %q refused", ok)
		}
	}
	for _, bad := range []string{"*", "web,api", "a b", "-web", "web-", "(web)"} {
		if value.MatchString(bad) {
			t.Errorf("label value %q accepted: no wildcards, lists or operators", bad)
		}
	}

	// excludedServices: at most 100 exact names, no duplicates.
	excluded := spec.Properties["excludedServices"]
	if excluded.Type != "array" || excluded.MaxItems == nil || *excluded.MaxItems != 100 || excluded.ListType != "set" || excluded.Items == nil ||
		excluded.Items.MinLength == nil || *excluded.Items.MinLength != 1 || excluded.Items.MaxLength == nil || *excluded.Items.MaxLength != 63 {
		t.Fatalf("excludedServices schema = %+v", excluded)
	}
	name := regexp.MustCompile(excluded.Items.Pattern)
	for _, bad := range []string{"web-*", "*", "Web", "a,b", ""} {
		if name.MatchString(bad) {
			t.Errorf("excluded Service %q accepted: exact names only", bad)
		}
	}
	if !name.MatchString("admin-api") {
		t.Error("an ordinary Service name was refused")
	}

	// deletionPolicy: exactly two outcomes, and the default is the one that withdraws nothing.
	policy := spec.Properties["deletionPolicy"]
	if strings.Join(policy.Enum, ",") != DeletionPolicyKeep+","+DeletionPolicyWithdraw || policy.Default != DeletionPolicyKeep {
		t.Fatalf("deletionPolicy enum=%v default=%v; the default must be %s", policy.Enum, policy.Default, DeletionPolicyKeep)
	}

	// status carries the rule's own status and counts, never a spec field.
	for _, field := range []string{"ruleId", "ruleStatus", "exposedServices", "exposedPorts", "waitingServices", "conditions"} {
		if _, ok := status.Properties[field]; !ok {
			t.Errorf("status is missing %s", field)
		}
	}
}

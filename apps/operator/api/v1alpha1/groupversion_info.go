// Package v1alpha1 is the Tunnex operator CRD API (S10.2). The three kinds — TunnexCluster,
// TunnexExposedService, TunnexGrant — mirror the control plane's OWN vocabulary (the nouns the dashboard and
// docs use: cluster, service, namespace, protocol, port, grant) so a platform engineer reading a CR and an
// admin reading the dashboard see ONE product. DERIVED truth (the resolvable FQDN, the CP-assigned ids) lives
// in STATUS, never spec.
//
// The operator is an API CLIENT of the control plane — never a DB writer (THE HARD RULE, docs/S10.2-
// decisions.md). It imports NO Tunnex DB package; every invariant (Collect/OrgRanges, identity-binding,
// edition gate, audit cascade) is inherited only through the CP HTTP handlers.
// +kubebuilder:object:generate=true
// +groupName=tunnex.io
package v1alpha1

import (
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

// GroupVersion is the group/version for the Tunnex operator CRDs.
var GroupVersion = schema.GroupVersion{Group: "tunnex.io", Version: "v1alpha1"}

// SchemeBuilder registers the CRD types with a runtime scheme.
var SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

// AddToScheme adds the CRD types to a scheme.
var AddToScheme = SchemeBuilder.AddToScheme

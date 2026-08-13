package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TunnexGrantSpec declares an access grant that reaches an exposed Service (mirrors the CP's policy rule with
// dst_kind=k8s_service). ENTERPRISE — the CP gates it edition_required (403) in the open build; the operator
// surfaces that verbatim in status (never a silent no-op). The subject is a user/group/site/cidr — NEVER a
// workload (a pod is not a policy SUBJECT; workload-identity was ruled out of the epic, D4), which is why
// there is no TunnexPeer. The destination is referenced by its TunnexExposedService resource name.
type TunnexGrantSpec struct {
	// SubjectKind is the kind of principal being granted access.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=user;group;site;cidr
	SubjectKind string `json:"subjectKind"`
	// Subject identifies the principal: a user email / group name / site name / CIDR, per SubjectKind.
	// +kubebuilder:validation:Required
	Subject string `json:"subject"`
	// Service is the name of the TunnexExposedService this grant reaches. Required.
	// +kubebuilder:validation:Required
	Service string `json:"service"`
	// ExpiresAt makes this a TEMPORARY grant — the CP deletes it (audited) when it lapses. Omit for a
	// permanent grant.
	// +optional
	ExpiresAt *metav1.Time `json:"expiresAt,omitempty"`
}

// TunnexGrantStatus reflects the CP's accepted state — DERIVED truth, never spec.
type TunnexGrantStatus struct {
	// RuleID is the control-plane policy-rule id assigned on creation.
	// +optional
	RuleID string `json:"ruleId,omitempty"`
	// Conditions carry Ready + any CP refusal verbatim — notably edition_required when the org is open-edition
	// (governance is enterprise). HONEST status: never a silent no-op.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Subject",type=string,JSONPath=`.spec.subject`
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.service`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// TunnexGrant is an access grant reaching an exposed Service (enterprise).
type TunnexGrant struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TunnexGrantSpec   `json:"spec,omitempty"`
	Status            TunnexGrantStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TunnexGrantList is a list of TunnexGrant.
type TunnexGrantList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnexGrant `json:"items"`
}

func init() { SchemeBuilder.Register(&TunnexGrant{}, &TunnexGrantList{}) }

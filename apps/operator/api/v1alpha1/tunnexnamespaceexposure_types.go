package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TunnexNamespaceExposureSpec declares a control-plane namespace rule (K8N-4): "expose every Service in
// this namespace of this cluster, now and as Services are added". Exposure gives a Service an address and
// a name on the fabric. It NEVER grants access: a TunnexGrant, or an access rule in Tunnex, does that.
//
// The operator does not list or expose Services itself. It keeps the control plane's rule equal to this
// spec; the control plane applies the rule each time the cluster's gateway reports its Services.
type TunnexNamespaceExposureSpec struct {
	// Cluster is the name of the TunnexCluster resource (same namespace as this resource) whose Services
	// are exposed. It cannot be changed: delete this resource and create another.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MinLength=1
	// +kubebuilder:validation:MaxLength=253
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="cluster cannot be changed; delete this resource and create a new one"
	Cluster string `json:"cluster"`
	// Namespace is the ONE Kubernetes namespace whose Services are exposed. There is no wildcard and no
	// all-namespaces rule. kube-system, kube-public, kube-node-lease and Tunnex's own namespaces (tunnex,
	// tunnex-*) are never eligible. It cannot be changed.
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:MaxLength=63
	// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
	// +kubebuilder:validation:XValidation:rule="self == oldSelf",message="namespace cannot be changed; delete this resource and create a new one"
	// +kubebuilder:validation:XValidation:rule="!(self in ['kube-system', 'kube-public', 'kube-node-lease'])",message="Kubernetes system namespaces cannot be exposed by a namespace rule"
	// +kubebuilder:validation:XValidation:rule="self != 'tunnex' && !self.startsWith('tunnex-')",message="Tunnex's own namespaces cannot be exposed by a namespace rule"
	Namespace string `json:"namespace"`
	// Selector limits the rule to Services whose labels equal EVERY key=value pair. Omit it for every
	// Service of the namespace. It is a flat map on purpose: there are no set operators, no negation and
	// no wildcards, and nothing here can be silently dropped. It needs a gateway that reports Service
	// labels; with an older gateway the rule exposes nothing and this resource is not Ready
	// (gateway_too_old). A Service that stops matching is withdrawn after 10 minutes.
	// +optional
	// +kubebuilder:validation:MaxProperties=8
	Selector map[string]SelectorValue `json:"selector,omitempty"`
	// ExcludedServices are exact Service names of the namespace that the rule must not expose. Adding a
	// name withdraws, at once, the exposures the rule made for that Service; access rules that pointed
	// at them are kept and allow nothing.
	// +optional
	// +listType=set
	// +kubebuilder:validation:MaxItems=100
	ExcludedServices []ServiceName `json:"excludedServices,omitempty"`
	// DeletionPolicy says what happens to the exposures the rule made when THIS RESOURCE is deleted.
	//
	// Keep (the default): the rule is removed and its exposures stay, as ordinary exposures an
	// administrator unexposes one at a time. Nothing new is exposed afterwards.
	//
	// Withdraw: the rule and every exposure it made are removed in one step. Access rules that pointed
	// at them are kept but allow nothing, and they do not come back if the Services are exposed again.
	//
	// Keep is the default because a resource is deleted for many reasons that are not a decision to cut
	// access (a Git revert, a pruning sync, an uninstall, a mistake) and withdrawing cannot be undone.
	// +optional
	// +kubebuilder:default=Keep
	// +kubebuilder:validation:Enum=Keep;Withdraw
	DeletionPolicy string `json:"deletionPolicy,omitempty"`
}

// SelectorValue is a Kubernetes label value.
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^([A-Za-z0-9]([-A-Za-z0-9_.]*[A-Za-z0-9])?)?$`
type SelectorValue string

// ServiceName is a Kubernetes Service name, exactly; no patterns.
// +kubebuilder:validation:MinLength=1
// +kubebuilder:validation:MaxLength=63
// +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
type ServiceName string

const (
	// DeletionPolicyKeep removes the rule and keeps the exposures it made.
	DeletionPolicyKeep = "Keep"
	// DeletionPolicyWithdraw removes the rule and withdraws every exposure it made.
	DeletionPolicyWithdraw = "Withdraw"
)

// TunnexNamespaceExposureStatus reflects the control plane's rule. DERIVED truth, never spec.
type TunnexNamespaceExposureStatus struct {
	// RuleID is the control-plane id of the namespace rule this resource declares.
	// +optional
	RuleID string `json:"ruleId,omitempty"`
	// RuleStatus is the control plane's outcome of the rule's last pass, verbatim: applied, pending,
	// inventory_stale, inventory_unavailable, vip_range_exhausted, scope_review_limit,
	// withdrawal_blocked, gateway_too_old, labels_incomplete or error. Ready is True only for applied.
	// +optional
	RuleStatus string `json:"ruleStatus,omitempty"`
	// ExposedServices and ExposedPorts count what the rule exposes right now.
	// +optional
	ExposedServices int32 `json:"exposedServices"`
	// +optional
	ExposedPorts int32 `json:"exposedPorts"`
	// WaitingServices counts Services the last pass could not expose (a limit was reached).
	// +optional
	WaitingServices int32 `json:"waitingServices"`
	// Conditions carry Ready with the rule's status as reason and the control plane's sentence as
	// message, Drift, and TeardownBlocked when a delete could not complete.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.cluster`
// +kubebuilder:printcolumn:name="Namespace",type=string,JSONPath=`.spec.namespace`
// +kubebuilder:printcolumn:name="Rule",type=string,JSONPath=`.status.ruleStatus`
// +kubebuilder:printcolumn:name="Services",type=integer,JSONPath=`.status.exposedServices`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`
// +kubebuilder:printcolumn:name="On delete",type=string,JSONPath=`.spec.deletionPolicy`

// TunnexNamespaceExposure exposes every Service of one namespace on the Tunnex fabric through a
// control-plane namespace rule.
type TunnexNamespaceExposure struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TunnexNamespaceExposureSpec   `json:"spec,omitempty"`
	Status            TunnexNamespaceExposureStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TunnexNamespaceExposureList is a list of TunnexNamespaceExposure.
type TunnexNamespaceExposureList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnexNamespaceExposure `json:"items"`
}

func init() { SchemeBuilder.Register(&TunnexNamespaceExposure{}, &TunnexNamespaceExposureList{}) }

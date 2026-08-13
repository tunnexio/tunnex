package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TunnexExposedServiceSpec declares an in-cluster Kubernetes Service exposed on the fabric (mirrors the CP's
// ExposeService verb). It must name a SINGLE specific port + protocol — the CP refuses all-ports and ranges
// (M8/M9), so the schema requires them. The org is implicit (the operator's credential); the owning cluster
// is referenced by its TunnexCluster resource name.
type TunnexExposedServiceSpec struct {
	// Cluster is the name of the TunnexCluster resource that owns this Service. Required.
	// +kubebuilder:validation:Required
	Cluster string `json:"cluster"`
	// Namespace is the Kubernetes namespace of the Service. Required.
	// +kubebuilder:validation:Required
	Namespace string `json:"namespace"`
	// Service is the Kubernetes Service name. Required.
	// +kubebuilder:validation:Required
	Service string `json:"service"`
	// Protocol is the exposed L4 protocol. Required (the DNAT needs it; the CP refuses all-ports).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Enum=tcp;udp
	Protocol string `json:"protocol"`
	// Port is the single Service port clients dial at the VIP (1-65535). Required — the CP refuses all-ports
	// and ranges (the gateway DNATs VIP:port to the pod's target port).
	// +kubebuilder:validation:Required
	// +kubebuilder:validation:Minimum=1
	// +kubebuilder:validation:Maximum=65535
	Port int32 `json:"port"`
}

// TunnexExposedServiceStatus reflects the CP's accepted state — DERIVED truth, never spec.
type TunnexExposedServiceStatus struct {
	// ServiceID is the control-plane id assigned at exposure.
	// +optional
	ServiceID string `json:"serviceId,omitempty"`
	// VIP is the synthetic VIP allocated to this Service (derived).
	// +optional
	VIP string `json:"vip,omitempty"`
	// FQDN is the resolvable in-tunnel hostname clients use — <service>.<namespace>.svc.<cluster>.<zone>.
	// It is DERIVED (server-built, the S10.3 copy-don't-construct naming ruling), so it lives in STATUS,
	// never spec — the operator copies it from the CP, never assembles it.
	// +optional
	FQDN string `json:"fqdn,omitempty"`
	// Conditions carry Ready + any CP refusal verbatim (e.g. service_port_required). HONEST status.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Service",type=string,JSONPath=`.spec.service`
// +kubebuilder:printcolumn:name="FQDN",type=string,JSONPath=`.status.fqdn`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// TunnexExposedService is an in-cluster Service exposed on the Tunnex fabric.
type TunnexExposedService struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TunnexExposedServiceSpec   `json:"spec,omitempty"`
	Status            TunnexExposedServiceStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TunnexExposedServiceList is a list of TunnexExposedService.
type TunnexExposedServiceList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnexExposedService `json:"items"`
}

func init() { SchemeBuilder.Register(&TunnexExposedService{}, &TunnexExposedServiceList{}) }

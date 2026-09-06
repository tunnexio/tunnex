package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// TunnexClusterSpec declares a Kubernetes cluster registered on the Tunnex fabric (mirrors the CP's
// RegisterCluster verb). The org is IMPLICIT — it is the org of the operator's machine credential (D3),
// never a spec field. The fronting site is referenced by its name.
// +kubebuilder:validation:XValidation:rule="has(self.provider) == has(self.platform)",message="provider and platform must be supplied together"
// +kubebuilder:validation:XValidation:rule="!has(self.provider) || (self.provider == 'aws' && self.platform == 'eks') || (self.provider == 'azure' && self.platform == 'aks') || (self.provider == 'gcp' && self.platform == 'gke_standard') || (self.provider == 'self_managed' && self.platform == 'kubernetes')",message="provider and platform must be one supported pair"
type TunnexClusterSpec struct {
	// Site is the name of the site whose gateway fronts this cluster. Required.
	// +kubebuilder:validation:Required
	Site string `json:"site"`
	// Connector is the active in-cluster gateway name. The operator resolves it
	// to the control-plane node ID within Site before registration. Required.
	// +kubebuilder:validation:Required
	Connector string `json:"connector"`
	// Provider is optional presentation metadata. It never selects networking or
	// cloud behavior. Provider and Platform must be supplied together as one of
	// the supported exact pairs.
	// +optional
	// +kubebuilder:validation:Enum=aws;azure;gcp;self_managed
	Provider string `json:"provider,omitempty"`
	// Platform is optional presentation metadata paired with Provider.
	// +optional
	// +kubebuilder:validation:Enum=eks;aks;gke_standard;kubernetes
	Platform string `json:"platform,omitempty"`
	// Name is the cluster's name — a DNS label that becomes part of every exposed Service's FQDN. Required.
	// +kubebuilder:validation:Required
	Name string `json:"name"`
	// VIPRange is the cluster's synthetic VIP CIDR (must be disjoint from the device pool, site subnets, and
	// other clusters' ranges — the CP's Collect/OrgRanges validator enforces it). Required.
	// +kubebuilder:validation:Required
	VIPRange string `json:"vipRange"`
	// ServiceCIDR is the cluster's real Kubernetes Service CIDR (e.g. 10.96.0.0/12). Required.
	// +kubebuilder:validation:Required
	ServiceCIDR string `json:"serviceCIDR"`
	// DNSZone is the customer zone suffix of every exposed Service's FQDN (e.g. k8s.acme.com). Required.
	// +kubebuilder:validation:Required
	DNSZone string `json:"dnsZone"`
}

// TunnexClusterStatus reflects the control plane's accepted state — DERIVED truth, never spec.
type TunnexClusterStatus struct {
	// ClusterID is the control-plane id assigned at registration.
	// +optional
	ClusterID string `json:"clusterId,omitempty"`
	// DNSVIP is the cluster's reserved DNS VIP (derived at registration).
	// +optional
	DNSVIP string `json:"dnsVip,omitempty"`
	// Conditions carry Ready + any CP refusal verbatim (e.g. a VIP-range overlap). HONEST status: a CR is
	// Ready ONLY when the CP ACCEPTED it, never merely "applied".
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Cluster",type=string,JSONPath=`.spec.name`
// +kubebuilder:printcolumn:name="Ready",type=string,JSONPath=`.status.conditions[?(@.type=="Ready")].status`

// TunnexCluster is a Kubernetes cluster registered on the Tunnex fabric.
type TunnexCluster struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              TunnexClusterSpec   `json:"spec,omitempty"`
	Status            TunnexClusterStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// TunnexClusterList is a list of TunnexCluster.
type TunnexClusterList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []TunnexCluster `json:"items"`
}

func init() { SchemeBuilder.Register(&TunnexCluster{}, &TunnexClusterList{}) }

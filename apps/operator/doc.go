// Package operator is the module root for the Tunnex GitOps operator (S10.2). It carries no code itself —
// the CRD API is in ./api/v1alpha1, the binary in ./cmd/operator, and the reconcilers (Slice 3) in
// ./controllers. The root exists so the no-DB-import census test (hardrule_test.go) can assert THE HARD
// RULE over the whole module: the operator is an API client of the control plane, never a DB writer.
package operator

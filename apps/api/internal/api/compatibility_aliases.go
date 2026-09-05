package api

// Active, None, and Pending preserve the pre-S21 exported enum names used by
// downstream Go clients. oapi-codegen prefixes these parameter enum values
// because other schemas own the same words; aliases keep that generator detail
// from becoming a source-breaking API change.
const (
	Active  ListAgentsParamsAccess = ListAgentsParamsAccessActive
	None    ListAgentsParamsAccess = ListAgentsParamsAccessNone
	Pending ListAgentsParamsAccess = ListAgentsParamsAccessPending
)

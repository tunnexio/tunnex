package api

// Assigned and Unassigned preserve the pre-S21 exported enum names used by
// downstream Go clients. oapi-codegen now prefixes parameter enum values when
// another schema owns the same words; aliases keep that generator detail from
// becoming a source-breaking API change.
const (
	Assigned   ListAgentsParamsMcp = ListAgentsParamsMcpAssigned
	Unassigned ListAgentsParamsMcp = ListAgentsParamsMcpUnassigned
)

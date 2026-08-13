package rbac

import "testing"

// ⛔ THE WHOLE POINT OF D4 IS ONE ABSENT PERMISSION, SO THAT IS WHAT IS PINNED.
//
// `RoleOperator` holds `PermPolicyManage` — correct for a GitOps operator, whose entire job is reconciling
// TunnexGrant CRs into policy rules, and INVERTED for an agent. A principal that can be talked into a
// request, and can then write the rule permitting it, is a compromised principal granting itself what it
// was denied.
//
// ⚠ The fix was never "remove PermPolicyManage" — that breaks the operator. It was "stop having one role
// for two principal kinds", which is why this test could not have been written before the agent existed.
func TestAgentRoleCannotAuthorPolicy(t *testing.T) {
	if Can(RoleAgent, PermPolicyManage) {
		t.Fatal("D4: an AGENT must not hold PermPolicyManage — it enforces policy, it never authors it")
	}
	// ⛔ THE CONTRAST IS THE ASSERTION. Without this, a table that granted the agent NOTHING would pass
	// above, and so would one where PermPolicyManage had been deleted outright — which would silently
	// break the GitOps operator instead.
	if !Can(RoleOperator, PermPolicyManage) {
		t.Fatal("the OPERATOR must still hold PermPolicyManage — reconciling TunnexGrant CRs is its job, " +
			"and removing the permission breaks the operator rather than narrowing the agent")
	}
}

func TestAgentRoleIsNarrowerThanOperator(t *testing.T) {
	// Every permission the agent holds, the operator must also hold: the agent is a STRICT subset, so a
	// future grant to the agent cannot quietly become wider than the role it was split out of.
	for _, p := range []Permission{PermOrgView} {
		if !Can(RoleAgent, p) {
			t.Fatalf("the agent must hold %v — a role with no permissions is not a role", p)
		}
	}
	// ⚠ AND IT MUST NOT HOLD THE ADMINISTRATIVE ONES. Listed individually rather than counted, because a
	// count passes whenever the total happens to match and says nothing about WHICH.
	for _, p := range []Permission{PermPolicyManage, PermMachineManage, PermMemberList, PermK8sManage} {
		if Can(RoleAgent, p) {
			t.Fatalf("the agent must NOT hold %v — every permission for an unattended principal is argued "+
				"for individually, never inherited from a sibling role that happened to exist first", p)
		}
	}
	// ⛔ NOT USER-ASSIGNABLE, enforced at the database: memberships.role CHECK is (owner, admin, member).
	// Pinned here as a reminder that the cheapness of this role depends on that condition holding.
	for _, human := range []string{"owner", "admin", "member"} {
		if human == RoleAgent {
			t.Fatal("the agent role must never become a human-assignable membership role")
		}
	}
}

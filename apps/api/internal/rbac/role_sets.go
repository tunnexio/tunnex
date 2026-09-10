package rbac

import "fmt"

// NormalizeHumanRoles validates a nonempty set and orders the compatibility
// primary role first. Machine roles never enter a human membership.
func NormalizeHumanRoles(roles []string) ([]string, error) {
	order := []string{RoleOwner, RoleAdmin, RoleAIAdmin, RoleAIView, RoleMember}
	if len(roles) == 0 || len(roles) > len(order) {
		return nil, fmt.Errorf("select at least one human role")
	}
	seen := map[string]bool{}
	for _, role := range roles {
		if !ValidRole(role) || role == RoleAgent || role == RoleOperator || seen[role] {
			return nil, fmt.Errorf("roles must be distinct human roles")
		}
		seen[role] = true
	}
	result := make([]string, 0, len(roles))
	for _, role := range order {
		if seen[role] {
			result = append(result, role)
		}
	}
	return result, nil
}

func CanAny(roles []string, permission Permission) bool {
	for _, role := range roles {
		if Can(role, permission) {
			return true
		}
	}
	return false
}

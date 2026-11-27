package mcpdecision

import (
	"encoding/json"
	"errors"
	"unicode/utf8"
)

// ErrConstraint means the arguments break the constraints an administrator set on the rule.
var ErrConstraint = errors.New("arguments are denied by the rule's constraints")

// constraints is the small policy-authored subset the tool policy accepts (see mcptoolpolicy). When a rule
// carries one, only the properties it names may be sent.
type constraints struct {
	Required   []string              `json:"required"`
	Properties map[string]constraint `json:"properties"`
}

type constraint struct {
	Type      string            `json:"type"`
	Enum      []json.RawMessage `json:"enum"`
	MaxLength *int              `json:"max_length"`
	Minimum   *float64          `json:"minimum"`
	Maximum   *float64          `json:"maximum"`
}

// CheckConstraints applies a rule's argument constraints with the meaning the agent-host proxy gave them.
// No constraints means nothing further to check.
func CheckConstraints(raw json.RawMessage, arguments []byte) error {
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	var c constraints
	if json.Unmarshal(raw, &c) != nil {
		return ErrConstraint
	}
	value := map[string]json.RawMessage{}
	if len(arguments) > 0 && string(arguments) != "null" {
		if json.Unmarshal(arguments, &value) != nil {
			return ErrConstraint
		}
	}
	for _, required := range c.Required {
		if _, ok := value[required]; !ok {
			return ErrConstraint
		}
	}
	for name, item := range value {
		rule, ok := c.Properties[name]
		if !ok || !rule.allows(item) {
			return ErrConstraint
		}
	}
	return nil
}

func (c constraint) allows(raw json.RawMessage) bool {
	var value interface{}
	if json.Unmarshal(raw, &value) != nil {
		return false
	}
	switch c.Type {
	case "string":
		s, ok := value.(string)
		if !ok || (c.MaxLength != nil && utf8.RuneCountInString(s) > *c.MaxLength) {
			return false
		}
	case "number", "integer":
		n, ok := value.(float64)
		if !ok || (c.Type == "integer" && n != float64(int64(n))) || (c.Minimum != nil && n < *c.Minimum) || (c.Maximum != nil && n > *c.Maximum) {
			return false
		}
	case "boolean":
		if _, ok := value.(bool); !ok {
			return false
		}
	default:
		return false
	}
	if len(c.Enum) == 0 {
		return true
	}
	canonical, _ := json.Marshal(value)
	for _, allowed := range c.Enum {
		var want interface{}
		if json.Unmarshal(allowed, &want) != nil {
			continue
		}
		normal, _ := json.Marshal(want)
		if string(canonical) == string(normal) {
			return true
		}
	}
	return false
}

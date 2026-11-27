// Package mcpdecision is the control plane's answer to a gateway asking whether one MCP request from one
// agent may be forwarded (AI-SEC-2). It owns the order of the checks; the tool allow-list, the definition
// pin and step-up approvals stay in their own packages.
package mcpdecision

import (
	"bytes"
	"encoding/json"
	"errors"
	"math"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ErrSchema means the arguments do not fit the tool's observed input schema.
var ErrSchema = errors.New("arguments do not match the tool input schema")

const (
	schemaMaxDepth = 32
	schemaMaxSteps = 100000
)

// CheckArguments validates a call's arguments against the input schema the gateway observed: value types,
// required arguments and arguments the schema does not declare. It runs for every allowed tool, with or
// without administrator constraints.
//
// It understands the part of JSON Schema that MCP tools use (type, properties, required,
// additionalProperties, patternProperties, items, enum, const, bounds, anyOf/oneOf/allOf and local $ref).
// What it cannot evaluate it refuses rather than forwards: an unresolvable reference, or nesting past the
// depth limit, denies the call.
//
// Undeclared arguments: at the top level an argument must be declared unless the schema says otherwise
// with additionalProperties. A nested object is held to the same rule once it declares properties; a nested
// object schema that declares none is free-form.
func CheckArguments(schema json.RawMessage, arguments []byte) error {
	var root interface{}
	if json.Unmarshal(schema, &root) != nil {
		return ErrSchema
	}
	if _, ok := root.(map[string]interface{}); !ok {
		return ErrSchema
	}
	decoder := json.NewDecoder(bytes.NewReader(arguments))
	decoder.UseNumber()
	var value map[string]interface{}
	if len(bytes.TrimSpace(arguments)) == 0 || string(bytes.TrimSpace(arguments)) == "null" {
		value = map[string]interface{}{}
	} else if err := decoder.Decode(&value); err != nil || value == nil || decoder.More() {
		return ErrSchema
	}
	c := &schemaCheck{root: root}
	if !c.valid(value, root, 0, true) {
		return ErrSchema
	}
	return nil
}

type schemaCheck struct {
	root  interface{}
	steps int
}

func (c *schemaCheck) valid(value, schema interface{}, depth int, top bool) bool {
	c.steps++
	if depth > schemaMaxDepth || c.steps > schemaMaxSteps {
		return false
	}
	switch s := schema.(type) {
	case bool:
		return s
	case map[string]interface{}:
		return c.validObjectSchema(value, s, depth, top)
	default:
		return false
	}
}

func (c *schemaCheck) validObjectSchema(value interface{}, s map[string]interface{}, depth int, top bool) bool {
	if ref, ok := s["$ref"].(string); ok {
		target, found := c.resolve(ref)
		if !found || !c.valid(value, target, depth+1, top) {
			return false
		}
	}
	if t, ok := s["type"]; ok && !typeMatches(value, t) {
		return false
	}
	if enum, ok := s["enum"].([]interface{}); ok {
		matched := false
		for _, allowed := range enum {
			if sameJSON(value, allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	if constant, ok := s["const"]; ok && !sameJSON(value, constant) {
		return false
	}
	for _, key := range []string{"anyOf", "oneOf"} {
		if options, ok := s[key].([]interface{}); ok {
			matched := false
			for _, option := range options {
				if c.valid(value, option, depth+1, top) {
					matched = true
					break
				}
			}
			if !matched {
				return false
			}
		}
	}
	if all, ok := s["allOf"].([]interface{}); ok {
		for _, part := range all {
			if !c.valid(value, part, depth+1, false) {
				return false
			}
		}
	}
	switch v := value.(type) {
	case map[string]interface{}:
		return c.validProperties(v, s, depth, top)
	case []interface{}:
		if !withinCount(len(v), s["minItems"], s["maxItems"]) {
			return false
		}
		if items, ok := s["items"]; ok {
			for _, item := range v {
				if !c.valid(item, items, depth+1, false) {
					return false
				}
			}
		}
	case string:
		if !withinCount(utf8.RuneCountInString(v), s["minLength"], s["maxLength"]) {
			return false
		}
	case json.Number:
		n, err := v.Float64()
		if err != nil {
			return false
		}
		if minimum, ok := s["minimum"].(float64); ok && n < minimum {
			return false
		}
		if maximum, ok := s["maximum"].(float64); ok && n > maximum {
			return false
		}
		if minimum, ok := s["exclusiveMinimum"].(float64); ok && n <= minimum {
			return false
		}
		if maximum, ok := s["exclusiveMaximum"].(float64); ok && n >= maximum {
			return false
		}
	}
	return true
}

func (c *schemaCheck) validProperties(value map[string]interface{}, s map[string]interface{}, depth int, top bool) bool {
	if required, ok := s["required"].([]interface{}); ok {
		for _, name := range required {
			key, isString := name.(string)
			if !isString {
				return false
			}
			if _, present := value[key]; !present {
				return false
			}
		}
	}
	properties, declares := s["properties"].(map[string]interface{})
	patterns, _ := s["patternProperties"].(map[string]interface{})
	additional, hasAdditional := s["additionalProperties"]
	for name, item := range value {
		if property, ok := properties[name]; ok {
			if !c.valid(item, property, depth+1, false) {
				return false
			}
			continue
		}
		matched := false
		for pattern, patternSchema := range patterns {
			re, err := regexp.Compile(pattern)
			if err != nil {
				return false
			}
			if re.MatchString(name) {
				if !c.valid(item, patternSchema, depth+1, false) {
					return false
				}
				matched = true
			}
		}
		if matched {
			continue
		}
		if hasAdditional {
			if !c.valid(item, additional, depth+1, false) {
				return false
			}
			continue
		}
		// Not declared and nothing in the schema admits it.
		if top || declares {
			return false
		}
	}
	return true
}

// resolve follows a reference into the same schema document. Anything else cannot be evaluated here.
func (c *schemaCheck) resolve(ref string) (interface{}, bool) {
	if ref == "#" {
		return c.root, true
	}
	if !strings.HasPrefix(ref, "#/") {
		return nil, false
	}
	current := c.root
	for _, part := range strings.Split(ref[2:], "/") {
		part = strings.ReplaceAll(strings.ReplaceAll(part, "~1", "/"), "~0", "~")
		object, ok := current.(map[string]interface{})
		if !ok {
			return nil, false
		}
		if current, ok = object[part]; !ok {
			return nil, false
		}
	}
	return current, true
}

func typeMatches(value, declared interface{}) bool {
	switch t := declared.(type) {
	case string:
		return isType(value, t)
	case []interface{}:
		for _, option := range t {
			if name, ok := option.(string); ok && isType(value, name) {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func isType(value interface{}, name string) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]interface{})
		return ok
	case "array":
		_, ok := value.([]interface{})
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	case "number":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		_, err := n.Float64()
		return err == nil
	case "integer":
		n, ok := value.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && !math.IsInf(f, 0) && f == math.Trunc(f)
	default:
		return false
	}
}

func withinCount(n int, minimum, maximum interface{}) bool {
	if low, ok := minimum.(float64); ok && float64(n) < low {
		return false
	}
	if high, ok := maximum.(float64); ok && float64(n) > high {
		return false
	}
	return true
}

// sameJSON compares a call value (numbers kept as literals) with a schema value (numbers as float64).
func sameJSON(value, allowed interface{}) bool {
	left, errLeft := json.Marshal(plainNumbers(value))
	right, errRight := json.Marshal(allowed)
	return errLeft == nil && errRight == nil && bytes.Equal(left, right)
}

func plainNumbers(value interface{}) interface{} {
	switch v := value.(type) {
	case json.Number:
		if f, err := v.Float64(); err == nil {
			return f
		}
		return v.String()
	case []interface{}:
		out := make([]interface{}, len(v))
		for i, item := range v {
			out[i] = plainNumbers(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, item := range v {
			out[key] = plainNumbers(item)
		}
		return out
	default:
		return value
	}
}

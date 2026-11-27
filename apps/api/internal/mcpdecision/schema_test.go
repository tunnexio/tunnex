package mcpdecision

import (
	"encoding/json"
	"testing"
)

const refundSchema = `{"type":"object","properties":{
 "customer":{"type":"string","maxLength":20},
 "amount":{"type":"number","minimum":0},
 "count":{"type":"integer"},
 "urgent":{"type":"boolean"},
 "currency":{"enum":["EUR","USD"]},
 "tags":{"type":"array","items":{"type":"string"},"maxItems":2},
 "address":{"type":"object","properties":{"city":{"type":"string"}},"required":["city"]},
 "metadata":{"type":"object"},
 "id":{"anyOf":[{"type":"string"},{"type":"integer"}]},
 "ref":{"$ref":"#/$defs/code"}
},"required":["customer"],"$defs":{"code":{"type":"string","minLength":2}}}`

func TestCheckArgumentsObservedSchema(t *testing.T) {
	tests := map[string]struct {
		arguments string
		ok        bool
	}{
		"minimal":                  {`{"customer":"c1"}`, true},
		"all declared":             {`{"customer":"c1","amount":10.5,"count":3,"urgent":true,"currency":"EUR","tags":["a"],"address":{"city":"x"},"metadata":{"anything":[1,{"a":null}]},"id":7,"ref":"ab"}`, true},
		"integer written as float": {`{"customer":"c1","count":3.0}`, true},
		"missing required":         {`{"amount":1}`, false},
		"absent arguments":         {``, false},
		"wrong type string":        {`{"customer":7}`, false},
		"wrong type number":        {`{"customer":"c1","amount":"10"}`, false},
		"wrong type integer":       {`{"customer":"c1","count":1.5}`, false},
		"wrong type boolean":       {`{"customer":"c1","urgent":"yes"}`, false},
		"undeclared argument":      {`{"customer":"c1","sql":"drop table"}`, false},
		"not in enum":              {`{"customer":"c1","currency":"GBP"}`, false},
		"below minimum":            {`{"customer":"c1","amount":-1}`, false},
		"too long":                 {`{"customer":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`, false},
		"array item type":          {`{"customer":"c1","tags":[1]}`, false},
		"array too long":           {`{"customer":"c1","tags":["a","b","c"]}`, false},
		"nested required":          {`{"customer":"c1","address":{}}`, false},
		"nested undeclared":        {`{"customer":"c1","address":{"city":"x","zip":"1"}}`, false},
		"anyOf no branch":          {`{"customer":"c1","id":true}`, false},
		"ref target":               {`{"customer":"c1","ref":"a"}`, false},
		"null for string":          {`{"customer":null}`, false},
	}
	for name, tt := range tests {
		err := CheckArguments(json.RawMessage(refundSchema), []byte(tt.arguments))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tt.ok)
		}
	}
}

func TestCheckArgumentsSchemaForms(t *testing.T) {
	tests := map[string]struct {
		schema, arguments string
		ok                bool
	}{
		"no properties, no arguments":       {`{"type":"object"}`, `{}`, true},
		"no properties, an argument":        {`{"type":"object"}`, `{"a":1}`, false},
		"additionalProperties true":         {`{"type":"object","additionalProperties":true}`, `{"a":1}`, true},
		"additionalProperties schema":       {`{"type":"object","additionalProperties":{"type":"string"}}`, `{"a":1}`, false},
		"additionalProperties false":        {`{"type":"object","properties":{"a":{}},"additionalProperties":false}`, `{"b":1}`, false},
		"pattern property":                  {`{"type":"object","patternProperties":{"^x-":{"type":"string"}}}`, `{"x-a":"v"}`, true},
		"pattern property wrong type":       {`{"type":"object","patternProperties":{"^x-":{"type":"string"}}}`, `{"x-a":1}`, false},
		"type list":                         {`{"type":"object","properties":{"a":{"type":["string","null"]}}}`, `{"a":null}`, true},
		"unresolvable reference is refused": {`{"type":"object","properties":{"a":{"$ref":"https://example.com/s.json"}}}`, `{"a":1}`, false},
		"schema is not an object":           {`[]`, `{}`, false},
		"arguments are not an object":       {`{"type":"object"}`, `[1]`, false},
		"false schema":                      {`{"type":"object","properties":{"a":false}}`, `{"a":1}`, false},
	}
	for name, tt := range tests {
		err := CheckArguments(json.RawMessage(tt.schema), []byte(tt.arguments))
		if (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tt.ok)
		}
	}
}

func TestCheckArgumentsBoundsRecursion(t *testing.T) {
	schema := `{"type":"object","properties":{"a":{"$ref":"#/properties/a"}}}`
	if err := CheckArguments(json.RawMessage(schema), []byte(`{"a":1}`)); err == nil {
		t.Fatal("a self-referencing schema was accepted")
	}
}

func TestCheckConstraints(t *testing.T) {
	raw := json.RawMessage(`{"required":["customer"],"properties":{"customer":{"type":"string","max_length":4},"amount":{"type":"number","maximum":100},"mode":{"type":"string","enum":["safe"]}}}`)
	tests := map[string]struct {
		arguments string
		ok        bool
	}{
		"within":               {`{"amount":100,"customer":"c1","mode":"safe"}`, true},
		"over maximum":         {`{"amount":101,"customer":"c1"}`, false},
		"missing required":     {`{"amount":1}`, false},
		"not a named property": {`{"customer":"c1","note":"x"}`, false},
		"enum":                 {`{"customer":"c1","mode":"fast"}`, false},
		"too long":             {`{"customer":"customer"}`, false},
	}
	for name, tt := range tests {
		if err := CheckConstraints(raw, []byte(tt.arguments)); (err == nil) != tt.ok {
			t.Errorf("%s: err = %v, want ok=%v", name, err, tt.ok)
		}
	}
	if err := CheckConstraints(nil, []byte(`{"anything":1}`)); err != nil {
		t.Fatalf("no constraints err = %v", err)
	}
}

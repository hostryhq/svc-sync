// Package specs reads the sync contract of record from a checkout of the api-specs repository:
// openapi/sync/v1/openapi.yaml, sync/conformance/v1.json, sync/intents/*.yaml and entities/. svc-sync
// keeps no copy; the checkout is found through API_SPECS_DIR or as a sibling directory
// (../api-specs-p2 first, then ../api-specs). contract/README.md names the pinned version.
package specs

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
)

// ErrNoSpecs is returned when no api-specs checkout can be found.
var ErrNoSpecs = errors.New("specs: no api-specs checkout found (set API_SPECS_DIR)")

// Dir returns the api-specs checkout directory.
func Dir() (string, error) {
	if d := os.Getenv("API_SPECS_DIR"); d != "" {
		return d, nil
	}
	_, file, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(file), "..", "..")
	for _, n := range []string{"api-specs-p2", "api-specs"} {
		d := filepath.Join(root, "..", n)
		if _, err := os.Stat(filepath.Join(d, "openapi", "sync", "v1", "openapi.yaml")); err == nil {
			return d, nil
		}
	}
	return "", ErrNoSpecs
}

// Path joins elem under the checkout.
func Path(elem ...string) (string, error) {
	d, err := Dir()
	if err != nil {
		return "", err
	}
	return filepath.Join(append([]string{d}, elem...)...), nil
}

// OpenAPI is the parsed sync OpenAPI document.
type OpenAPI struct {
	Doc map[string]any
}

// LoadOpenAPI parses openapi/sync/v1/openapi.yaml.
func LoadOpenAPI() (*OpenAPI, error) {
	p, err := Path("openapi", "sync", "v1", "openapi.yaml")
	if err != nil {
		return nil, err
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, err
	}
	return &OpenAPI{Doc: doc}, nil
}

func dig(v any, keys ...string) any {
	for _, k := range keys {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

// Operation is one operation of the document.
type Operation struct {
	ID, Method, Path, Permission string
	Callers                      []string
	node                         map[string]any
}

// Operations lists every operation.
func (o *OpenAPI) Operations() []Operation {
	var out []Operation
	paths, _ := o.Doc["paths"].(map[string]any)
	for p, item := range paths {
		im, _ := item.(map[string]any)
		for m, opn := range im {
			on, ok := opn.(map[string]any)
			if !ok {
				continue
			}
			op := Operation{Method: strings.ToUpper(m), Path: p, node: on}
			op.ID, _ = on["operationId"].(string)
			op.Permission, _ = on["x-permission"].(string)
			if cs, ok := on["x-service-callers"].([]any); ok {
				for _, c := range cs {
					op.Callers = append(op.Callers, fmt.Sprint(c))
				}
			}
			out = append(out, op)
		}
	}
	return out
}

// Find returns the operation for a method and path.
func (o *OpenAPI) Find(method, path string) (Operation, bool) {
	for _, op := range o.Operations() {
		if op.Method == method && op.Path == path {
			return op, true
		}
	}
	return Operation{}, false
}

// ResponseSchema returns the JSON schema of the response body for status, or nil (shared
// responses of api-specs/common are referenced, not inlined, and answer the Problem shape).
func (o *OpenAPI) ResponseSchema(op Operation, status int) map[string]any {
	r := dig(op.node, "responses", fmt.Sprint(status))
	for _, ct := range []string{"application/json", "application/problem+json"} {
		if s, ok := dig(r, "content", ct, "schema").(map[string]any); ok {
			return s
		}
	}
	return nil
}

// RequestSchema returns the JSON schema of the request body, or nil.
func (o *OpenAPI) RequestSchema(op Operation) map[string]any {
	s, _ := dig(op.node, "requestBody", "content", "application/json", "schema").(map[string]any)
	return s
}

// Example is a request or response example of an operation with its schema.
type Example struct {
	Operation string
	Kind      string // request, or response:<status>
	Value     any
	Schema    map[string]any
}

// Examples lists every request and response example that has a schema.
func (o *OpenAPI) Examples() []Example {
	var out []Example
	for _, op := range o.Operations() {
		if s := o.RequestSchema(op); s != nil {
			if ex := dig(op.node, "requestBody", "content", "application/json", "example"); ex != nil {
				out = append(out, Example{op.ID, "request", ex, s})
			}
		}
		resp, _ := op.node["responses"].(map[string]any)
		for st, r := range resp {
			for _, ct := range []string{"application/json", "application/problem+json"} {
				ex := dig(r, "content", ct, "example")
				s, _ := dig(r, "content", ct, "schema").(map[string]any)
				if ex != nil && s != nil {
					out = append(out, Example{op.ID, "response:" + st, ex, s})
				}
			}
		}
	}
	return out
}

// Validate checks v (decoded JSON) against schema, resolving local $refs. It checks what the
// contract states: type, required, properties, items, enum and string and array bounds. A $ref
// into api-specs/common is accepted as satisfied. Unknown properties are allowed (consumers
// ignore them, ADR-0002 S13).
func (o *OpenAPI) Validate(schema map[string]any, v any) error {
	return o.validate(schema, v, "$")
}

func (o *OpenAPI) deref(s map[string]any) (map[string]any, bool) {
	for i := 0; i < 16; i++ {
		ref, ok := s["$ref"].(string)
		if !ok {
			return s, true
		}
		name, local := strings.CutPrefix(ref, "#/components/schemas/")
		if !local {
			return nil, false
		}
		next, _ := dig(o.Doc, "components", "schemas", name).(map[string]any)
		if next == nil {
			return nil, false
		}
		s = next
	}
	return s, true
}

func (o *OpenAPI) validate(schema map[string]any, v any, at string) error {
	s, ok := o.deref(schema)
	if !ok {
		return nil
	}
	if types, ok := s["type"]; ok && !typeOK(types, v) {
		return fmt.Errorf("%s: %T is not of type %v", at, v, types)
	}
	if en, ok := s["enum"].([]any); ok {
		found := false
		for _, e := range en {
			if fmt.Sprint(e) == fmt.Sprint(v) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("%s: %v is not in the enum", at, v)
		}
	}
	switch x := v.(type) {
	case map[string]any:
		if req, ok := s["required"].([]any); ok {
			for _, r := range req {
				if _, have := x[fmt.Sprint(r)]; !have {
					return fmt.Errorf("%s: required property %v is missing", at, r)
				}
			}
		}
		props, _ := s["properties"].(map[string]any)
		for k, pv := range x {
			if ps, ok := props[k].(map[string]any); ok {
				if err := o.validate(ps, pv, at+"."+k); err != nil {
					return err
				}
			}
		}
	case []any:
		if n, ok := num(s["minItems"]); ok && len(x) < n {
			return fmt.Errorf("%s: fewer than %d items", at, n)
		}
		if n, ok := num(s["maxItems"]); ok && len(x) > n {
			return fmt.Errorf("%s: more than %d items", at, n)
		}
		if is, ok := s["items"].(map[string]any); ok {
			for i, e := range x {
				if err := o.validate(is, e, fmt.Sprintf("%s[%d]", at, i)); err != nil {
					return err
				}
			}
		}
	case string:
		if n, ok := num(s["maxLength"]); ok && len(x) > n {
			return fmt.Errorf("%s: longer than %d", at, n)
		}
		if n, ok := num(s["minLength"]); ok && len(x) < n {
			return fmt.Errorf("%s: shorter than %d", at, n)
		}
	}
	return nil
}

func num(v any) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case float64:
		return int(n), true
	}
	return 0, false
}

func typeOK(types any, v any) bool {
	var list []string
	switch t := types.(type) {
	case string:
		list = []string{t}
	case []any:
		for _, e := range t {
			list = append(list, fmt.Sprint(e))
		}
	}
	for _, t := range list {
		switch t {
		case "object":
			if _, ok := v.(map[string]any); ok {
				return true
			}
		case "array":
			if _, ok := v.([]any); ok {
				return true
			}
		case "string":
			if _, ok := v.(string); ok {
				return true
			}
		case "boolean":
			if _, ok := v.(bool); ok {
				return true
			}
		case "null":
			if v == nil {
				return true
			}
		case "integer":
			switch n := v.(type) {
			case int, int64:
				return true
			case float64:
				return n == float64(int64(n))
			}
		case "number":
			switch v.(type) {
			case int, int64, float64:
				return true
			}
		}
	}
	return false
}

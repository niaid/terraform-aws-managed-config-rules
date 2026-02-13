package domain

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"
)

// HCLRenderer renders ConfigRule entities into HCL strings using Go text/template.
// Templates are passed as strings and parsed in-memory — no filesystem dependency.
type HCLRenderer struct{}

// RenderLocals renders a list of ConfigRule entities into an HCL locals block string.
func (hr *HCLRenderer) RenderLocals(rules []ConfigRule, templateStr string) (string, error) {
	funcMap := template.FuncMap{
		"localsDesc": func(r ConfigRule) string {
			return r.LocalsDescription(256)
		},
		"formatResourceTypes": func(types []string) string {
			quoted := make([]string, len(types))
			for i, t := range types {
				quoted[i] = fmt.Sprintf(`"%s"`, t)
			}
			return "[" + strings.Join(quoted, ", ") + "]"
		},
	}

	tmpl, err := template.New("locals").Funcs(funcMap).Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parsing locals template: %w", err)
	}

	var buf bytes.Buffer
	err = tmpl.Execute(&buf, map[string]any{
		"Rules": rules,
	})
	if err != nil {
		return "", fmt.Errorf("executing locals template: %w", err)
	}

	return buf.String(), nil
}

// RenderVariables renders a list of ConfigRule entities (with parameters) into HCL variable definitions.
func (hr *HCLRenderer) RenderVariables(rules []ConfigRule, templateStr string) (string, error) {
	tmpl, err := template.New("variable").Parse(templateStr)
	if err != nil {
		return "", fmt.Errorf("parsing variable template: %w", err)
	}

	var results []string
	for i := range rules {
		var buf bytes.Buffer
		err = tmpl.Execute(&buf, map[string]any{
			"Config": &rules[i],
		})
		if err != nil {
			return "", fmt.Errorf("executing variable template for rule %s: %w", rules[i].TfRuleName(), err)
		}
		results = append(results, buf.String())
	}

	return strings.Join(results, "\n\n"), nil
}

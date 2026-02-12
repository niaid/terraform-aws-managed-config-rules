package domain

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Minimal locals template for property testing — mirrors the structure of the real template.
const testLocalsTemplate = `locals {
    managed_rules = {
        {{- range .Rules}}
            {{.TfRuleName}} = {
                description = "{{localsDesc .}}"
                identifier = "{{.RuleIdentifier}}"
                {{- if .ParametersData}}
                input_parameters = var.{{.TfVariableName}}
                {{- end}}
                {{- if .ResourceTypes}}
                resource_types_scope = {{formatResourceTypes .ResourceTypes}}
                {{- end}}
                severity = "{{.RuleSeverity}}"
            }
        {{end}}
    }
}
`

// Minimal variable template for property testing — mirrors the structure of the real template.
const testVariableTemplate = `variable "{{.Config.TfVariableName}}" {
    description = "Input parameters for the {{.Config.TfRuleName}} rule."
    type        = {{.Config.TfVariableTypeHCL}}
    {{- if .Config.HasDefaults}}
    default     = {{.Config.TfVariableDefaultValueHCL}}
    {{else}}
    default    = {}
    {{- end}}
}
`

func genConfigRuleForRenderer(t *rapid.T) ConfigRule {
	raw := genRawConfigRuleData(t)
	return NewConfigRule(raw)
}

// Feature: scripts-lib-hexagonal-refactor, Property 8: HCL locals rendering contains all rule data
// Validates: Requirements 7.1
func TestProperty8_HCLLocalsRenderingContainsAllRuleData(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numRules := rapid.IntRange(1, 5).Draw(t, "numRules")
		rules := make([]ConfigRule, numRules)
		for i := range rules {
			rules[i] = genConfigRuleForRenderer(t)
		}

		renderer := &HCLRenderer{}
		output, err := renderer.RenderLocals(rules, testLocalsTemplate)
		if err != nil {
			t.Fatalf("RenderLocals failed: %v", err)
		}

		for _, rule := range rules {
			if !strings.Contains(output, rule.TfRuleName()) {
				t.Fatalf("rendered locals missing TfRuleName %q", rule.TfRuleName())
			}
			if !strings.Contains(output, rule.RuleIdentifier) {
				t.Fatalf("rendered locals missing RuleIdentifier %q", rule.RuleIdentifier)
			}
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 9: HCL variables rendering contains all variable names
// Validates: Requirements 7.2
func TestProperty9_HCLVariablesRenderingContainsAllVariableNames(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numRules := rapid.IntRange(1, 5).Draw(t, "numRules")
		rules := make([]ConfigRule, numRules)
		for i := range rules {
			// Ensure each rule has at least one parameter.
			numParams := rapid.IntRange(1, 3).Draw(t, "numParams")
			params := make([]ParameterData, numParams)
			for j := range params {
				params[j] = genParameterData(t)
			}
			raw := genRawConfigRuleData(t)
			raw.Parameters = params
			rules[i] = NewConfigRule(raw)
		}

		renderer := &HCLRenderer{}
		output, err := renderer.RenderVariables(rules, testVariableTemplate)
		if err != nil {
			t.Fatalf("RenderVariables failed: %v", err)
		}

		for _, rule := range rules {
			if !strings.Contains(output, rule.TfVariableName()) {
				t.Fatalf("rendered variables missing TfVariableName %q", rule.TfVariableName())
			}
		}
	})
}

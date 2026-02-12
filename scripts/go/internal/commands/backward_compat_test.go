package commands

import (
	"fmt"
	"scripts/go/internal/domain"
	"sort"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// --- In-memory port stubs ---

type captureHCLOutput struct {
	LocalsContent    string
	VariablesContent string
}

func (c *captureHCLOutput) WriteLocals(content string) error {
	c.LocalsContent = content
	return nil
}

func (c *captureHCLOutput) WriteVariables(content string) error {
	c.VariablesContent = content
	return nil
}

type noopFormatter struct{}

func (n *noopFormatter) Format(path string) error { return nil }

// --- Templates matching the real ones in scripts/go/templates/ ---

const realLocalsTemplate = `locals {
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

const realVariableTemplate = `variable "{{.Config.TfVariableName}}" {
    description = "Input parameters for the {{.Config.TfRuleName}} rule."
    type        = {{.Config.TfVariableTypeHCL}}
    {{- if .Config.HasDefaults}}
    default     = {{.Config.TfVariableDefaultValueHCL}}
    {{else}}
    default    = {}
    {{- end}}
}
`

// --- Generators ---

func genRawConfigRuleData(t *rapid.T) domain.RawConfigRuleData {
	numParams := rapid.IntRange(0, 5).Draw(t, "numParams")
	params := make([]domain.ParameterData, numParams)
	for i := range params {
		params[i] = genParameterData(t)
	}
	numResTypes := rapid.IntRange(0, 3).Draw(t, "numResTypes")
	resTypes := make([]string, numResTypes)
	for i := range resTypes {
		resTypes[i] = rapid.StringMatching(`AWS::[A-Z][a-z]+::[A-Z][a-z]+`).Draw(t, "resType")
	}
	return domain.RawConfigRuleData{
		Name:          rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "name"),
		Identifier:    rapid.StringMatching(`[A-Z][A-Z0-9_]{2,20}`).Draw(t, "identifier"),
		Description:   rapid.StringMatching(`[a-zA-Z0-9 .]{1,80}`).Draw(t, "description"),
		Parameters:    params,
		ResourceTypes: resTypes,
		Severity:      rapid.SampledFrom([]string{"Low", "Medium", "High", "Critical"}).Draw(t, "severity"),
	}
}

// Feature: scripts-lib-hexagonal-refactor, Property 13: Backward compatible HCL output
// Validates: Requirements 9.1, 9.2
//
// For any valid list of RawConfigRuleData, the Go HCL rendering pipeline should produce:
// - A locals block containing every rule's TfRuleName, RuleIdentifier, and RuleSeverity
// - Variable definitions for every rule with parameters, containing TfVariableName
// - Structurally valid HCL (starts with "locals {", ends with "}")
// - Correct severity after applying overrides and Security Hub controls
func TestProperty13_BackwardCompatibleHCLOutput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate random config rules.
		numRules := rapid.IntRange(1, 10).Draw(t, "numRules")
		rawRules := make([]domain.RawConfigRuleData, numRules)
		for i := range rawRules {
			rawRules[i] = genRawConfigRuleData(t)
		}

		// Construct domain entities (same as query handler would).
		rules := make([]domain.ConfigRule, len(rawRules))
		for i, raw := range rawRules {
			rules[i] = domain.NewConfigRule(raw)
		}

		// Generate some severity overrides and Security Hub controls.
		numOverrides := rapid.IntRange(0, 3).Draw(t, "numOverrides")
		overrides := make([]domain.SeverityOverride, numOverrides)
		for i := range overrides {
			ruleIdx := rapid.IntRange(0, len(rules)-1).Draw(t, "overrideRuleIdx")
			overrides[i] = domain.SeverityOverride{
				RuleName: rules[ruleIdx].TfRuleName(),
				Severity: rapid.SampledFrom([]string{"Low", "Medium", "High", "Critical"}).Draw(t, "overrideSeverity"),
			}
		}

		numControls := rapid.IntRange(0, 3).Draw(t, "numControls")
		controls := make([]domain.SecurityHubControl, numControls)
		for i := range controls {
			ruleIdx := rapid.IntRange(0, len(rules)-1).Draw(t, "controlRuleIdx")
			controls[i] = domain.SecurityHubControl{
				ControlName: rapid.StringMatching(`[A-Z]{2,5}\.[0-9]{1,3}`).Draw(t, "controlName"),
				Severity:    rapid.SampledFrom([]string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}).Draw(t, "controlSeverity"),
				RuleName:    rules[ruleIdx].TfRuleName(),
			}
		}

		// Apply severity resolution (same pipeline as the CLI).
		resolver := &domain.SeverityResolver{}
		rules = resolver.Resolve(rules, overrides, controls)

		// Run the HCL generation command.
		hclOutput := &captureHCLOutput{}
		cmd := &GenerateHCLCommand{
			HCLOutput:        hclOutput,
			HCLFormatter:     &noopFormatter{},
			LocalsTemplate:   realLocalsTemplate,
			VariableTemplate: realVariableTemplate,
		}
		err := cmd.Execute(rules)
		if err != nil {
			t.Fatalf("GenerateHCLCommand.Execute failed: %v", err)
		}

		// Verify locals block structure.
		locals := hclOutput.LocalsContent
		if !strings.HasPrefix(strings.TrimSpace(locals), "locals {") {
			t.Fatalf("locals block does not start with 'locals {': %q", locals[:min(80, len(locals))])
		}
		if !strings.HasSuffix(strings.TrimSpace(locals), "}") {
			t.Fatalf("locals block does not end with '}'")
		}

		// Verify every rule appears in the locals block.
		for _, rule := range rules {
			if !strings.Contains(locals, rule.TfRuleName()) {
				t.Fatalf("locals block missing rule name %q", rule.TfRuleName())
			}
			if !strings.Contains(locals, rule.RuleIdentifier) {
				t.Fatalf("locals block missing identifier %q", rule.RuleIdentifier)
			}
			if !strings.Contains(locals, fmt.Sprintf(`severity = "%s"`, rule.RuleSeverity())) {
				t.Fatalf("locals block missing severity %q for rule %q", rule.RuleSeverity(), rule.TfRuleName())
			}
		}

		// Verify variables output for rules with parameters.
		variables := hclOutput.VariablesContent
		for _, rule := range rules {
			if len(rule.ParametersData) > 0 {
				if !strings.Contains(variables, rule.TfVariableName()) {
					t.Fatalf("variables output missing variable name %q", rule.TfVariableName())
				}
				// Each variable block should reference the rule name in its description.
				expectedDesc := fmt.Sprintf("Input parameters for the %s rule.", rule.TfRuleName())
				if !strings.Contains(variables, expectedDesc) {
					t.Fatalf("variables output missing description for %q", rule.TfRuleName())
				}
			}
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 14: Backward compatible rule pack output
// Validates: Requirements 9.3, 9.4
//
// For any valid set of conformance pack YAML data and config rules, the Go pack processing
// pipeline should produce:
// - A packs map where each key is a pack name and each value is a sorted list of rule names
// - A pack names list matching the keys of the packs map
// - Rule names that correspond to actual config rules referenced by the pack resources
func TestProperty14_BackwardCompatibleRulePackOutput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate config rules.
		numRules := rapid.IntRange(1, 8).Draw(t, "numRules")
		configRules := make([]domain.ConfigRule, numRules)
		for i := range configRules {
			raw := genRawConfigRuleData(t)
			configRules[i] = domain.NewConfigRule(raw)
		}

		// Generate conformance packs that reference the config rules.
		numPacks := rapid.IntRange(1, 5).Draw(t, "numPacks")
		packs := make([]domain.RawConformancePackData, numPacks)
		for i := range packs {
			packs[i] = genConformancePackDataCompat(t, configRules)
		}

		source := &stubConformancePackSource{packs: packs}
		output := &captureRulePackOutput{}

		cmd := &ProcessRulePacksCommand{
			PackSource: source,
			PackOutput: output,
		}

		err := cmd.Execute(configRules, nil) // no excluded packs
		if err != nil {
			t.Fatalf("ProcessRulePacksCommand.Execute failed: %v", err)
		}

		// Verify packs map: each value should be sorted.
		for packName, ruleNames := range output.Packs {
			if !sort.StringsAreSorted(ruleNames) {
				t.Fatalf("pack %q has unsorted rule names: %v", packName, ruleNames)
			}
			// Every rule name in the output should be a valid TfRuleName from our config rules.
			for _, rn := range ruleNames {
				found := false
				for _, cr := range configRules {
					if cr.TfRuleName() == rn {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("pack %q contains unknown rule name %q", packName, rn)
				}
			}
		}

		// Verify pack names list matches the packs map keys.
		if len(output.PackNames) != len(output.Packs) {
			t.Fatalf("pack names count %d != packs map count %d", len(output.PackNames), len(output.Packs))
		}
		for _, name := range output.PackNames {
			if _, ok := output.Packs[name]; !ok {
				t.Fatalf("pack name %q in list but not in packs map", name)
			}
		}
	})
}

// genConformancePackDataCompat builds a RawConformancePackData with resources that reference config rules.
func genConformancePackDataCompat(t *rapid.T, configRules []domain.ConfigRule) domain.RawConformancePackData {
	packName := rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "packName")
	numResources := rapid.IntRange(1, 5).Draw(t, "numResources")
	resources := make(map[string]interface{})

	for i := 0; i < numResources; i++ {
		resName := rapid.StringMatching(`[A-Z][a-zA-Z0-9]{2,20}`).Draw(t, "resourceName")
		if len(configRules) > 0 {
			ruleIdx := rapid.IntRange(0, len(configRules)-1).Draw(t, "ruleIdx")
			resources[resName] = map[string]interface{}{
				"Properties": map[string]interface{}{
					"Source": map[string]interface{}{
						"Owner":            "AWS",
						"SourceIdentifier": configRules[ruleIdx].RuleIdentifier,
					},
				},
			}
		}
	}

	return domain.RawConformancePackData{
		Name: packName,
		Content: map[string]interface{}{
			"Resources": resources,
		},
	}
}

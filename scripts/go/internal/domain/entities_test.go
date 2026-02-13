package domain

import (
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// --- Rapid generators ---

var validParamTypes = []string{"int", "String", "CSV", "string", "StringMap", "double", "boolean"}

func genParameterData(t *rapid.T) ParameterData {
	paramType := rapid.SampledFrom(validParamTypes).Draw(t, "paramType")
	hasDefault := rapid.Bool().Draw(t, "hasDefault")
	def := ""
	if hasDefault {
		switch paramType {
		case "int", "double":
			def = rapid.StringMatching(`[1-9][0-9]{0,4}`).Draw(t, "numDefault")
		case "boolean":
			def = rapid.SampledFrom([]string{"true", "false"}).Draw(t, "boolDefault")
		default:
			def = rapid.StringMatching(`[a-zA-Z0-9_-]{1,20}`).Draw(t, "strDefault")
		}
	}
	return ParameterData{
		Name:        rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9]{0,19}`).Draw(t, "paramName"),
		Type:        paramType,
		Default:     def,
		Optional:    rapid.Bool().Draw(t, "optional"),
		Description: rapid.StringMatching(`[a-zA-Z0-9 .]{0,50}`).Draw(t, "paramDesc"),
	}
}

func genRawConfigRuleData(t *rapid.T) RawConfigRuleData {
	numParams := rapid.IntRange(0, 5).Draw(t, "numParams")
	params := make([]ParameterData, numParams)
	for i := range params {
		params[i] = genParameterData(t)
	}
	numResTypes := rapid.IntRange(0, 3).Draw(t, "numResTypes")
	resTypes := make([]string, numResTypes)
	for i := range resTypes {
		resTypes[i] = rapid.StringMatching(`AWS::[A-Z][a-z]+::[A-Z][a-z]+`).Draw(t, "resType")
	}
	return RawConfigRuleData{
		Name:          rapid.StringMatching(`[a-z][a-z0-9-]{0,29}`).Draw(t, "name"),
		Identifier:    rapid.StringMatching(`[A-Z][A-Z0-9_]{0,29}`).Draw(t, "identifier"),
		Description:   rapid.StringMatching(`[a-zA-Z0-9 .,;:!?'-]{1,100}`).Draw(t, "description"),
		Parameters:    params,
		ResourceTypes: resTypes,
		Severity:      rapid.SampledFrom([]string{"Low", "Medium", "High", "Critical"}).Draw(t, "severity"),
	}
}

// Feature: scripts-lib-hexagonal-refactor, Property 1: ConfigRule round-trip serialization
// Validates: Requirements 11.2
func TestProperty1_ConfigRuleRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genRawConfigRuleData(t)
		rule := NewConfigRule(raw)
		roundTripped := NewConfigRule(rule.ToRawData())

		if rule.RuleName != roundTripped.RuleName {
			t.Fatalf("RuleName mismatch: %q vs %q", rule.RuleName, roundTripped.RuleName)
		}
		if rule.RuleIdentifier != roundTripped.RuleIdentifier {
			t.Fatalf("RuleIdentifier mismatch: %q vs %q", rule.RuleIdentifier, roundTripped.RuleIdentifier)
		}
		if rule.TfVariableDescription != roundTripped.TfVariableDescription {
			t.Fatalf("TfVariableDescription mismatch")
		}
		if rule.RuleSeverity() != roundTripped.RuleSeverity() {
			t.Fatalf("RuleSeverity mismatch: %q vs %q", rule.RuleSeverity(), roundTripped.RuleSeverity())
		}
		if len(rule.ParametersData) != len(roundTripped.ParametersData) {
			t.Fatalf("ParametersData length mismatch: %d vs %d", len(rule.ParametersData), len(roundTripped.ParametersData))
		}
		for i := range rule.ParametersData {
			if rule.ParametersData[i] != roundTripped.ParametersData[i] {
				t.Fatalf("ParametersData[%d] mismatch", i)
			}
		}
		if len(rule.ResourceTypes) != len(roundTripped.ResourceTypes) {
			t.Fatalf("ResourceTypes length mismatch: %d vs %d", len(rule.ResourceTypes), len(roundTripped.ResourceTypes))
		}
		for i := range rule.ResourceTypes {
			if rule.ResourceTypes[i] != roundTripped.ResourceTypes[i] {
				t.Fatalf("ResourceTypes[%d] mismatch", i)
			}
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 3: Description truncation length invariant
// Validates: Requirements 1.5
func TestProperty3_DescriptionTruncationLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		desc := rapid.StringMatching(`[a-zA-Z0-9 .,;:!?'-]{1,500}`).Draw(t, "description")
		maxLen := rapid.IntRange(4, 300).Draw(t, "maxLength")

		rule := ConfigRule{TfVariableDescription: desc}
		result := rule.LocalsDescription(maxLen)

		if len(result) > maxLen {
			t.Fatalf("LocalsDescription(%d) produced length %d (> %d): %q", maxLen, len(result), maxLen, result)
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 4: Whitespace normalization idempotence
// Validates: Requirements 1.5
func TestProperty4_WhitespaceNormalizationIdempotence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.String().Draw(t, "input")

		rule := ConfigRule{}
		once := rule.ReplaceMultipleWhitespaceWithSingle(input)
		twice := rule.ReplaceMultipleWhitespaceWithSingle(once)

		if once != twice {
			t.Fatalf("Not idempotent:\n  once:  %q\n  twice: %q", once, twice)
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 5: Terraform name derivation determinism
// Validates: Requirements 1.6
func TestProperty5_TfNameDerivationDeterminism(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genRawConfigRuleData(t)
		rule1 := NewConfigRule(raw)
		rule2 := NewConfigRule(raw)

		if rule1.TfRuleName() != rule2.TfRuleName() {
			t.Fatalf("TfRuleName not deterministic: %q vs %q", rule1.TfRuleName(), rule2.TfRuleName())
		}
		if rule1.TfVariableName() != rule2.TfVariableName() {
			t.Fatalf("TfVariableName not deterministic: %q vs %q", rule1.TfVariableName(), rule2.TfVariableName())
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 6: HCL variable type generation structural validity
// Validates: Requirements 1.8
func TestProperty6_HCLVariableTypeStructuralValidity(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		numParams := rapid.IntRange(1, 5).Draw(t, "numParams")
		params := make([]ParameterData, numParams)
		for i := range params {
			params[i] = genParameterData(t)
		}
		rule := ConfigRule{ParametersData: params}
		result := rule.TfVariableType()

		if !strings.HasPrefix(result, "object({\n") {
			t.Fatalf("TfVariableType does not start with 'object({\\n': %q", result)
		}
		if !strings.HasSuffix(result, "\n})") {
			t.Fatalf("TfVariableType does not end with '\\n})': %q", result)
		}
	})
}

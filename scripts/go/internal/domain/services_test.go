package domain

import (
	"testing"

	"pgregory.net/rapid"
)

var severityLevels = []string{"Low", "Medium", "High", "Critical"}

// Feature: scripts-lib-hexagonal-refactor, Property 7: Severity resolution precedence
// Validates: Requirements 6.1, 6.2, 6.3, 6.4
func TestProperty7_SeverityResolutionPrecedence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a config rule with a known default severity.
		defaultSeverity := rapid.SampledFrom(severityLevels).Draw(t, "defaultSeverity")
		ruleName := rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "ruleName")

		rule := ConfigRule{
			RuleName:       ruleName,
			RuleIdentifier: "SOME_IDENTIFIER",
			ruleSeverity:   defaultSeverity,
		}

		// Decide whether an override and/or control matches this rule.
		hasOverride := rapid.Bool().Draw(t, "hasOverride")
		hasControl := rapid.Bool().Draw(t, "hasControl")

		overrideSeverity := rapid.SampledFrom(severityLevels).Draw(t, "overrideSeverity")
		controlSeverity := rapid.SampledFrom(severityLevels).Draw(t, "controlSeverity")

		var overrides []SeverityOverride
		if hasOverride {
			overrides = append(overrides, SeverityOverride{
				RuleName: ruleName,
				Severity: overrideSeverity,
			})
		}
		// Add a non-matching override to ensure we don't accidentally match.
		overrides = append(overrides, SeverityOverride{
			RuleName: "unrelated-rule-override",
			Severity: "Critical",
		})

		var controls []SecurityHubControl
		if hasControl {
			controls = append(controls, SecurityHubControl{
				ControlName: "CTL.1",
				Severity:    controlSeverity,
				RuleName:    ruleName,
			})
		}
		// Add a non-matching control.
		controls = append(controls, SecurityHubControl{
			ControlName: "CTL.99",
			Severity:    "Low",
			RuleName:    "unrelated-rule-control",
		})

		resolver := &SeverityResolver{}
		rules := []ConfigRule{rule}
		resolved := resolver.Resolve(rules, overrides, controls)

		// Determine expected severity based on precedence:
		// Security Hub control > Severity override > default
		expected := defaultSeverity
		if hasOverride {
			expected = overrideSeverity
		}
		if hasControl {
			expected = controlSeverity
		}

		actual := resolved[0].RuleSeverity()
		if actual != expected {
			t.Fatalf(
				"Severity mismatch: got %q, want %q (default=%q, hasOverride=%v overrideSev=%q, hasControl=%v controlSev=%q)",
				actual, expected, defaultSeverity, hasOverride, overrideSeverity, hasControl, controlSeverity,
			)
		}
	})
}

package domain

// SeverityResolver applies severity overrides and Security Hub control
// severities to a list of ConfigRules.
// Resolution order: overrides are applied first, then Security Hub controls.
// This means Security Hub takes precedence when both match.
type SeverityResolver struct{}

// Resolve applies severity overrides first, then Security Hub control severities.
// For each rule:
//  1. If a SeverityOverride matches by TfRuleName, update severity to the override value.
//  2. If a SecurityHubControl matches by TfRuleName, update severity to the control value.
//
// Because controls are applied after overrides, Security Hub takes precedence.
func (sr *SeverityResolver) Resolve(
	rules []ConfigRule,
	overrides []SeverityOverride,
	controls []SecurityHubControl,
) []ConfigRule {
	for i := range rules {
		for _, override := range overrides {
			if override.RuleName == rules[i].TfRuleName() {
				rules[i].SetSeverityLevel(override.Severity)
				break
			}
		}
		for _, control := range controls {
			if control.RuleName == rules[i].TfRuleName() {
				rules[i].SetSeverityLevel(control.Severity)
				break
			}
		}
	}
	return rules
}

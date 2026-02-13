package queries

import (
	"testing"

	"scripts/go/internal/domain"

	"pgregory.net/rapid"
)

// --- In-memory port implementations for testing ---

type stubConfigRuleDataSource struct {
	data []domain.RawConfigRuleData
}

func (s *stubConfigRuleDataSource) Load() ([]domain.RawConfigRuleData, error) {
	return s.data, nil
}

type stubSecurityHubDataSource struct {
	data []domain.RawSecurityHubControlData
}

func (s *stubSecurityHubDataSource) Load() ([]domain.RawSecurityHubControlData, error) {
	return s.data, nil
}

type stubSeverityOverrideSource struct {
	data []domain.SeverityOverride
}

func (s *stubSeverityOverrideSource) Load() ([]domain.SeverityOverride, error) {
	return s.data, nil
}

// --- Property test ---

var validParamTypes = []string{"int", "String", "CSV", "string", "StringMap", "double", "boolean"}
var validSeverities = []string{"Low", "Medium", "High", "Critical"}

// Feature: scripts-lib-hexagonal-refactor, Property 12: Query handlers preserve item count
// Validates: Requirements 5.1, 5.2, 5.3
func TestProperty12_QueryHandlersPreserveItemCount(t *testing.T) {
	t.Run("LoadConfigRulesQuery", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			n := rapid.IntRange(0, 50).Draw(t, "n")
			rawData := make([]domain.RawConfigRuleData, n)
			for i := 0; i < n; i++ {
				rawData[i] = domain.RawConfigRuleData{
					Name:       rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "name"),
					Identifier: rapid.StringMatching(`[A-Z][A-Z0-9_]{2,20}`).Draw(t, "identifier"),
					Severity:   rapid.SampledFrom(validSeverities).Draw(t, "severity"),
				}
			}

			query := &LoadConfigRulesQuery{
				Source: &stubConfigRuleDataSource{data: rawData},
			}
			rules, err := query.Execute()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(rules) != n {
				t.Fatalf("expected %d rules, got %d", n, len(rules))
			}
		})
	})

	t.Run("LoadSeverityOverridesQuery", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			n := rapid.IntRange(0, 50).Draw(t, "n")
			overrides := make([]domain.SeverityOverride, n)
			for i := 0; i < n; i++ {
				overrides[i] = domain.SeverityOverride{
					RuleName: rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "ruleName"),
					Severity: rapid.SampledFrom(validSeverities).Draw(t, "severity"),
				}
			}

			query := &LoadSeverityOverridesQuery{
				Source: &stubSeverityOverrideSource{data: overrides},
			}
			result, err := query.Execute()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(result) != n {
				t.Fatalf("expected %d overrides, got %d", n, len(result))
			}
		})
	})

	t.Run("LoadSecurityHubControlsQuery", func(t *testing.T) {
		rapid.Check(t, func(t *rapid.T) {
			n := rapid.IntRange(0, 50).Draw(t, "n")
			rawData := make([]domain.RawSecurityHubControlData, n)
			for i := 0; i < n; i++ {
				rawData[i] = domain.RawSecurityHubControlData{
					Severity: rapid.SampledFrom(validSeverities).Draw(t, "severity"),
					Rule:     rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "rule"),
					Control:  rapid.StringMatching(`[A-Z]{2,5}\.[0-9]{1,3}`).Draw(t, "control"),
				}
			}

			query := &LoadSecurityHubControlsQuery{
				Source: &stubSecurityHubDataSource{data: rawData},
			}
			controls, err := query.Execute()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(controls) != n {
				t.Fatalf("expected %d controls, got %d", n, len(controls))
			}
		})
	})
}

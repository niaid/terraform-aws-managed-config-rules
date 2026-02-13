package queries

import (
	"scripts/go/internal/domain"
	"scripts/go/internal/ports"
)

// LoadConfigRulesQuery retrieves raw config rule data and returns domain entities.
type LoadConfigRulesQuery struct {
	Source ports.ConfigRuleDataSource
}

// Execute loads raw data from the source and converts to ConfigRule entities.
func (q *LoadConfigRulesQuery) Execute() ([]domain.ConfigRule, error) {
	rawData, err := q.Source.Load()
	if err != nil {
		return nil, err
	}
	rules := make([]domain.ConfigRule, len(rawData))
	for i, d := range rawData {
		rules[i] = domain.NewConfigRule(d)
	}
	return rules, nil
}

// LoadSeverityOverridesQuery retrieves severity overrides from the source.
type LoadSeverityOverridesQuery struct {
	Source ports.SeverityOverrideSource
}

// Execute loads severity overrides directly from the source.
func (q *LoadSeverityOverridesQuery) Execute() ([]domain.SeverityOverride, error) {
	return q.Source.Load()
}

// LoadSecurityHubControlsQuery retrieves raw Security Hub data and returns domain objects.
type LoadSecurityHubControlsQuery struct {
	Source ports.SecurityHubDataSource
}

// Execute loads raw data from the source and converts to SecurityHubControl objects.
func (q *LoadSecurityHubControlsQuery) Execute() ([]domain.SecurityHubControl, error) {
	rawData, err := q.Source.Load()
	if err != nil {
		return nil, err
	}
	controls := make([]domain.SecurityHubControl, len(rawData))
	for i, d := range rawData {
		controls[i] = domain.NewSecurityHubControl(d)
	}
	return controls, nil
}

// LoadConformancePacksQuery retrieves raw conformance pack data from the source.
type LoadConformancePacksQuery struct {
	Source ports.ConformancePackSource
}

// Execute loads raw conformance pack data directly from the source.
func (q *LoadConformancePacksQuery) Execute() ([]domain.RawConformancePackData, error) {
	return q.Source.Load()
}

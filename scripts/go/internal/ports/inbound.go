package ports

import "scripts/go/internal/domain"

// ConfigRuleDataSource loads raw Config Rule data from an external source.
type ConfigRuleDataSource interface {
	Load() ([]domain.RawConfigRuleData, error)
}

// SecurityHubDataSource loads raw Security Hub control data from an external source.
type SecurityHubDataSource interface {
	Load() ([]domain.RawSecurityHubControlData, error)
}

// SeverityOverrideSource loads severity override data from an external source.
type SeverityOverrideSource interface {
	Load() ([]domain.SeverityOverride, error)
}

// ConformancePackSource loads raw conformance pack data from an external source.
type ConformancePackSource interface {
	Load() ([]domain.RawConformancePackData, error)
}

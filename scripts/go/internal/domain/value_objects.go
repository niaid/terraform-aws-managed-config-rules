package domain

// SeverityOverride is a value object representing a manual severity level override.
type SeverityOverride struct {
	RuleName string
	Severity string
}

// RawSecurityHubControlData is the intermediate structure from JSON.
type RawSecurityHubControlData struct {
	Severity string `json:"severity"`
	Rule     string `json:"rule"`
	Control  string `json:"control"`
}

// SecurityHubControl is a value object representing an AWS Security Hub control.
type SecurityHubControl struct {
	ControlName string
	Severity    string
	RuleName    string
}

// NewSecurityHubControl constructs a SecurityHubControl from raw JSON data.
func NewSecurityHubControl(data RawSecurityHubControlData) SecurityHubControl {
	return SecurityHubControl{
		ControlName: data.Control,
		Severity:    data.Severity,
		RuleName:    data.Rule,
	}
}

// ToRawData serializes the SecurityHubControl back to RawSecurityHubControlData.
func (s *SecurityHubControl) ToRawData() RawSecurityHubControlData {
	return RawSecurityHubControlData{
		Severity: s.Severity,
		Rule:     s.RuleName,
		Control:  s.ControlName,
	}
}

// RawConformancePackData is the intermediate structure for conformance pack YAML.
type RawConformancePackData struct {
	Name    string
	Content map[string]interface{}
}

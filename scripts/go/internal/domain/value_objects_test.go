package domain

import (
	"testing"

	"pgregory.net/rapid"
)

func genRawSecurityHubControlData(t *rapid.T) RawSecurityHubControlData {
	return RawSecurityHubControlData{
		Severity: rapid.SampledFrom([]string{"LOW", "MEDIUM", "HIGH", "CRITICAL"}).Draw(t, "severity"),
		Rule:     rapid.StringMatching(`[a-z][a-z0-9-]{0,29}`).Draw(t, "rule"),
		Control:  rapid.StringMatching(`[A-Z]{2,5}\.[0-9]{1,3}`).Draw(t, "control"),
	}
}

// Feature: scripts-lib-hexagonal-refactor, Property 2: SecurityHubControl round-trip serialization
// Validates: Requirements 11.4
func TestProperty2_SecurityHubControlRoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		raw := genRawSecurityHubControlData(t)
		control := NewSecurityHubControl(raw)
		roundTripped := NewSecurityHubControl(control.ToRawData())

		if control.ControlName != roundTripped.ControlName {
			t.Fatalf("ControlName mismatch: %q vs %q", control.ControlName, roundTripped.ControlName)
		}
		if control.Severity != roundTripped.Severity {
			t.Fatalf("Severity mismatch: %q vs %q", control.Severity, roundTripped.Severity)
		}
		if control.RuleName != roundTripped.RuleName {
			t.Fatalf("RuleName mismatch: %q vs %q", control.RuleName, roundTripped.RuleName)
		}
	})
}

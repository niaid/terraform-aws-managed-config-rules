package commands

import (
	"sort"
	"testing"

	"pgregory.net/rapid"

	"scripts/go/internal/domain"
)

// --- In-memory port stubs for testing ---

// stubConformancePackSource returns pre-loaded pack data.
type stubConformancePackSource struct {
	packs []domain.RawConformancePackData
}

func (s *stubConformancePackSource) Load() ([]domain.RawConformancePackData, error) {
	return s.packs, nil
}

// captureRulePackOutput captures WritePacks/WritePacksList calls.
type captureRulePackOutput struct {
	Packs     map[string][]string
	PackNames []string
}

func (c *captureRulePackOutput) WritePacks(packsData map[string][]string) error {
	c.Packs = packsData
	return nil
}

func (c *captureRulePackOutput) WritePacksList(packs []string) error {
	c.PackNames = packs
	return nil
}

// --- Rapid generators ---

var validParamTypes = []string{"int", "String", "CSV", "string", "StringMap", "double", "boolean"}

func genParameterData(t *rapid.T) domain.ParameterData {
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
	return domain.ParameterData{
		Name:     rapid.StringMatching(`[a-zA-Z][a-zA-Z0-9]{0,19}`).Draw(t, "paramName"),
		Type:     paramType,
		Default:  def,
		Optional: rapid.Bool().Draw(t, "optional"),
	}
}

func genConfigRule(t *rapid.T) domain.ConfigRule {
	numParams := rapid.IntRange(0, 3).Draw(t, "numParams")
	params := make([]domain.ParameterData, numParams)
	for i := range params {
		params[i] = genParameterData(t)
	}
	numResTypes := rapid.IntRange(0, 2).Draw(t, "numResTypes")
	resTypes := make([]string, numResTypes)
	for i := range resTypes {
		resTypes[i] = rapid.StringMatching(`AWS::[A-Z][a-z]+::[A-Z][a-z]+`).Draw(t, "resType")
	}
	raw := domain.RawConfigRuleData{
		Name:          rapid.StringMatching(`[a-z][a-z0-9-]{0,29}`).Draw(t, "name"),
		Identifier:    rapid.StringMatching(`[A-Z][A-Z0-9_]{0,29}`).Draw(t, "identifier"),
		Description:   rapid.StringMatching(`[a-zA-Z0-9 .]{1,50}`).Draw(t, "description"),
		Parameters:    params,
		ResourceTypes: resTypes,
		Severity:      rapid.SampledFrom([]string{"Low", "Medium", "High", "Critical"}).Draw(t, "severity"),
	}
	return domain.NewConfigRule(raw)
}

// genConformancePackData builds a RawConformancePackData whose Resources reference the given config rules.
func genConformancePackData(t *rapid.T, configRules []domain.ConfigRule) domain.RawConformancePackData {
	packName := rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "packName")
	numResources := rapid.IntRange(1, 5).Draw(t, "numResources")
	resources := make(map[string]any)

	for i := 0; i < numResources; i++ {
		resName := rapid.StringMatching(`[A-Z][a-zA-Z0-9]{2,20}`).Draw(t, "resourceName")
		if len(configRules) > 0 {
			ruleIdx := rapid.IntRange(0, len(configRules)-1).Draw(t, "ruleIdx")
			resources[resName] = map[string]any{
				"Properties": map[string]any{
					"Source": map[string]any{
						"Owner":            "AWS",
						"SourceIdentifier": configRules[ruleIdx].RuleIdentifier,
					},
				},
			}
		}
	}

	return domain.RawConformancePackData{
		Name: packName,
		Content: map[string]any{
			"Resources": resources,
		},
	}
}

// Feature: scripts-lib-hexagonal-refactor, Property 15: Pack processor command produces valid output
// Validates: Requirements 4.3
func TestProperty15_PackProcessorCommandProducesValidOutput(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate config rules.
		numRules := rapid.IntRange(1, 5).Draw(t, "numRules")
		configRules := make([]domain.ConfigRule, numRules)
		for i := range configRules {
			configRules[i] = genConfigRule(t)
		}

		// Generate at least one non-excluded pack.
		numPacks := rapid.IntRange(1, 3).Draw(t, "numPacks")
		packs := make([]domain.RawConformancePackData, numPacks)
		for i := range packs {
			packs[i] = genConformancePackData(t, configRules)
		}

		source := &stubConformancePackSource{packs: packs}
		output := &captureRulePackOutput{}

		cmd := &ProcessRulePacksCommand{
			PackSource: source,
			PackOutput: output,
		}

		err := cmd.Execute(configRules, nil) // no excluded packs
		if err != nil {
			t.Fatalf("Execute failed: %v", err)
		}

		// The packs map should be non-empty (we generated valid packs with resources).
		if len(output.Packs) == 0 {
			t.Fatalf("expected non-empty packs map, got empty")
		}

		// Each value in the packs map should be a sorted slice of strings.
		for packName, ruleNames := range output.Packs {
			if !sort.StringsAreSorted(ruleNames) {
				t.Fatalf("pack %q has unsorted rule names: %v", packName, ruleNames)
			}
		}
	})
}

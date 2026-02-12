package domain

import (
	"errors"
	"sort"
	"testing"

	"pgregory.net/rapid"
)

// genConformancePackResources generates a CloudFormation-style resources map
// with random Source/SourceIdentifier entries that reference the given config rules.
func genConformancePackResources(t *rapid.T, configRules []ConfigRule) map[string]interface{} {
	numResources := rapid.IntRange(1, 10).Draw(t, "numResources")
	resources := make(map[string]interface{})

	for i := 0; i < numResources; i++ {
		resName := rapid.StringMatching(`[A-Z][a-zA-Z0-9]{2,20}`).Draw(t, "resourceName")
		hasSource := rapid.Bool().Draw(t, "hasSource")

		if hasSource && len(configRules) > 0 {
			ruleIdx := rapid.IntRange(0, len(configRules)-1).Draw(t, "ruleIdx")
			resources[resName] = map[string]interface{}{
				"Properties": map[string]interface{}{
					"Source": map[string]interface{}{
						"Owner":            "AWS",
						"SourceIdentifier": configRules[ruleIdx].RuleIdentifier,
					},
				},
			}
		} else {
			// Resource without Source property
			resources[resName] = map[string]interface{}{
				"Properties": map[string]interface{}{
					"ConfigRuleName": resName,
				},
			}
		}
	}
	return resources
}

// Feature: scripts-lib-hexagonal-refactor, Property 10: Pack processor returns sorted rule names
// Validates: Requirements 8.1
func TestProperty10_PackProcessorReturnsSortedRuleNames(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate some config rules.
		numRules := rapid.IntRange(1, 5).Draw(t, "numRules")
		configRules := make([]ConfigRule, numRules)
		for i := range configRules {
			configRules[i] = genConfigRuleForRenderer(t)
		}

		resources := genConformancePackResources(t, configRules)
		packName := rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "packName")

		processor := &PackProcessor{}
		pack, err := processor.Process(packName, resources, configRules, nil)
		if err != nil {
			t.Fatalf("Process failed: %v", err)
		}

		if !sort.StringsAreSorted(pack.RuleNames) {
			t.Fatalf("RuleNames not sorted: %v", pack.RuleNames)
		}
	})
}

// Feature: scripts-lib-hexagonal-refactor, Property 11: Pack processor rejects excluded packs
// Validates: Requirements 8.3
func TestProperty11_PackProcessorRejectsExcludedPacks(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		packName := rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "packName")

		// Build an excluded list that always contains the pack name.
		numExtra := rapid.IntRange(0, 3).Draw(t, "numExtra")
		excluded := []string{packName}
		for i := 0; i < numExtra; i++ {
			excluded = append(excluded, rapid.StringMatching(`[a-z][a-z0-9-]{2,20}`).Draw(t, "extraExcluded"))
		}

		processor := &PackProcessor{}
		_, err := processor.Process(packName, nil, nil, excluded)

		if !errors.Is(err, ErrInvalidConformancePack) {
			t.Fatalf("expected ErrInvalidConformancePack, got: %v", err)
		}
	})
}

package domain

import (
	"errors"
	"sort"
)

// ErrInvalidConformancePack is returned when a conformance pack name is in the excluded list.
var ErrInvalidConformancePack = errors.New("invalid conformance pack")

// ErrNoSourceProperty is returned when a conformance pack resource has no Source property.
var ErrNoSourceProperty = errors.New("no source property")

// PackProcessor processes conformance pack data to extract rule-to-pack mappings.
type PackProcessor struct{}

// Process takes a pack name, its CloudFormation resources map, a list of ConfigRule entities,
// and an excluded packs list. It returns a ConformancePack with sorted rule names.
func (pp *PackProcessor) Process(
	packName string,
	resources map[string]interface{},
	configRules []ConfigRule,
	excludedPacks []string,
) (ConformancePack, error) {
	for _, excluded := range excludedPacks {
		if packName == excluded {
			return ConformancePack{}, ErrInvalidConformancePack
		}
	}

	var ruleNames []string
	for _, attr := range resources {
		attrMap, ok := attr.(map[string]interface{})
		if !ok {
			continue
		}
		props, ok := attrMap["Properties"].(map[string]interface{})
		if !ok {
			continue
		}
		source, ok := props["Source"].(map[string]interface{})
		if !ok {
			// Skip resources with no Source property (Requirement 8.2)
			continue
		}
		identifier, ok := source["SourceIdentifier"].(string)
		if !ok {
			continue
		}
		for _, cr := range configRules {
			if cr.RuleIdentifier == identifier {
				found := false
				for _, rn := range ruleNames {
					if rn == cr.TfRuleName() {
						found = true
						break
					}
				}
				if !found {
					ruleNames = append(ruleNames, cr.TfRuleName())
				}
				break
			}
		}
	}

	sort.Strings(ruleNames)
	return ConformancePack{Name: packName, RuleNames: ruleNames}, nil
}

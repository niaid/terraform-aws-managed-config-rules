package commands

import (
	"scripts/go/internal/domain"
	"scripts/go/internal/ports"
)

// GenerateHCLCommand writes HCL locals and variable definitions through the output port,
// then formats the result via the formatter port.
type GenerateHCLCommand struct {
	HCLOutput        ports.HCLOutput
	HCLFormatter     ports.HCLFormatter
	LocalsTemplate   string
	VariableTemplate string
}

// Execute renders HCL for the given rules and writes + formats the output.
func (c *GenerateHCLCommand) Execute(rules []domain.ConfigRule) error {
	renderer := &domain.HCLRenderer{}

	localsContent, err := renderer.RenderLocals(rules, c.LocalsTemplate)
	if err != nil {
		return err
	}
	if err := c.HCLOutput.WriteLocals(localsContent); err != nil {
		return err
	}

	var rulesWithParams []domain.ConfigRule
	for _, r := range rules {
		if len(r.ParametersData) > 0 {
			rulesWithParams = append(rulesWithParams, r)
		}
	}

	variablesContent, err := renderer.RenderVariables(rulesWithParams, c.VariableTemplate)
	if err != nil {
		return err
	}
	if err := c.HCLOutput.WriteVariables(variablesContent); err != nil {
		return err
	}

	return c.HCLFormatter.Format(".")
}

// ProcessRulePacksCommand loads conformance packs and processes them against config rules,
// writing the results through the pack output port.
type ProcessRulePacksCommand struct {
	PackSource ports.ConformancePackSource
	PackOutput ports.RulePackOutput
}

// Execute loads packs, processes each one, and writes the results.
func (c *ProcessRulePacksCommand) Execute(
	configRules []domain.ConfigRule,
	excludedPacks []string,
) error {
	packsData, err := c.PackSource.Load()
	if err != nil {
		return err
	}

	processor := &domain.PackProcessor{}
	resultPacks := make(map[string][]string)
	var packNames []string

	for _, packData := range packsData {
		resources, ok := packData.Content["Resources"].(map[string]interface{})
		if !ok {
			continue
		}
		pack, err := processor.Process(packData.Name, resources, configRules, excludedPacks)
		if err != nil {
			continue // skip invalid/excluded packs
		}
		resultPacks[pack.Name] = pack.RuleNames
		packNames = append(packNames, pack.Name)
	}

	if err := c.PackOutput.WritePacks(resultPacks); err != nil {
		return err
	}
	return c.PackOutput.WritePacksList(packNames)
}

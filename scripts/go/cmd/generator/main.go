package main

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"scripts/go/internal/adapters"
	"scripts/go/internal/commands"
	"scripts/go/internal/domain"
	"scripts/go/internal/queries"
)

const (
	rootPage               = "https://docs.aws.amazon.com/config/latest/developerguide/"
	managedRulesPage       = rootPage + "managed-rules-by-aws-config.html"
	securityHubRootPage    = "https://docs.aws.amazon.com/securityhub/latest/userguide"
	securityHubControlsRef = "securityhub-controls-reference.html"

	awsConfigRulesRepo = "https://github.com/awslabs/aws-config-rules.git"
	rulesDir           = "aws-config-rules"
)

func main() {
	log.SetFlags(log.Ldate | log.Ltime)

	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	// Resolve paths relative to the project root (two levels up from cmd/generator/).
	projectRoot := resolveProjectRoot()

	switch os.Args[1] {
	case "update-config-rules":
		if err := updateConfigRules(projectRoot); err != nil {
			log.Fatalf("update-config-rules failed: %v", err)
		}
	case "update-rule-packs":
		if err := updateRulePacks(projectRoot); err != nil {
			log.Fatalf("update-rule-packs failed: %v", err)
		}
	default:
		fmt.Fprintf(os.Stderr, "Invalid command: %s\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "\nUsage: go run ./cmd/generator <command>")
	fmt.Fprintln(os.Stderr, "Valid commands: update-config-rules, update-rule-packs")
}

// resolveProjectRoot returns the absolute path to the repository root.
// It assumes the binary is invoked from the repository root directory.
func resolveProjectRoot() string {
	root, err := os.Getwd()
	if err != nil {
		log.Fatalf("cannot determine working directory: %v", err)
	}
	return root
}

func updateConfigRules(projectRoot string) error {
	scriptsDir := filepath.Join(projectRoot, "scripts", "go")
	sourceFile := filepath.Join(scriptsDir, "config_rule_data.json")
	severityOverridesFile := filepath.Join(projectRoot, "etc", "severity_overrides.yaml")
	securityHubControlsFile := filepath.Join(scriptsDir, "security_hub_controls.json")
	localsFile := filepath.Join(projectRoot, "managed_rules_locals.tf")
	variablesFile := filepath.Join(projectRoot, "managed_rules_variables.tf")

	// 1. Scrape AWS documentation for Config Rules.
	log.Println("Scraping AWS documentation for Config Rules...")
	httpRuleSource := &adapters.HttpConfigRuleDataSource{
		RootURL:          rootPage,
		ManagedRulesPage: managedRulesPage,
	}
	rawRules, err := httpRuleSource.Load()
	if err != nil {
		return fmt.Errorf("scraping config rules: %w", err)
	}
	if err := writeJSON(sourceFile, rawRules); err != nil {
		return fmt.Errorf("writing config rule data: %w", err)
	}

	// 2. Scrape AWS documentation for Security Hub controls.
	log.Println("Scraping AWS documentation for Security Hub controls...")
	httpHubSource := &adapters.HttpSecurityHubDataSource{
		RootURL:         securityHubRootPage,
		ControlsRefPage: securityHubControlsRef,
	}
	rawControls, err := httpHubSource.Load()
	if err != nil {
		return fmt.Errorf("scraping security hub controls: %w", err)
	}
	if err := writeJSON(securityHubControlsFile, rawControls); err != nil {
		return fmt.Errorf("writing security hub controls: %w", err)
	}

	// 3. Load severity overrides.
	overridesSource := &adapters.YamlFileSeverityOverrideSource{FilePath: severityOverridesFile}
	overridesQuery := &queries.LoadSeverityOverridesQuery{Source: overridesSource}
	overrides, err := overridesQuery.Execute()
	if err != nil {
		return fmt.Errorf("loading severity overrides: %w", err)
	}

	// 4. Load config rules from the persisted JSON.
	rulesSource := &adapters.JsonFileConfigRuleDataSource{FilePath: sourceFile}
	rulesQuery := &queries.LoadConfigRulesQuery{Source: rulesSource}
	rules, err := rulesQuery.Execute()
	if err != nil {
		return fmt.Errorf("loading config rules: %w", err)
	}

	// 5. Load Security Hub controls from the persisted JSON.
	hubSource := &adapters.JsonFileSecurityHubDataSource{FilePath: securityHubControlsFile}
	hubQuery := &queries.LoadSecurityHubControlsQuery{Source: hubSource}
	controls, err := hubQuery.Execute()
	if err != nil {
		return fmt.Errorf("loading security hub controls: %w", err)
	}

	// 6. Resolve severities (overrides first, then Security Hub).
	resolver := &domain.SeverityResolver{}
	rules = resolver.Resolve(rules, overrides, controls)

	// 7. Load templates.
	templatesDir := filepath.Join(projectRoot, "scripts", "go", "templates")
	localsTemplate, err := os.ReadFile(filepath.Join(templatesDir, "locals_block.tmpl"))
	if err != nil {
		return fmt.Errorf("reading locals template: %w", err)
	}
	variableTemplate, err := os.ReadFile(filepath.Join(templatesDir, "variable.tmpl"))
	if err != nil {
		return fmt.Errorf("reading variable template: %w", err)
	}

	// 8. Generate HCL output.
	hclCmd := &commands.GenerateHCLCommand{
		HCLOutput: &adapters.FileHCLOutput{
			LocalsPath:    localsFile,
			VariablesPath: variablesFile,
		},
		HCLFormatter:     &adapters.TerraformFormatterAdapter{WorkingDir: projectRoot},
		LocalsTemplate:   string(localsTemplate),
		VariableTemplate: string(variableTemplate),
	}
	if err := hclCmd.Execute(rules); err != nil {
		return fmt.Errorf("generating HCL: %w", err)
	}

	log.Println("Config rules updated successfully.")
	return nil
}

func updateRulePacks(projectRoot string) error {
	scriptsDir := filepath.Join(projectRoot, "scripts", "go")
	sourceFile := filepath.Join(scriptsDir, "config_rule_data.json")
	packRulesFile := filepath.Join(projectRoot, "files", "pack-rules.yaml")
	packsListFile := filepath.Join(projectRoot, "files", "pack-rules-list.txt")

	excludedPacks := []string{"custom-conformance-pack"}

	// 1. Optionally download conformance packs.
	if os.Getenv("DOWNLOAD_CONFORMANCE_PACKS") != "no" {
		log.Println("Downloading conformance packs...")
		os.RemoveAll(rulesDir)
		cmd := exec.Command("git", "clone", awsConfigRulesRepo)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("cloning conformance packs repo: %w", err)
		}
	}

	// 2. Load config rules.
	rulesSource := &adapters.JsonFileConfigRuleDataSource{FilePath: sourceFile}
	rulesQuery := &queries.LoadConfigRulesQuery{Source: rulesSource}
	rules, err := rulesQuery.Execute()
	if err != nil {
		return fmt.Errorf("loading config rules: %w", err)
	}

	// 3. Process rule packs.
	conformancePackDir := filepath.Join(rulesDir, "aws-config-conformance-packs")
	packSource := &adapters.YamlFileConformancePackSource{
		Directory:   conformancePackDir,
		GlobPattern: "*.yaml",
	}
	packOutput := &adapters.FileRulePackOutput{
		PacksFile: packRulesFile,
		ListFile:  packsListFile,
	}
	packCmd := &commands.ProcessRulePacksCommand{
		PackSource: packSource,
		PackOutput: packOutput,
	}
	if err := packCmd.Execute(rules, excludedPacks); err != nil {
		return fmt.Errorf("processing rule packs: %w", err)
	}

	log.Println("Rule packs updated successfully.")
	return nil
}

func writeJSON(path string, v interface{}) error {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

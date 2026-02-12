package adapters

import (
	"os"
	"path/filepath"
	"scripts/go/internal/domain"
	"testing"
)

func TestJsonFileConfigRuleDataSource_Load(t *testing.T) {
	content := `[
		{
			"name": "access-keys-rotated",
			"identifier": "ACCESS_KEYS_ROTATED",
			"description": "Checks if active IAM access keys are rotated.",
			"parameters": [
				{"name": "maxAccessKeyAge", "type": "int", "default": "90", "optional": false}
			],
			"resource_types": ["AWS::IAM::User"],
			"severity": "Medium"
		}
	]`
	tmpFile := filepath.Join(t.TempDir(), "rules.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	src := &JsonFileConfigRuleDataSource{FilePath: tmpFile}
	rules, err := src.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	if rules[0].Name != "access-keys-rotated" {
		t.Errorf("expected name 'access-keys-rotated', got %q", rules[0].Name)
	}
	if rules[0].Identifier != "ACCESS_KEYS_ROTATED" {
		t.Errorf("expected identifier 'ACCESS_KEYS_ROTATED', got %q", rules[0].Identifier)
	}
	if len(rules[0].Parameters) != 1 {
		t.Errorf("expected 1 parameter, got %d", len(rules[0].Parameters))
	}
}

func TestJsonFileConfigRuleDataSource_Load_FileNotFound(t *testing.T) {
	src := &JsonFileConfigRuleDataSource{FilePath: "/nonexistent/path.json"}
	_, err := src.Load()
	if err == nil {
		t.Fatal("expected error for missing file")
	}
}

func TestJsonFileSecurityHubDataSource_Load(t *testing.T) {
	content := `[
		{"severity": "MEDIUM", "rule": "access-keys-rotated", "control": "IAM.3"}
	]`
	tmpFile := filepath.Join(t.TempDir(), "controls.json")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	src := &JsonFileSecurityHubDataSource{FilePath: tmpFile}
	controls, err := src.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(controls) != 1 {
		t.Fatalf("expected 1 control, got %d", len(controls))
	}
	if controls[0].Severity != "MEDIUM" {
		t.Errorf("expected severity 'MEDIUM', got %q", controls[0].Severity)
	}
	if controls[0].Rule != "access-keys-rotated" {
		t.Errorf("expected rule 'access-keys-rotated', got %q", controls[0].Rule)
	}
}

func TestYamlFileSeverityOverrideSource_Load(t *testing.T) {
	content := `overrides:
  desired-instance-tenancy:
    severity: Low
  ec2-volume-inuse-check:
    severity: Low
`
	tmpFile := filepath.Join(t.TempDir(), "overrides.yaml")
	if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	src := &YamlFileSeverityOverrideSource{FilePath: tmpFile}
	overrides, err := src.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(overrides) != 2 {
		t.Fatalf("expected 2 overrides, got %d", len(overrides))
	}
	// Check that both overrides are present (map iteration order is non-deterministic)
	found := map[string]string{}
	for _, o := range overrides {
		found[o.RuleName] = o.Severity
	}
	if found["desired-instance-tenancy"] != "Low" {
		t.Errorf("expected 'desired-instance-tenancy' -> 'Low', got %q", found["desired-instance-tenancy"])
	}
	if found["ec2-volume-inuse-check"] != "Low" {
		t.Errorf("expected 'ec2-volume-inuse-check' -> 'Low', got %q", found["ec2-volume-inuse-check"])
	}
}

func TestYamlFileConformancePackSource_Load(t *testing.T) {
	dir := t.TempDir()
	packContent := `Resources:
  SomeRule:
    Properties:
      Source:
        Owner: AWS
        SourceIdentifier: ACCESS_KEYS_ROTATED
`
	if err := os.WriteFile(filepath.Join(dir, "test-pack.yaml"), []byte(packContent), 0644); err != nil {
		t.Fatal(err)
	}

	src := &YamlFileConformancePackSource{Directory: dir}
	packs, err := src.Load()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(packs) != 1 {
		t.Fatalf("expected 1 pack, got %d", len(packs))
	}
	if packs[0].Name != "test-pack" {
		t.Errorf("expected name 'test-pack', got %q", packs[0].Name)
	}
	resources, ok := packs[0].Content["Resources"]
	if !ok {
		t.Fatal("expected 'Resources' key in content")
	}
	resMap, ok := resources.(map[string]interface{})
	if !ok {
		t.Fatal("expected Resources to be a map")
	}
	if _, ok := resMap["SomeRule"]; !ok {
		t.Error("expected 'SomeRule' in Resources")
	}
}

func TestFileHCLOutput_WriteLocalsAndVariables(t *testing.T) {
	dir := t.TempDir()
	localsPath := filepath.Join(dir, "locals.tf")
	varsPath := filepath.Join(dir, "variables.tf")

	out := &FileHCLOutput{LocalsPath: localsPath, VariablesPath: varsPath}

	if err := out.WriteLocals("locals { }"); err != nil {
		t.Fatalf("WriteLocals error: %v", err)
	}
	if err := out.WriteVariables("variable \"x\" { }"); err != nil {
		t.Fatalf("WriteVariables error: %v", err)
	}

	localsData, _ := os.ReadFile(localsPath)
	if string(localsData) != "locals { }" {
		t.Errorf("unexpected locals content: %q", string(localsData))
	}
	varsData, _ := os.ReadFile(varsPath)
	if string(varsData) != "variable \"x\" { }" {
		t.Errorf("unexpected variables content: %q", string(varsData))
	}
}

func TestFileRulePackOutput_WritePacksAndList(t *testing.T) {
	dir := t.TempDir()
	packsFile := filepath.Join(dir, "packs.yaml")
	listFile := filepath.Join(dir, "packs-list.txt")

	out := &FileRulePackOutput{PacksFile: packsFile, ListFile: listFile}

	packsData := map[string][]string{
		"pack-a": {"rule-1", "rule-2"},
	}
	if err := out.WritePacks(packsData); err != nil {
		t.Fatalf("WritePacks error: %v", err)
	}
	if err := out.WritePacksList([]string{"pack-a", "pack-b"}); err != nil {
		t.Fatalf("WritePacksList error: %v", err)
	}

	packsBytes, _ := os.ReadFile(packsFile)
	if len(packsBytes) == 0 {
		t.Error("expected non-empty packs file")
	}

	listBytes, _ := os.ReadFile(listFile)
	if string(listBytes) != "pack-a\npack-b" {
		t.Errorf("unexpected list content: %q", string(listBytes))
	}
}

// Verify adapters satisfy port interfaces at compile time.
var _ interface {
	Load() ([]domain.RawConfigRuleData, error)
} = (*JsonFileConfigRuleDataSource)(nil)
var _ interface {
	Load() ([]domain.RawSecurityHubControlData, error)
} = (*JsonFileSecurityHubDataSource)(nil)
var _ interface {
	Load() ([]domain.SeverityOverride, error)
} = (*YamlFileSeverityOverrideSource)(nil)
var _ interface {
	Load() ([]domain.RawConformancePackData, error)
} = (*YamlFileConformancePackSource)(nil)

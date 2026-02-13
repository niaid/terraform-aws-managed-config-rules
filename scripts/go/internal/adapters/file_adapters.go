package adapters

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"scripts/go/internal/domain"

	"gopkg.in/yaml.v3"
)

// JsonFileConfigRuleDataSource loads Config Rule data from a JSON file.
type JsonFileConfigRuleDataSource struct {
	FilePath string
}

func (s *JsonFileConfigRuleDataSource) Load() ([]domain.RawConfigRuleData, error) {
	data, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}
	var rules []domain.RawConfigRuleData
	err = json.Unmarshal(data, &rules)
	return rules, err
}

// JsonFileSecurityHubDataSource loads Security Hub control data from a JSON file.
type JsonFileSecurityHubDataSource struct {
	FilePath string
}

func (s *JsonFileSecurityHubDataSource) Load() ([]domain.RawSecurityHubControlData, error) {
	data, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}
	var controls []domain.RawSecurityHubControlData
	err = json.Unmarshal(data, &controls)
	return controls, err
}

// YamlFileSeverityOverrideSource loads severity overrides from a YAML file.
type YamlFileSeverityOverrideSource struct {
	FilePath string
}

func (s *YamlFileSeverityOverrideSource) Load() ([]domain.SeverityOverride, error) {
	data, err := os.ReadFile(s.FilePath)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Overrides map[string]struct {
			Severity string `yaml:"severity"`
		} `yaml:"overrides"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	var overrides []domain.SeverityOverride
	for name, v := range raw.Overrides {
		overrides = append(overrides, domain.SeverityOverride{
			RuleName: name, Severity: v.Severity,
		})
	}
	return overrides, nil
}

// YamlFileConformancePackSource loads conformance pack data from YAML files in a directory.
type YamlFileConformancePackSource struct {
	Directory   string
	GlobPattern string
}

func (s *YamlFileConformancePackSource) Load() ([]domain.RawConformancePackData, error) {
	pattern := s.GlobPattern
	if pattern == "" {
		pattern = "*.yaml"
	}
	matches, err := filepath.Glob(filepath.Join(s.Directory, pattern))
	if err != nil {
		return nil, err
	}
	sort.Strings(matches)
	var result []domain.RawConformancePackData
	for _, f := range matches {
		data, err := os.ReadFile(f)
		if err != nil {
			return nil, err
		}
		var content map[string]any
		if err := yaml.Unmarshal(data, &content); err != nil {
			return nil, err
		}
		name := filepath.Base(f)
		name = strings.TrimSuffix(name, filepath.Ext(name))
		result = append(result, domain.RawConformancePackData{
			Name: name, Content: content,
		})
	}
	return result, nil
}

// FileHCLOutput writes HCL content to files on disk.
type FileHCLOutput struct {
	LocalsPath    string
	VariablesPath string
}

func (o *FileHCLOutput) WriteLocals(content string) error {
	return os.WriteFile(o.LocalsPath, []byte(content), 0644)
}

func (o *FileHCLOutput) WriteVariables(content string) error {
	return os.WriteFile(o.VariablesPath, []byte(content), 0644)
}

// FileRulePackOutput writes rule pack data to YAML and text list files.
type FileRulePackOutput struct {
	PacksFile string
	ListFile  string
}

func (o *FileRulePackOutput) WritePacks(packsData map[string][]string) error {
	wrapper := struct {
		GeneratedOn string              `yaml:"generated_on"`
		Packs       map[string][]string `yaml:"packs"`
	}{
		GeneratedOn: time.Now().UTC().Format(time.RFC3339),
		Packs:       packsData,
	}
	data, err := yaml.Marshal(wrapper)
	if err != nil {
		return err
	}
	return os.WriteFile(o.PacksFile, data, 0644)
}

func (o *FileRulePackOutput) WritePacksList(packs []string) error {
	content := strings.Join(packs, "\n")
	return os.WriteFile(o.ListFile, []byte(content), 0644)
}

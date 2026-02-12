package domain

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// RawConfigRuleData is the intermediate dict-like structure from JSON.
type RawConfigRuleData struct {
	Name          string          `json:"name"`
	Identifier    string          `json:"identifier"`
	Description   string          `json:"description"`
	Parameters    []ParameterData `json:"parameters"`
	ResourceTypes []string        `json:"resource_types"`
	Severity      string          `json:"severity,omitempty"`
}

// ParameterData represents a single parameter for a config rule.
type ParameterData struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Default     string `json:"default,omitempty"`
	Optional    bool   `json:"optional"`
	Description string `json:"description,omitempty"`
}

// ConfigRule is the core domain entity representing an AWS Config Rule.
type ConfigRule struct {
	RuleName              string
	RuleIdentifier        string
	TfVariableDescription string
	ParametersData        []ParameterData
	ResourceTypes         []string
	ruleSeverity          string
}

// NewConfigRule constructs a ConfigRule from raw JSON data.
func NewConfigRule(data RawConfigRuleData) ConfigRule {
	severity := data.Severity
	if severity == "" {
		severity = "Medium"
	}
	resourceTypes := data.ResourceTypes
	if resourceTypes == nil {
		resourceTypes = []string{}
	}
	params := data.Parameters
	if params == nil {
		params = []ParameterData{}
	}
	rule := ConfigRule{
		RuleName:              data.Name,
		RuleIdentifier:        data.Identifier,
		TfVariableDescription: data.Description,
		ParametersData:        params,
		ResourceTypes:         resourceTypes,
		ruleSeverity:          severity,
	}
	rule.RuleName = rule.deriveTfRuleName()
	return rule
}

// TfRuleName returns the Terraform rule name.
func (r *ConfigRule) TfRuleName() string {
	return r.RuleName
}

// TfVariableName returns the Terraform variable name for this rule's parameters.
func (r *ConfigRule) TfVariableName() string {
	return strings.ReplaceAll(r.RuleName, "-", "_") + "_parameters"
}

// RuleSeverity returns the current severity level.
func (r *ConfigRule) RuleSeverity() string {
	return r.ruleSeverity
}

// SetSeverityLevel updates the rule's severity.
func (r *ConfigRule) SetSeverityLevel(value string) {
	r.ruleSeverity = value
}

// deriveTfRuleName computes the Terraform rule name from the raw data.
func (r *ConfigRule) deriveTfRuleName() string {
	normalizedIdentifier := strings.ToLower(strings.ReplaceAll(r.RuleIdentifier, "_", "-"))
	if r.RuleName != normalizedIdentifier {
		return r.RuleName
	}
	return normalizedIdentifier
}

// ToRawData serializes the ConfigRule back to RawConfigRuleData.
func (r *ConfigRule) ToRawData() RawConfigRuleData {
	return RawConfigRuleData{
		Name:          r.RuleName,
		Identifier:    r.RuleIdentifier,
		Description:   r.TfVariableDescription,
		Parameters:    r.ParametersData,
		ResourceTypes: r.ResourceTypes,
		Severity:      r.ruleSeverity,
	}
}

// --- String transformation methods ---

var multipleWhitespacePattern = regexp.MustCompile(`\s+`)

// ReplaceMultipleWhitespaceWithSingle collapses consecutive whitespace into a single space.
func (r *ConfigRule) ReplaceMultipleWhitespaceWithSingle(input string) string {
	return multipleWhitespacePattern.ReplaceAllString(input, " ")
}

// CleanupDescriptionString fixes quotes and tick marks for HCL compatibility.
func (r *ConfigRule) CleanupDescriptionString(input string) string {
	var result strings.Builder
	runes := []rune(input)
	for i := 0; i < len(runes); i++ {
		ch := runes[i]
		if ch == '\'' || ch == '\u2018' || ch == '\u2019' {
			end := i + 3
			if end > len(runes) {
				end = len(runes)
			}
			result.WriteString(r.ReplaceSingleQuotes(string(runes[i:end])))
		} else if ch == '"' || ch == '`' {
			result.WriteRune(' ')
		} else {
			result.WriteRune(ch)
		}
	}
	return strings.TrimSpace(result.String())
}

// ReplaceSingleQuotes returns an apostrophe for possessives, otherwise a space.
func (r *ConfigRule) ReplaceSingleQuotes(input string) string {
	if strings.HasSuffix(input, "s ") || strings.HasSuffix(input, "s.") {
		return "'"
	}
	return " "
}

// ReplaceLastWhitespaceCharWithEllipsis replaces the last space with "...".
func (r *ConfigRule) ReplaceLastWhitespaceCharWithEllipsis(input string) string {
	lastSpace := strings.LastIndex(input, " ")
	if lastSpace == -1 {
		return "..."
	}
	return input[:lastSpace] + "..."
}

// LocalsDescription truncates the description to maxLength, ending on a full word with ellipsis.
func (r *ConfigRule) LocalsDescription(maxLength int) string {
	if maxLength == 0 {
		maxLength = 256
	}
	parts := strings.Split(r.TfVariableDescription, "\n")
	cleaned := make([]string, len(parts))
	for i, p := range parts {
		cleaned[i] = r.CleanupDescriptionString(p)
	}
	fullDescription := r.ReplaceMultipleWhitespaceWithSingle(strings.Join(cleaned, " "))
	if len(fullDescription) <= maxLength {
		return fullDescription
	}
	shortDescription := fullDescription[:maxLength]
	if shortDescription[len(shortDescription)-1] == '.' {
		return shortDescription
	}
	result := r.ReplaceLastWhitespaceCharWithEllipsis(shortDescription)
	for len(result) > maxLength {
		result = r.ReplaceLastWhitespaceCharWithEllipsis(result)
	}
	return result
}

// ReplaceColonsWithEquals replaces colons with " = " except those within quoted strings.
func (r *ConfigRule) ReplaceColonsWithEquals(input string) string {
	inQuotes := false
	var result strings.Builder
	for _, ch := range input {
		if ch == '"' {
			inQuotes = !inQuotes
			result.WriteRune(ch)
		} else if ch == ':' && !inQuotes {
			result.WriteString(" = ")
		} else {
			result.WriteRune(ch)
		}
	}
	return result.String()
}

// --- Parameter type mapping and HCL generation ---

var paramTypeMap = map[string]string{
	"int":       "number",
	"String":    "string",
	"CSV":       "string",
	"string":    "string",
	"StringMap": "string",
	"double":    "number",
	"boolean":   "bool",
}

// MapParamType maps an AWS parameter type to a Terraform type.
func MapParamType(paramType string) (string, error) {
	t, ok := paramTypeMap[paramType]
	if !ok {
		return "", fmt.Errorf("unknown parameter type: %s", paramType)
	}
	return t, nil
}

// GetDefaultParamValue formats a default value for HCL output.
func GetDefaultParamValue(value string, valueType string) string {
	switch valueType {
	case "string":
		return fmt.Sprintf(`"%s"`, value)
	case "number":
		return value
	case "bool":
		return value
	default:
		return value
	}
}

// TfVariableType returns the HCL object type definition for this rule's parameters.
func (r *ConfigRule) TfVariableType() string {
	var lines []string
	for _, param := range r.ParametersData {
		tfType, _ := MapParamType(param.Type)
		if param.Default != "" {
			lines = append(lines, fmt.Sprintf("    %s = optional(%s, %s)",
				param.Name, tfType, GetDefaultParamValue(param.Default, tfType)))
		} else {
			lines = append(lines, fmt.Sprintf("    %s = optional(%s, null)",
				param.Name, tfType))
		}
	}
	return fmt.Sprintf("object({\n%s\n})", strings.Join(lines, "\n"))
}

// TfVariableTypeHCL is an alias used by the variable template.
func (r *ConfigRule) TfVariableTypeHCL() string {
	return r.TfVariableType()
}

// TfVariableDefaultValue returns the HCL default value block for this rule's parameters.
func (r *ConfigRule) TfVariableDefaultValue() string {
	var lines []string
	for _, param := range r.ParametersData {
		if param.Default == "" {
			continue
		}
		tfType, _ := MapParamType(param.Type)
		lines = append(lines, fmt.Sprintf("    %s = %s",
			param.Name, GetDefaultParamValue(param.Default, tfType)))
	}
	if len(lines) > 0 {
		return fmt.Sprintf("{\n%s\n}", strings.Join(lines, "\n"))
	}
	return ""
}

// TfVariableDefaultValueHCL is an alias used by the variable template.
func (r *ConfigRule) TfVariableDefaultValueHCL() string {
	return r.TfVariableDefaultValue()
}

// HasDefaults returns true if any parameter has a default value.
func (r *ConfigRule) HasDefaults() bool {
	for _, param := range r.ParametersData {
		if param.Default != "" {
			return true
		}
	}
	return false
}

// --- ConformancePack ---

// ConformancePack represents an AWS Config conformance pack with sorted rule names.
type ConformancePack struct {
	Name      string
	RuleNames []string
}

// NewConformancePack creates a ConformancePack with rule names sorted lexicographically.
func NewConformancePack(name string, ruleNames []string) ConformancePack {
	sorted := make([]string, len(ruleNames))
	copy(sorted, ruleNames)
	sort.Strings(sorted)
	return ConformancePack{Name: name, RuleNames: sorted}
}

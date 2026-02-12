package ports

// HCLOutput writes generated HCL content to an external destination.
type HCLOutput interface {
	WriteLocals(content string) error
	WriteVariables(content string) error
}

// RulePackOutput writes processed rule pack data to an external destination.
type RulePackOutput interface {
	WritePacks(packsData map[string][]string) error
	WritePacksList(packs []string) error
}

// HCLFormatter formats generated HCL content.
type HCLFormatter interface {
	Format(path string) error
}

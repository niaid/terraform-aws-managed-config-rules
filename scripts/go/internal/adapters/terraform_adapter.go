package adapters

import "os/exec"

// TerraformFormatterAdapter formats HCL files using `terraform fmt`.
type TerraformFormatterAdapter struct {
	WorkingDir string
}

func (t *TerraformFormatterAdapter) Format(path string) error {
	cmd := exec.Command("terraform", "fmt", path)
	cmd.Dir = t.WorkingDir
	return cmd.Run()
}

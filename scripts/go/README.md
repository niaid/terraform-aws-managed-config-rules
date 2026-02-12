# Config Rules Generator (Go)

This tool scrapes AWS documentation for the latest AWS-managed Config Rules and Security Hub controls, then generates Terraform HCL code (`locals` blocks and `variable` definitions) for the `terraform-aws-managed-config-rules` module. It also processes AWS Conformance Packs to produce rule pack mappings.

## Prerequisites

- Go 1.21+
- `terraform` CLI on your PATH (used for `terraform fmt`)
- `git` (for cloning conformance packs)

## Commands

Build the binary:

```bash
cd scripts/go
go build ./cmd/generator/
```

### update-config-rules

Scrapes AWS documentation, generates HCL, and formats the output.

```bash
scripts/go/generator update-config-rules
```

This command:

1. Scrapes the AWS Config managed rules documentation for rule definitions (name, identifier, description, parameters, resource types)
2. Scrapes the AWS Security Hub controls reference for severity data
3. Persists both datasets as JSON in `scripts/go`
4. Loads manual severity overrides from `etc/severity_overrides.yaml`
5. Resolves final severity for each rule (manual overrides first, then Security Hub controls take precedence)
6. Renders `managed_rules_locals.tf` and `managed_rules_variables.tf` at the project root
7. Runs `terraform fmt` on the output

### update-rule-packs

Processes AWS Conformance Packs into rule-to-pack mappings.

```bash
scripts/go/generator update-rule-packs
```

This command:

1. Clones the [awslabs/aws-config-rules](https://github.com/awslabs/aws-config-rules) repository (set `DOWNLOAD_CONFORMANCE_PACKS=no` to skip)
2. Loads the previously generated config rule data from `scripts/go/config_rule_data.json`
3. Parses each conformance pack YAML, mapping CloudFormation resource identifiers to config rule names
4. Writes `files/pack-rules.yaml` (rule-to-pack mappings) and `files/pack-rules-list.txt` (pack names list)

## File Layout

```
scripts/go/
├── cmd/generator/main.go       # CLI entry point
├── internal/
│   ├── domain/                  # Pure business logic (zero I/O dependencies)
│   ├── ports/                   # Interface contracts for external systems
│   ├── adapters/                # File I/O, HTTP scraping, terraform fmt
│   ├── commands/                # Write operations (HCL generation, pack processing)
│   └── queries/                 # Read operations (load rules, overrides, controls)
└── templates/                   # Go text/template files for HCL rendering
```

## Testing

```bash
cd scripts/go
go test ./...
```

The test suite includes both unit tests and property-based tests (using [pgregory.net/rapid](https://pkg.go.dev/pgregory.net/rapid)) covering round-trip serialization, severity resolution, HCL rendering, pack processing, and backward compatibility with the original Python output.

## Severity Resolution

Rule severity is determined in this order:

1. Default severity from AWS documentation (typically "Medium")
2. Manual overrides from `etc/severity_overrides.yaml` are applied
3. Security Hub control severities are applied last and take precedence

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `DOWNLOAD_CONFORMANCE_PACKS` | `yes` | Set to `no` to skip cloning the conformance packs repo during `update-rule-packs` |

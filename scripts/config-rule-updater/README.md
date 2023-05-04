# AWS-managed Config Rules Updater

This script scrapes AWS documentation for the latest list of AWS-managed Config Rules and generates Terraform HCL code for variables and locals compatible with the `terraform-aws-managed-config-rules` Terraform module.

## How it Works

First, the script scrapes AWS documentation for a list of Rules and the documentation page for each rule is scraped for information describing the rule and its parameters. A Terraform variable is generated with a list of the rule's parameters and any default values, and the `managed_rules` local value is updated with the new rule.

For example, below is the JSON generated after scraping the documentation for the `access-keys-rotated` rule.

```json
{
    "name": "access-keys-rotated",
    "variable_name": "access_keys_rotated_parameters",
    "description": "Checks if the active access keys are rotated within the number of days specified in`maxAccessKeyAge`. The rule is NON_COMPLIANT if the access keys have not been rotated for more than`maxAccessKeyAge`number of days.",
    "parameters": [
        {
            "name": "maxAccessKeyAge",
            "type": "int",
            "default": "90",
            "description": "Maximum number of days without rotation. Default 90."
        }
    ]
}
```

And this is the Terraform variable generated from this JSON map.

```hcl
variable "access_keys_rotated_parameters" {
  description = "Input parameters for the access-keys-rotated rule."
  type = object({
    maxAccessKeyAge = number
  })
  default = object({
    maxAccessKeyAge = 90
  })
}
```

## Updating the Locals Block

In addition to updating variables, the script also updates the `managed_rules` values in the `locals` block. Because the severity level for each rule is subjective and not maintained by AWS, the existing locals block is read in first and merged with the new rule definitions. Any new rules have a `Medium` severity level by default and may need to be modified manually later.

Using the same JSON input above, the locals block generated for the `access-keys-rotated` rule looks like this:

```hcl
locals {
  managed_rules = {
    access-keys-rotated = {
      description      = "Checks if the active access keys are rotated within the number of days specified in`maxAccessKeyAge`. The rule is NON_COMPLIANT if the access keys have not been rotated for more than`maxAccessKeyAge`number of days."
      input_parameters = var.access_keys_rotated_parameters
      severity         = "Medium"
    }
  }
}
```

If a rule has no parameters then a `{rule_name}_parameters` variable is not generated and the `input_parameters` attribute is omitted in the `locals` block.
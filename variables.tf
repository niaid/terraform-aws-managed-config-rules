
# Variables not required for settings unrelated to specific Config Rules

variable "rules_to_include" {
  description = "A list of individual AWS-managed Config Rules to deploy"
  default     = []
  type        = list(string)
}

variable "rule_overrides" {
  description = "Override the configuration for any managed rule"
  default     = {}
  type        = any
}

variable "rule_packs" {
  description = "A list of Rule Packs (based off AWS Conformance Packs) to deploy"
  default     = []
  type        = list(string)
}

# In cases where rules from other packs overlap and let's say we want to exclude all overlap rules from a pack..
# this feature should address that. Example use case is where securityhub deploys CIS Level1 and 2 Rules and
# lets say we want to exclude all these rules from NIST pack
variable "rule_packs_to_exclude" {
  description = "A list of Rule Packs (based off AWS Conformance Packs) from which overlap rules to exclude"
  default     = []
  type        = list(string)
}

variable "rules_to_exclude" {
  description = "A list of individual AWS-managed Config Rules to exclude from deployment"
  default     = []
  type        = list(string)
}

variable "excluded_accounts" {
  description = "AWS accounts to exclude from the managed config rules"
  default     = []
  type        = list(string)
}

variable "organization_managed" {
  description = "Whether the rules to create should be organization managed rules"
  default     = false
  type        = bool
}

variable "rule_name_prefix" {
  description = "Rule names created should start with the specified string"
  default     = ""
  type        = string
}

variable "tags" {
  description = "Tags to add to config rules (not applicable to organization managed rules)"
  default     = {}
  type        = map(string)
}

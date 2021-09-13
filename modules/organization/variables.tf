variable "rules" {
  description = "The rules to process"
}

variable "excluded_accounts" {
  description = "AWS accounts to exclude from the managed config rules"
  default     = []
  type        = list(string)
}

variable "rule_name_prefix" {
  description = "Rule names created should start with the specified string"
  default     = ""
  type        = string
}
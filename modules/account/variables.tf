variable "rules" {
  description = "The rules to process"
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
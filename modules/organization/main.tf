resource "aws_config_organization_managed_rule" "rule" {
  for_each = var.rules

  name                 = "${var.rule_name_prefix}${each.key}"
  rule_identifier      = upper(replace(each.key, "-", "_"))
  excluded_accounts    = var.excluded_accounts
  description          = try(each.value["description"], "")
  resource_types_scope = try(each.value["resource_types_scope"], [])

  input_parameters = (
    try(jsonencode(each.value["input_parameters"]), null) != "null" ?
    try(jsonencode(each.value["input_parameters"]), null) :
    null
  )
}
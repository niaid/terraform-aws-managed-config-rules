resource "aws_config_organization_managed_rule" "rule" {
  for_each = var.rules

  name                 = "${var.rule_name_prefix}${each.key}"
  rule_identifier      = upper(replace(each.key, "-", "_"))
  excluded_accounts    = var.excluded_accounts
  description          = try(each.value["description"], "")
  resource_types_scope = try(each.value["resource_types_scope"], [])

  input_parameters = (
    # AWS Config expects all values as strings. This list comprehension
    # removes optional parameter attributes whose value is 'null'.
    try(jsonencode(each.value["input_parameters"]), null) != "null" ?
    try(jsonencode(
      { for k, v in each.value["input_parameters"] :
        k => tostring(v) if v != null }), null) :
    null
  )
}
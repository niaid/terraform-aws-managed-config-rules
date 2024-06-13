resource "aws_config_config_rule" "rule" {
  for_each = var.rules

  name        = "${var.rule_name_prefix}${each.key}"
  description = try(each.value.description, "")

  scope {
    compliance_resource_types = try(each.value.resource_types_scope, [])
  }

  source {
    owner             = "AWS"
    source_identifier = each.value.identifier
  }

  input_parameters = (
    # AWS Config expects all values as strings. This list comprehension
    # removes optional parameter attributes whose value is 'null'.
    try(jsonencode(each.value.input_parameters), null) != "null" ?
    try(jsonencode(
      { for k, v in each.value.input_parameters :
        k => tostring(v) if v != null }), null) :
    null
  )

  tags = var.tags
}
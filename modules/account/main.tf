resource "aws_config_config_rule" "rule" {
  for_each = var.rules

  name        = "${var.rule_name_prefix}${each.key}"
  description = try(each.value["description"], "")

  scope {
    compliance_resource_types = try(each.value["resource_types_scope"], [])
  }

  source {
    owner             = "AWS"
    source_identifier = upper(replace(each.key, "-", "_"))
  }

  input_parameters = (
    try(jsonencode(each.value["input_parameters"]), null) != "null" ?
    try(jsonencode(each.value["input_parameters"]), null) :
    null
  )

  tags = var.tags
}
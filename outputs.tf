output "rules" {
  description = "The AWS-managed Config Rules applied"

  value = (
    var.organization_managed ?
    module.org[0].rules :
    module.account[0].rules
  )
}

output "rule_pack_list" {
  description = "A list of all the Rule Packs included"
  value       = keys(local.pack_file["packs"])
}

output "all_rule_descriptions" {
  description = "A list of maps for Config Rules and their descriptions"

  value = [
    for rule, attr in local.final_managed_rules :
    {
      name        = rule
      severity    = attr["severity"]
      description = attr["description"]
    }
  ]
}

locals {
  pack_file = yamldecode(file("${path.module}/files/pack-rules.yaml"))

  rule_packs_to_apply = [
    for pack in var.rule_packs :
    local.pack_file["packs"][pack]
  ]

  rule_packs_to_exclude = [
    for pack in var.rule_packs_to_exclude :
    local.pack_file["packs"][pack]
  ]

  rules_collected = sort(
    distinct(
      flatten(
        concat(
          var.rules_to_include,
          local.rule_packs_to_apply
        )
      )
    )
  )

  rules_exclude_collected = sort(
    distinct(
      flatten(
        concat(
          var.rules_to_exclude,
          local.rule_packs_to_exclude
        )
      )
    )
  )

  final_rules = [
    for rule in local.rules_collected :
    rule if !contains(local.rules_exclude_collected, rule)
  ]

  combined_rules = {
    for rule in distinct(concat(keys(local.managed_rules), keys(var.rule_overrides))) :
    rule => lookup(local.managed_rules, rule, lookup(var.rule_overrides, rule, {}))
  }

  final_managed_rules = {
    for rule, attr in local.combined_rules :
    rule => merge(attr, lookup(var.rule_overrides, rule, {}))
  }

  rules_to_apply = {
    for rule, attr in local.final_managed_rules :
    rule => attr if contains(local.final_rules, rule)
  }
}

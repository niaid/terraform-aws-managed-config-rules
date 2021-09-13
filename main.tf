module "org" {
  count  = var.organization_managed ? 1 : 0
  source = "./modules/organization"

  rules             = local.rules_to_apply
  rule_name_prefix  = var.rule_name_prefix
  excluded_accounts = var.excluded_accounts
}

module "account" {
  count  = var.organization_managed ? 0 : 1
  source = "./modules/account"

  rules            = local.rules_to_apply
  rule_name_prefix = var.rule_name_prefix
  tags             = var.tags
}
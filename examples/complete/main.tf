module "managed_rules" {
  source = "../../"

  organization_managed = false # this is the default setting

  # You can exclude AWS accounts when deploying Organization rules
  # excluded_accounts = [
  #   "123456789012",
  # ]

  rule_packs = [
    "Operational-Best-Practices-for-CIS-Critical-Security-Controls-v8-IG3",
    "Operational-Best-Practices-for-NIST-800-53-rev-4",
  ]

  rule_packs_to_exclude = [
    "Operational-Best-Practices-for-CIS-AWS-v1.4-Level1",
    "Operational-Best-Practices-for-CIS-AWS-v1.4-Level2",
  ]


  # Extra rules not included in the Packs you want to deploy
  rules_to_include = [
    "dax-encryption-enabled",
  ]

  rules_to_exclude = [
    "lambda-concurrency-check",
  ]

  redshift_cluster_maintenancesettings_check_parameters = {
    allowVersionUpgrade = true
  }

  rule_overrides = {
    acm-certificate-expiration-check = {
      description = "Checks if AWS Certificate Manager Certificates in your account..."

      input_parameters = {
        daysToExpiration = var.acm_certificate_expiration_check
      }
    }
  }
}

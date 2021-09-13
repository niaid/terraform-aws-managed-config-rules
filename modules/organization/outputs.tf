output "rules" {
  description = "The AWS-managed Config Rules applied"
  value       = aws_config_organization_managed_rule.rule.*
}
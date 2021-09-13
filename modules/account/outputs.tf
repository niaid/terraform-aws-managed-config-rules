output "rules" {
  description = "The AWS-managed Config Rules applied"
  value       = aws_config_config_rule.rule.*
}
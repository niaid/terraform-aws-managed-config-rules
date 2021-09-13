output "rules_applied" {
  description = "A list of Config Rules applied by the module"
  value       = keys(module.managed_rules.rules[0])
}
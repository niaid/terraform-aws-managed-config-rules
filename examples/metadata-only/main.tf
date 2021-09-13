# This module will do/manage nothing by default when instantiated, but it will
# return an output which has all the managed rules, with their descriptions and
# severities included.
#
# In this example, we'll call this module send the JSON-encoded results to S3

module "managed_config_rules" {
  source = "../../"
}

resource "aws_s3_bucket" "config_rule_desc" {
  bucket_prefix = "config-rule-descriptions"
  acl           = "private"

  versioning {
    enabled = true
  }

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }
}

resource "aws_s3_bucket_object" "managed_rules_desc" {
  bucket       = aws_s3_bucket.config_rule_desc.bucket
  key          = "managed-rules-descriptions.json"
  content_type = "application/json"
  content      = jsonencode(module.managed_config_rules.all_rule_descriptions)
}
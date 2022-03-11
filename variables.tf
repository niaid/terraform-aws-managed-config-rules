
# Variables not required for settings unrelated to specific Config Rules

variable "rules_to_include" {
  description = "A list of individual AWS-managed Config Rules to deploy"
  default     = []
  type        = list(string)
}

variable "rule_overrides" {
  description = "Override the configuration for any managed rule"
  default     = {}
  type        = any
}

variable "rule_packs" {
  description = "A list of Rule Packs (based off AWS Conformance Packs) to deploy"
  default     = []
  type        = list(string)
}

# In cases where rules from other packs overlap and let's say we want to exclude all overlap rules from a pack..
# this feature should address that. Example use case is where securityhub deploys CIS Level1 and 2 Rules and
# lets say we want to exclude all these rules from NIST pack
variable "rule_packs_to_exclude" {
  description = "A list of Rule Packs (based off AWS Conformance Packs) from which overlap rules to exclude"
  default     = []
  type        = list(string)
}

variable "rules_to_exclude" {
  description = "A list of individual AWS-managed Config Rules to exclude from deployment"
  default     = []
  type        = list(string)
}

variable "excluded_accounts" {
  description = "AWS accounts to exclude from the managed config rules"
  default     = []
  type        = list(string)
}

variable "organization_managed" {
  description = "Whether the rules to create should be organization managed rules"
  default     = false
  type        = bool
}

variable "rule_name_prefix" {
  description = "Rule names created should start with the specified string"
  default     = ""
  type        = string
}

variable "tags" {
  description = "Tags to add to config rules (not applicable to organization managed rules)"
  default     = {}
  type        = map(string)
}

# Config Rule Settings
variable "access_keys_rotated_parameters" {
  description = "Input Parameters for the access-keys-rotated rule"

  default = {
    maxAccessKeyAge = "90"
  }

  type = object({
    maxAccessKeyAge = string
  })
}

variable "account_part_of_organizations_parameters" {
  description = "Input Parameters for the account-part-of-organizations rule"
  default     = null
  type        = map(string)
}

variable "acm_certificate_expiration_check_parameters" {
  description = "Input Parameters for the acm-certificate-expiration-check rule"

  default = {
    daysToExpiration = "14"
  }

  type = object({
    daysToExpiration = string
  })
}

variable "alb_waf_enabled_parameters" {
  description = "Input Parameters for the alb-waf-enabled rule."
  default     = null
  type        = map(string)
}

variable "api_gw_associated_with_waf_parameters" {
  description = "Input Parameters for the api-gw-associated-with-waf rule"
  default     = null
  type        = map(string)
}

variable "api_gw_endpoint_type_check_parameters" {
  description = "Input Parameters for the api-gw-endpoint-type-check rule"
  default     = null

  # Comma-separated list of allowed endpointConfigurationTypes. Allowed values are REGIONAL, PRIVATE and EDGE.
  type = object({
    endpointConfigurationTypes = string
  })
}

variable "api_gw_execution_logging_enabled_parameters" {
  description = "Input Parameters for the api-gw-execution-logging-enabled rule"

  default = {
    loggingLevel = "ERROR,INFO"
  }

  # Comma-separated list of specific logging levels (for example, ERROR, INFO or ERROR,INFO).
  type = object({
    loggingLevel = string
  })
}

variable "api_gw_ssl_enabled_parameters" {
  description = "Input Parameters for the api-gw-ssl-enabled rule"
  default     = null
  type        = map(string)
}

variable "approved_amis_by_id_parameters" {
  description = "Input parameters for the approved-amis-by-id rule"
  default     = null

  # The AMI IDs (comma-separated list of up to 10).
  type = object({
    amiIds = string
  })
}

variable "approved_amis_by_tag_parameters" {
  description = "Input parameters for the approved-amis-by-tag rule"
  default     = null

  # The AMIs by tag (comma-separated list up to 10; for example,tag-key:tag-value; i.e. tag-key1 matches AMIs with tag-key1,tag-key2:value2 matches tag-key2 having value2).
  type = object({
    amisByTagKeyAndValue = string
  })
}

variable "aurora_mysql_backtracking_enabled_parameters" {
  description = "Input parameters for the aurora-mysql-backtracking-enabled rule"
  default     = null
  type        = map(string)
}

variable "aurora_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the aurora-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "autoscaling_multiple_az_parameters" {
  description = "Input parameters for the autoscaling-multiple-az rule"
  default     = null
  type        = map(string)
}

variable "backup_plan_min_frequency_and_min_retention_check_parameters" {
  description = "Input parameters for the backup-plan-min-frequency-and-min-retention-check rule"

  default = {
    requiredFrequencyValue = "1"
    requiredRetentionDays  = "35"
    requiredFrequencyUnit  = "days"
  }

  type = object({
    requiredFrequencyValue = string
    requiredRetentionDays  = string
    requiredFrequencyUnit  = string
  })
}

variable "backup_recovery_point_manual_deletion_disabled_parameters" {
  description = "Input parameters for the backup-recovery-point-manual-deletion-disabled rule"
  default     = null
  type        = map(string)
}

variable "backup_recovery_point_minimum_retention_check_parameters" {
  description = "Input parameters for the backup-recovery-point-minimum-retention-check rule"

  default = {
    requiredRetentionDays = "35"
  }

  type = object({
    requiredRetentionDays = string
  })
}

variable "cloudformation_stack_drift_detection_check_parameters" {
  description = "Input parameters for the cloudformation-stack-drift-detection-check rule"
  default     = null

  # The AWS CloudFormation role ARN with IAM policy permissions to detect drift for AWS CloudFormation Stacks
  type = object({
    cloudformationRoleArn = string
  })
}

variable "cloudformation_stack_notification_check_parameters" {
  description = "Input parameters for the cloudformation-stack-notification-check rule"
  default     = null
  type        = map(string)
}

variable "cloudfront_accesslogs_enabled_parameters" {
  description = "Input parameters for the cloudfront-accesslogs-enabled rule"
  default     = null
  type        = map(string)
}

variable "cloudfront_associated_with_waf_parameters" {
  description = "Input parameters for the cloudfront-associated-with-waf rule"
  default     = null
  type        = map(string)
}

variable "cloudwatch_alarm_action_check_parameters" {
  description = "Input Parameters for the cloudwatch-alarm-action-check rule"
  type        = map(string)

  default = {
    alarmActionRequired            = "true"
    insufficientDataActionRequired = "true"
    okActionRequired               = "false"
  }
}

variable "cloudwatch_alarm_resource_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-resource-check rule"
  default     = null

  # AWS resource type. The value can be one of the following: AWS::EC2::Volume, AWS::EC2::Instance, AWS::RDS::DBCluster, or AWS::S3::Bucket.
  # The metric associated with the alarm (for example, 'CPUUtilization' for EC2 instances).
  type = object({
    resourceType = string
    metricName   = string
  })
}

variable "cloudwatch_alarm_settings_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-settings-check rule"
  default     = null
  type        = map(string)
}

variable "cloudwatch_log_group_encrypted_parameters" {
  description = "Input parameters for the cloudwatch-log-group-encrypted rule"
  default     = null
  type        = map(string)
}

variable "cloud_trail_cloud_watch_logs_enabled_parameters" {
  description = "Input parameters for the cloud-trail-cloud-watch-logs-enabled rule"
  default     = null
  type        = map(string)
}

variable "cloud_trail_enabled_parameters" {
  description = "Input parameters for the cloud-trail-enabled rule"
  default     = null
  type        = map(string)
}

variable "codebuild_project_environment_privileged_check_parameters" {
  description = "Input parameters for the codebuild-project-environment-privileged-check rule"
  default     = null
  type        = map(string)
}

variable "codebuild_project_logging_enabled_parameters" {
  description = "Input parameters for the codebuild-project-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "codebuild_project_s3_logs_encrypted_parameters" {
  description = "Input parameters for the codebuild-project-s3-logs-encrypted rule"
  default     = null
  type        = map(string)
}

variable "codedeploy_ec2_minimum_healthy_hosts_configured_parameters" {
  description = "Input parameters for the codedeploy-ec2-minimum-healthy-hosts-configured rule"

  type = object({
    minimumHealthyHostsFleetPercent = string
    minimumHealthyHostsHostCount    = string
  })

  default = {
    minimumHealthyHostsFleetPercent = "66"
    minimumHealthyHostsHostCount    = "1"
  }
}
variable "codepipeline_deployment_count_check_parameters" {
  description = "Input parameters for the codepipeline-deployment-count-check rule"
  default     = null
  type        = map(string)
}

variable "codepipeline_region_fanout_check_parameters" {
  description = "Input parameters for the codepipeline-region-fanout-check rule"

  default = {
    regionFanoutFactor = "3"
  }

  type = object({
    regionFanoutFactor = string
  })
}

variable "cw_loggroup_retention_period_check_parameters" {
  description = "Input parameters for the cw-loggroup-retention-period-check rule"
  default     = null
  type        = map(string)
}

variable "desired_instance_tenancy_parameters" {
  description = "Input parameters for the desired-instance-tenancy rule"
  default     = null
  type        = map(string)
}

variable "desired_instance_type_parameters" {
  description = "Input parameters for the desired-instance-type rule"
  default     = null

  type = object({
    instanceType = string
  })
}

variable "db_instance_backup_enabled_parameters" {
  description = "Input parameters for the db-instance-backup-enabled rule"
  default     = null
  type        = map(string)
}

variable "dynamodb_autoscaling_enabled_parameters" {
  description = "Input parameters for the dynamodb-autoscaling-enabled rule"
  default     = null
  type        = map(string)
}

variable "dynamodb_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the dynamodb-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "dynamodb_table_encrypted_kms_parameters" {
  description = "Input parameters for the dynamodb-table_encrypted-kms rule"
  default     = null
  type        = map(string)
}

variable "dynamodb_throughput_limit_check_parameters" {
  description = "Input parameters for the dynamodb-throughput-limit-check rule"
  default     = null
  type        = map(string)
}

variable "ebs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ebs-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "ec2_instance_multiple_eni_check_parameters" {
  description = "Input parameters for the ec2-instance-multiple-eni-check rule"
  default     = null
  type        = map(string)
}

variable "ec2_instance_profile_attached_parameters" {
  description = "Input parameters for the ec2-instance-profile-attached rule"
  default     = null
  type        = map(string)
}

variable "ec2_managedinstance_applications_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-blacklisted rule"
  default     = null
  type        = map(string)
}

variable "ec2_managedinstance_applications_required_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-required rule"
  default     = null
  type        = map(string)
}

variable "ec2_managedinstance_inventory_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-inventory-blacklisted rule"
  default     = null
  type        = map(string)
}

variable "ec2_managedinstance_platform_check_parameters" {
  description = "Input parameters for the ec2-managedinstance-platform-check rule"
  default     = null
  type        = map(string)
}

variable "ec2_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ec2-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "ec2_stopped_instance_parameters" {
  description = "Input parameters for the ec2-stopped-instance rule"

  default = {
    AllowedDays = "30"
  }

  type = object({
    AllowedDays = string
  })
}

variable "ec2_volume_inuse_check_parameters" {
  description = "Input parameters for the ec2-volume-inuse-check rule"
  default     = null
  type        = map(string)
}

variable "ecs_no_environment_secrets_parameters" {
  description = "Input parameters for the ecs-no-environment-secrets rule"
  default     = null

  type = object({
    secretKeys = string
  })
}

variable "ecs_task_definition_user_for_host_mode_check_parameters" {
  description = "Input parameters for the ecs-task-definition-user-for-host-mode-check rule"
  default     = null
  type        = map(string)
}

variable "efs_encrypted_check_parameters" {
  description = "Input parameters for the efs-encrypted-check rule"
  default     = null
  type        = map(string)
}

variable "efs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the efs-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "eks_cluster_oldest_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-oldest-supported-version rule"
  default     = null

  type = object({
    oldestVersionSupported = string
  })
}

variable "eks_cluster_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-supported-version rule"
  default     = null

  type = object({
    oldestVersionSupported = string
  })
}

variable "eks_secrets_encrypted_parameters" {
  description = "Input parameters for the eks-secrets-encrypted rule"
  default     = null
  type        = map(string)
}

variable "elasticache_redis_cluster_automatic_backup_check_parameters" {
  description = "Input parameters for the elasticache-redis-cluster-automatic-backup-check rule"

  default = {
    snapshotRetentionPeriod = "15"
  }

  type = object({
    snapshotRetentionPeriod = string
  })
}

variable "elasticsearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the elasticsearch-logs-to-cloudwatch rule"
  default     = null
  type        = map(string)
}

variable "elastic_beanstalk_managed_updates_enabled_parameters" {
  description = "Input parameters for the elastic-beanstalk-managed-updates-enabled rule"
  default     = null
  type        = map(string)
}

variable "elbv2_acm_certificate_required_parameters" {
  description = "Input parameters for the elbv2-acm-certificate-required rule"
  default     = null
  type        = map(string)
}

variable "elb_custom_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-custom-security-policy-ssl-check rule"
  default     = null
  type        = map(string)
}

variable "elb_logging_enabled_parameters" {
  description = "Input parameters for the elb-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "elb_predefined_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-predefined-security-policy-ssl-check rule"
  default     = null
  type        = map(string)
}

variable "emr_kerberos_enabled_parameters" {
  description = "Input parameters for the emr-kerberos-enabled rule"
  default     = null
  type        = map(string)
}

variable "encrypted_volumes_parameters" {
  description = "Input parameters for the encrypted-volumes rule"
  default     = null
  type        = map(string)
}

variable "fms_shield_resource_policy_check_parameters" {
  description = "Input parameters for the fms-shield-resource-policy-check rule"
  default     = null
  type        = map(string)
}

variable "fms_webacl_resource_policy_check_parameters" {
  description = "Input parameters for the fms-webacl-resource-policy-check rule"
  default     = null
  type        = map(string)
}

variable "fms_webacl_rulegroup_association_check_parameters" {
  description = "Input parameters for the fms-webacl-rulegroup-association-check rule"
  default     = null
  type        = map(string)
}

variable "fsx_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the fsx-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "guardduty_enabled_centralized_parameters" {
  description = "Input parameters for the guardduty-enabled-centralized rule"
  default     = null
  type        = map(string)
}

variable "guardduty_non_archived_findings_parameters" {
  description = "Input parameters for the guardduty-non-archived-findings rule"
  type        = map(string)

  default = {
    daysLowSev    = "30"
    daysMediumSev = "7"
    daysHighSev   = "1"
  }
}

variable "iam_customer_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-customer-policy-blocked-kms-actions rule"
  default     = null

  type = object({
    blockedActionsPatterns = string
  })
}

variable "iam_inline_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-inline-policy-blocked-kms-actions rule"
  default     = null

  type = object({
    blockedActionsPatterns = string
  })
}

variable "iam_password_policy_parameters" {
  description = "Input parameters for the iam-password-policy rule"
  type        = map(string)

  # Important: The true and false values for the rule parameters are case-sensitive. If true is not provided in lowercase, it will be treated as false.
  default = {
    RequireUppercaseCharacters = "true"
    RequireLowercaseCharacters = "true"
    RequireSymbols             = "true"
    RequireNumbers             = "true"
    MinimumPasswordLength      = "14"
    PasswordReusePrevention    = "24"
    MaxPasswordAge             = "90"
  }
}

variable "iam_policy_blacklisted_check_parameters" {
  description = "Input parameters for the iam-policy-blacklisted-check rule"
  default     = null
  type        = map(string)
}

variable "iam_policy_in_use_parameters" {
  description = "Input parameters for the iam-policy-in-use rule"
  default     = null
  type        = map(string)
}

variable "iam_role_managed_policy_check_parameters" {
  description = "Input parameters for the iam-role-managed-policy-check rule"
  default     = null

  type = object({
    managedPolicyArns = string
  })
}

variable "iam_user_group_membership_check_parameters" {
  description = "Input parameters for the iam-user-group-membership-check rule"
  default     = null
  type        = map(string)
}

variable "iam_user_unused_credentials_check_parameters" {
  description = "Input parameters for the iam-user-unused-credentials-check rule"

  default = {
    maxCredentialUsageAge = "90"
  }

  type = object({
    maxCredentialUsageAge = string
  })
}

variable "instances_in_vpc_parameters" {
  description = "Input parameters for the instances-in-vpc rule"
  default     = null
  type        = map(string)
}

variable "internet_gateway_authorized_vpc_only_parameters" {
  description = "Input parameters for the internet-gateway-authorized-vpc-only rule"
  default     = null
  type        = map(string)
}

variable "kms_cmk_not_scheduled_for_deletion_parameters" {
  description = "Input parameters for the kms-cmk-not-scheduled-for-deletion rule"
  default     = null
  type        = map(string)
}

variable "lambda_concurrency_check_parameters" {
  description = "Input parameters for the lambda-concurrency-check rule"
  default     = null
  type        = map(string)
}

variable "lambda_dlq_check_parameters" {
  description = "Input parameters for the lambda-dlq-check rule"
  default     = null
  type        = map(string)
}

variable "lambda_function_settings_check_parameters" {
  description = "Input parameters for the lambda-function-settings-check rule"
  default     = null
  type        = map(string)
}

variable "lambda_inside_vpc_parameters" {
  description = "Input parameters for the lambda-inside-vpc rule"
  default     = null
  type        = map(string)
}

variable "lambda_vpc_multi_az_check_parameters" {
  description = "Input parameters for the lambda-vpc-multi-az-check rule"
  default     = null
  type        = map(string)
}

variable "multi_region_cloud_trail_enabled_parameters" {
  description = "Input parameters for the multi-region-cloud-trail-enabled rule"
  default     = null
  type        = map(string)
}

variable "no_unrestricted_route_to_igw_parameters" {
  description = "Input parameters for the no-unrestricted-route-to-igw rule"
  default     = null
  type        = map(string)
}

variable "opensearch_audit_logging_enabled_parameters" {
  description = "Input parameters for the opensearch-audit-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "opensearch_https_required_parameters" {
  description = "Input parameters for the opensearch-https-required rule"
  default     = null
  type        = map(string)
}

variable "opensearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the opensearch-logs-to-cloudwatch rule"
  default     = null
  type        = map(string)
}

variable "rds_cluster_default_admin_check_parameters" {
  description = "Input parameters for the rds-cluster-default-admin-check rule"
  default     = null
  type        = map(string)
}

variable "rds_enhanced_monitoring_enabled_parameters" {
  description = "Input parameters for the rds-enhanced-monitoring-enabled rule"
  default     = null
  type        = map(string)
}

variable "rds_instance_default_admin_check_parameters" {
  description = "Input parameters for the rds-instance-default-admin-check rule"
  default     = null
  type        = map(string)
}

variable "rds_instance_deletion_protection_enabled_parameters" {
  description = "Input parameters for the rds-instance-deletion-protection-enabled rule"
  default     = null
  type        = map(string)
}

variable "rds_logging_enabled_parameters" {
  description = "Input parameters for the rds-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "rds_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the rds-resources-protected-by-backup-plan rule"
  default     = null
  type        = map(string)
}

variable "rds_storage_encrypted_parameters" {
  description = "Input parameters for the rds-storage-encrypted rule"
  default     = null
  type        = map(string)
}

variable "redshift_backup_enabled_parameters" {
  description = "Input parameters for the redshift-backup-enabled rule"
  default     = null
  type        = map(string)
}

variable "redshift_cluster_configuration_check_parameters" {
  description = "Input parameters for the redshift-cluster-configuration-check rule"
  type        = map(string)

  default = {
    clusterDbEncrypted = "true"
    loggingEnabled     = "true"
    nodeTypes          = "dc1.large"
  }
}

variable "redshift_cluster_kms_enabled_parameters" {
  description = "Input parameters for the redshift-cluster-kms-enabled rule"
  default     = null
  type        = map(string)
}

variable "redshift_cluster_maintenancesettings_check_parameters" {
  description = "Input parameters for the redshift-cluster-maintenancesettings-check rule"
  default     = null
  type        = map(string)
}

variable "redshift_default_admin_check_parameters" {
  description = "Input parameters for the redshift-default-admin-check rule"
  default     = null
  type        = map(string)
}

variable "required_tags_parameters" {
  description = "Input parameters for the required-tags rule"
  default     = null
  type        = map(string)
}

variable "restricted_incoming_traffic_parameters" {
  description = "Input parameters for the restricted-incoming-traffic rule"
  default     = null
  type        = map(string)
}

variable "s3_account_level_public_access_blocks_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks rule"
  default     = null
  type        = map(string)
}

variable "s3_account_level_public_access_blocks_periodic_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks-periodic rule"
  default     = null
  type        = map(string)
}

variable "s3_bucket_blacklisted_actions_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-blacklisted-actions-prohibited rule"
  default     = null

  type = object({
    blacklistedActionPattern = string
  })
}

variable "s3_bucket_default_lock_enabled_parameters" {
  description = "Input parameters for the s3-bucket-default-lock-enabled rule"
  default     = null
  type        = map(string)
}

variable "s3_bucket_level_public_access_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-level-public-access-prohibited rule"
  default     = null
  type        = map(string)
}

variable "s3_bucket_logging_enabled_parameters" {
  description = "Input parameters for the s3-bucket-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "s3_bucket_policy_grantee_check_parameters" {
  description = "Input parameters for the s3-bucket-policy-grantee-check rule"
  default     = null
  type        = map(string)
}

variable "s3_bucket_policy_not_more_permissive_parameters" {
  description = "Input parameters for the s3-bucket-policy-not-more-permissive rule"
  default     = null

  type = object({
    controlPolicy = string
  })
}

variable "s3_bucket_versioning_enabled_parameters" {
  description = "Input parameters for the s3-bucket-versioning-enabled rule"
  default     = null
  type        = map(string)
}

variable "s3_default_encryption_kms_parameters" {
  description = "Input parameters for the s3-default-encryption-kms rule"
  default     = null
  type        = map(string)
}

variable "s3_version_lifecycle_policy_check_parameters" {
  description = "Input parameters for the s3-version-lifecycle-policy-check rule"
  default     = null
  type        = map(string)
}

variable "sagemaker_endpoint_configuration_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-endpoint-configuration-kms-key-configured rule"
  default     = null
  type        = map(string)
}

variable "sagemaker_notebook_instance_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-kms-key-configured rule"
  default     = null
  type        = map(string)
}

variable "secretsmanager_rotation_enabled_check_parameters" {
  description = "Input parameters for the secretsmanager-rotation-enabled-check rule"
  default     = null
  type        = map(string)
}

variable "secretsmanager_secret_periodic_rotation_parameters" {
  description = "Input parameters for the secretsmanager-secret-periodic-rotation rule"

  default = {
    maxDaysSinceRotation = "90"
  }

  type = object({
    maxDaysSinceRotation = string
  })
}

variable "secretsmanager_secret_unused_parameters" {
  description = "Input parameters for the secretsmanager-secret-unused rule"

  default = {
    unusedForDays = "90"
  }

  type = object({
    unusedForDays = string
  })
}

variable "secretsmanager_using_cmk_parameters" {
  description = "Input parameters for the secretsmanager-using-cmk rule"
  default     = null
  type        = map(string)
}

variable "service_vpc_endpoint_enabled_parameters" {
  description = "Input parameters for the service-vpc-endpoint-enabled rule"
  default     = null

  type = object({
    serviceName = string
  })
}

variable "sns_encrypted_kms_parameters" {
  description = "Input parameters for the sns-encrypted-kms rule"
  default     = null
  type        = map(string)
}

variable "vpc_flow_logs_enabled_parameters" {
  description = "Input parameters for the vpc-flow-logs-enabled rule"
  default     = null
  type        = map(string)
}

variable "vpc_sg_open_only_to_authorized_ports_parameters" {
  description = "Input parameters for the vpc-sg-open-only-to-authorized-ports rule"
  default     = null
  type        = map(string)
}

variable "wafv2_logging_enabled_parameters" {
  description = "Input parameters for the wafv2-logging-enabled rule"
  default     = null
  type        = map(string)
}

variable "waf_classic_logging_enabled_parameters" {
  description = "Input parameters for the waf-classic-logging-enabled rule"
  default     = null
  type        = map(string)
}

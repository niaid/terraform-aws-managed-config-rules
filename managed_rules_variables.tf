variable "access_keys_rotated_parameters" {
  description = "Input parameters for the access-keys-rotated rule."
  type = object({
    maxAccessKeyAge = optional(number, 90)
  })
}

variable "account_part_of_organizations_parameters" {
  description = "Input parameters for the account-part-of-organizations rule."
  type = object({
    masterAccountId = optional(string, null)
  })
}

variable "acm_certificate_expiration_check_parameters" {
  description = "Input parameters for the acm-certificate-expiration-check rule."
  type = object({
    daysToExpiration = optional(number, 14)
  })
}

variable "alb_desync_mode_check_parameters" {
  description = "Input parameters for the alb-desync-mode-check rule."
  type = object({
    desyncMode = string
  })
}

variable "alb_waf_enabled_parameters" {
  description = "Input parameters for the alb-waf-enabled rule."
  type = object({
    wafWebAclIds = optional(string, null)
  })
}

variable "api_gwv2_authorization_type_configured_parameters" {
  description = "Input parameters for the api-gwv2-authorization-type-configured rule."
  type = object({
    authorizationType = optional(string, null)
  })
}

variable "api_gw_associated_with_waf_parameters" {
  description = "Input parameters for the api-gw-associated-with-waf rule."
  type = object({
    webAclArns = optional(string, null)
  })
}

variable "api_gw_endpoint_type_check_parameters" {
  description = "Input parameters for the api-gw-endpoint-type-check rule."
  type = object({
    endpointConfigurationTypes = string
  })
}

variable "api_gw_execution_logging_enabled_parameters" {
  description = "Input parameters for the api-gw-execution-logging-enabled rule."
  type = object({
    loggingLevel = optional(string, "ERROR,INF")
  })
}

variable "api_gw_ssl_enabled_parameters" {
  description = "Input parameters for the api-gw-ssl-enabled rule."
  type = object({
    certificateIDs = optional(string, null)
  })
}

variable "approved_amis_by_id_parameters" {
  description = "Input parameters for the approved-amis-by-id rule."
  type = object({
    amiIds = string
  })
}

variable "approved_amis_by_tag_parameters" {
  description = "Input parameters for the approved-amis-by-tag rule."
  type = object({
    amisByTagKeyAndValue = optional(string, "tag-key = tag-value,other-tag-key")
  })
}

variable "appsync_associated_with_waf_parameters" {
  description = "Input parameters for the appsync-associated-with-waf rule."
  type = object({
    wafWebAclARNs = optional(string, null)
  })
}

variable "appsync_logging_enabled_parameters" {
  description = "Input parameters for the appsync-logging-enabled rule."
  type = object({
    fieldLoggingLevel = optional(string, null)
  })
}

variable "aurora_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the aurora-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "aurora_mysql_backtracking_enabled_parameters" {
  description = "Input parameters for the aurora-mysql-backtracking-enabled rule."
  type = object({
    backtrackWindowInHours = optional(number, null)
  })
}

variable "aurora_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the aurora-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "autoscaling_multiple_az_parameters" {
  description = "Input parameters for the autoscaling-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
}

variable "backup_plan_min_frequency_and_min_retention_check_parameters" {
  description = "Input parameters for the backup-plan-min-frequency-and-min-retention-check rule."
  type = object({
    requiredFrequencyUnit  = optional(string, "days")
    requiredFrequencyValue = optional(number, 1)
    requiredRetentionDays  = optional(number, 35)
  })
}

variable "backup_recovery_point_manual_deletion_disabled_parameters" {
  description = "Input parameters for the backup-recovery-point-manual-deletion-disabled rule."
  type = object({
    principalArnList = optional(string, null)
  })
}

variable "backup_recovery_point_minimum_retention_check_parameters" {
  description = "Input parameters for the backup-recovery-point-minimum-retention-check rule."
  type = object({
    requiredRetentionDays = optional(number, 35)
  })
}

variable "clb_desync_mode_check_parameters" {
  description = "Input parameters for the clb-desync-mode-check rule."
  type = object({
    desyncMode = string
  })
}

variable "clb_multiple_az_parameters" {
  description = "Input parameters for the clb-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
}

variable "cloudformation_stack_drift_detection_check_parameters" {
  description = "Input parameters for the cloudformation-stack-drift-detection-check rule."
  type = object({
    cloudformationRoleArn = string
  })
}

variable "cloudformation_stack_notification_check_parameters" {
  description = "Input parameters for the cloudformation-stack-notification-check rule."
  type = object({
    snsTopic1 = optional(string, null)
    snsTopic2 = optional(string, null)
    snsTopic3 = optional(string, null)
    snsTopic4 = optional(string, null)
    snsTopic5 = optional(string, null)
  })
}

variable "cloudfront_accesslogs_enabled_parameters" {
  description = "Input parameters for the cloudfront-accesslogs-enabled rule."
  type = object({
    s3BucketName = optional(string, null)
  })
}

variable "cloudfront_associated_with_waf_parameters" {
  description = "Input parameters for the cloudfront-associated-with-waf rule."
  type = object({
    wafWebAclIds = optional(string, null)
  })
}

variable "cloudtrail_s3_dataevents_enabled_parameters" {
  description = "Input parameters for the cloudtrail-s3-dataevents-enabled rule."
  type = object({
    s3BucketNames = optional(string, null)
  })
}

variable "cloudwatch_alarm_action_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-action-check rule."
  type = object({
    action1                        = optional(string, null)
    action2                        = optional(string, null)
    action3                        = optional(string, null)
    action4                        = optional(string, null)
    action5                        = optional(string, null)
    alarmActionRequired            = optional(string, "true")
    insufficientDataActionRequired = optional(string, "true")
    okActionRequired               = optional(string, "false")
  })
}

variable "cloudwatch_alarm_resource_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-resource-check rule."
  type = object({
    metricName   = string
    resourceType = string
  })
}

variable "cloudwatch_alarm_settings_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-settings-check rule."
  type = object({
    comparisonOperator = optional(string, null)
    evaluationPeriods  = optional(number, null)
    metricName         = string
    period             = optional(number, 300)
    statistic          = optional(string, null)
    threshold          = optional(number, null)
  })
}

variable "cloudwatch_log_group_encrypted_parameters" {
  description = "Input parameters for the cloudwatch-log-group-encrypted rule."
  type = object({
    kmsKeyId = optional(string, null)
  })
}

variable "cloud_trail_cloud_watch_logs_enabled_parameters" {
  description = "Input parameters for the cloud-trail-cloud-watch-logs-enabled rule."
  type = object({
    expectedDeliveryWindowAge = optional(number, null)
  })
}

variable "cloudtrail_enabled_parameters" {
  description = "Input parameters for the cloudtrail-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArn = optional(string, null)
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
  })
}

variable "codebuild_project_environment_privileged_check_parameters" {
  description = "Input parameters for the codebuild-project-environment-privileged-check rule."
  type = object({
    exemptedProjects = optional(string, null)
  })
}

variable "codebuild_project_logging_enabled_parameters" {
  description = "Input parameters for the codebuild-project-logging-enabled rule."
  type = object({
    cloudWatchGroupNames = optional(string, null)
    s3BucketNames        = optional(string, null)
  })
}

variable "codebuild_project_s3_logs_encrypted_parameters" {
  description = "Input parameters for the codebuild-project-s3-logs-encrypted rule."
  type = object({
    exemptedProjects = optional(string, null)
  })
}

variable "codedeploy_ec2_minimum_healthy_hosts_configured_parameters" {
  description = "Input parameters for the codedeploy-ec2-minimum-healthy-hosts-configured rule."
  type = object({
    minimumHealthyHostsFleetPercent = optional(number, 66)
    minimumHealthyHostsHostCount    = optional(number, 1)
  })
}

variable "codepipeline_deployment_count_check_parameters" {
  description = "Input parameters for the codepipeline-deployment-count-check rule."
  type = object({
    deploymentLimit = optional(number, null)
  })
}

variable "codepipeline_region_fanout_check_parameters" {
  description = "Input parameters for the codepipeline-region-fanout-check rule."
  type = object({
    regionFanoutFactor = optional(number, 3)
  })
}

variable "cw_loggroup_retention_period_check_parameters" {
  description = "Input parameters for the cw-loggroup-retention-period-check rule."
  type = object({
    logGroupNames    = optional(string, null)
    minRetentionTime = optional(number, null)
  })
}

variable "db_instance_backup_enabled_parameters" {
  description = "Input parameters for the db-instance-backup-enabled rule."
  type = object({
    backupRetentionMinimum = optional(number, null)
    backupRetentionPeriod  = optional(number, null)
    checkReadReplicas      = optional(bool, null)
    preferredBackupWindow  = optional(string, null)
  })
}

variable "desired_instance_tenancy_parameters" {
  description = "Input parameters for the desired-instance-tenancy rule."
  type = object({
    hostId  = optional(string, null)
    imageId = optional(string, null)
    tenancy = string
  })
}

variable "desired_instance_type_parameters" {
  description = "Input parameters for the desired-instance-type rule."
  type = object({
    instanceType = string
  })
}

variable "dynamodb_autoscaling_enabled_parameters" {
  description = "Input parameters for the dynamodb-autoscaling-enabled rule."
  type = object({
    maxProvisionedReadCapacity  = optional(number, null)
    maxProvisionedWriteCapacity = optional(number, null)
    minProvisionedReadCapacity  = optional(number, null)
    minProvisionedWriteCapacity = optional(number, null)
    targetReadUtilization       = optional(number, null)
    targetWriteUtilization      = optional(number, null)
  })
}

variable "dynamodb_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the dynamodb-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "dynamodb_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the dynamodb-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "dynamodb_table_encrypted_kms_parameters" {
  description = "Input parameters for the dynamodb-table-encrypted-kms rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "dynamodb_throughput_limit_check_parameters" {
  description = "Input parameters for the dynamodb-throughput-limit-check rule."
  type = object({
    accountRCUThresholdPercentage = optional(number, 80)
    accountWCUThresholdPercentage = optional(number, 80)
  })
}

variable "ebs_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the ebs-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "ebs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ebs-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "ec2_instance_multiple_eni_check_parameters" {
  description = "Input parameters for the ec2-instance-multiple-eni-check rule."
  type = object({
    networkInterfaceIds = optional(string, null)
  })
}

variable "ec2_instance_profile_attached_parameters" {
  description = "Input parameters for the ec2-instance-profile-attached rule."
  type = object({
    iamInstanceProfileArnList = optional(string, null)
  })
}

variable "ec2_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the ec2-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "ec2_launch_template_public_ip_disabled_parameters" {
  description = "Input parameters for the ec2-launch-template-public-ip-disabled rule."
  type = object({
    exemptedLaunchTemplates = optional(string, null)
  })
}

variable "ec2_managedinstance_applications_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-blacklisted rule."
  type = object({
    applicationNames = string
    platformType     = optional(string, null)
  })
}

variable "ec2_managedinstance_applications_required_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-required rule."
  type = object({
    applicationNames = string
    platformType     = optional(string, null)
  })
}

variable "ec2_managedinstance_inventory_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-inventory-blacklisted rule."
  type = object({
    inventoryNames = string
    platformType   = optional(string, null)
  })
}

variable "ec2_managedinstance_platform_check_parameters" {
  description = "Input parameters for the ec2-managedinstance-platform-check rule."
  type = object({
    agentVersion    = optional(string, null)
    platformName    = optional(string, null)
    platformType    = string
    platformVersion = optional(string, null)
  })
}

variable "ec2_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ec2-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "ec2_stopped_instance_parameters" {
  description = "Input parameters for the ec2-stopped-instance rule."
  type = object({
    allowedDays = optional(number, 30)
  })
}

variable "ec2_token_hop_limit_check_parameters" {
  description = "Input parameters for the ec2-token-hop-limit-check rule."
  type = object({
    tokenHopLimit = optional(number, null)
  })
}

variable "ec2_volume_inuse_check_parameters" {
  description = "Input parameters for the ec2-volume-inuse-check rule."
  type = object({
    deleteOnTermination = optional(bool, null)
  })
}

variable "ecs_fargate_latest_platform_version_parameters" {
  description = "Input parameters for the ecs-fargate-latest-platform-version rule."
  type = object({
    latestLinuxVersion   = optional(string, null)
    latestWindowsVersion = optional(string, null)
  })
}

variable "ecs_no_environment_secrets_parameters" {
  description = "Input parameters for the ecs-no-environment-secrets rule."
  type = object({
    secretKeys = string
  })
}

variable "ecs_task_definition_user_for_host_mode_check_parameters" {
  description = "Input parameters for the ecs-task-definition-user-for-host-mode-check rule."
  type = object({
    skipInactiveTaskDefinitions = optional(bool, null)
  })
}

variable "efs_access_point_enforce_root_directory_parameters" {
  description = "Input parameters for the efs-access-point-enforce-root-directory rule."
  type = object({
    approvedDirectories = optional(string, null)
  })
}

variable "efs_access_point_enforce_user_identity_parameters" {
  description = "Input parameters for the efs-access-point-enforce-user-identity rule."
  type = object({
    approvedGids = optional(string, null)
    approvedUids = optional(string, null)
  })
}

variable "efs_encrypted_check_parameters" {
  description = "Input parameters for the efs-encrypted-check rule."
  type = object({
    kmsKeyId = optional(string, null)
  })
}

variable "efs_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the efs-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "efs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the efs-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "eks_cluster_oldest_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-oldest-supported-version rule."
  type = object({
    oldestVersionSupported = string
  })
}

variable "eks_cluster_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-supported-version rule."
  type = object({
    oldestVersionSupported = string
  })
}

variable "eks_secrets_encrypted_parameters" {
  description = "Input parameters for the eks-secrets-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "elasticache_rbac_auth_enabled_parameters" {
  description = "Input parameters for the elasticache-rbac-auth-enabled rule."
  type = object({
    allowedUserGroupIDs = optional(string, null)
  })
}

variable "elasticache_redis_cluster_automatic_backup_check_parameters" {
  description = "Input parameters for the elasticache-redis-cluster-automatic-backup-check rule."
  type = object({
    snapshotRetentionPeriod = optional(number, 15)
  })
}

variable "elasticache_repl_grp_encrypted_at_rest_parameters" {
  description = "Input parameters for the elasticache-repl-grp-encrypted-at-rest rule."
  type = object({
    approvedKMSKeyIds = optional(string, null)
  })
}

variable "elasticache_supported_engine_version_parameters" {
  description = "Input parameters for the elasticache-supported-engine-version rule."
  type = object({
    latestMemcachedVersion = string
    latestRedisVersion     = string
  })
}

variable "elasticsearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the elasticsearch-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
  })
}

variable "elastic_beanstalk_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the elastic-beanstalk-logs-to-cloudwatch rule."
  type = object({
    deleteOnTerminate = optional(string, null)
    retentionInDays   = optional(string, null)
  })
}

variable "elastic_beanstalk_managed_updates_enabled_parameters" {
  description = "Input parameters for the elastic-beanstalk-managed-updates-enabled rule."
  type = object({
    updateLevel = optional(string, null)
  })
}

variable "elbv2_acm_certificate_required_parameters" {
  description = "Input parameters for the elbv2-acm-certificate-required rule."
  type = object({
    acmCertificatesAllowed = optional(string, null)
  })
}

variable "elbv2_multiple_az_parameters" {
  description = "Input parameters for the elbv2-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
}

variable "elb_custom_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-custom-security-policy-ssl-check rule."
  type = object({
    sslProtocolsAndCiphers = string
  })
}

variable "elb_logging_enabled_parameters" {
  description = "Input parameters for the elb-logging-enabled rule."
  type = object({
    s3BucketNames = optional(string, null)
  })
}

variable "elb_predefined_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-predefined-security-policy-ssl-check rule."
  type = object({
    predefinedPolicyName = string
  })
}

variable "emr_kerberos_enabled_parameters" {
  description = "Input parameters for the emr-kerberos-enabled rule."
  type = object({
    adminServer           = optional(string, null)
    domain                = optional(string, null)
    kdcServer             = optional(string, null)
    realm                 = optional(string, null)
    ticketLifetimeInHours = optional(number, null)
  })
}

variable "encrypted_volumes_parameters" {
  description = "Input parameters for the encrypted-volumes rule."
  type = object({
    kmsId = optional(string, null)
  })
}

variable "fms_shield_resource_policy_check_parameters" {
  description = "Input parameters for the fms-shield-resource-policy-check rule."
  type = object({
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    resourceTags          = optional(string, null)
    resourceTypes         = string
    webACLId              = string
  })
}

variable "fms_webacl_resource_policy_check_parameters" {
  description = "Input parameters for the fms-webacl-resource-policy-check rule."
  type = object({
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    resourceTags          = optional(string, null)
    webACLId              = string
  })
}

variable "fms_webacl_rulegroup_association_check_parameters" {
  description = "Input parameters for the fms-webacl-rulegroup-association-check rule."
  type = object({
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    ruleGroups            = string
  })
}

variable "fsx_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the fsx-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "fsx_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the fsx-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "guardduty_enabled_centralized_parameters" {
  description = "Input parameters for the guardduty-enabled-centralized rule."
  type = object({
    centralMonitoringAccount = optional(string, null)
  })
}

variable "guardduty_non_archived_findings_parameters" {
  description = "Input parameters for the guardduty-non-archived-findings rule."
  type = object({
    daysHighSev   = optional(number, 1)
    daysLowSev    = optional(number, 30)
    daysMediumSev = optional(number, 7)
  })
}

variable "iam_customer_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-customer-policy-blocked-kms-actions rule."
  type = object({
    blockedActionsPatterns          = string
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
}

variable "iam_inline_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-inline-policy-blocked-kms-actions rule."
  type = object({
    blockedActionsPatterns         = string
    excludeRoleByManagementAccount = optional(bool, null)
  })
}

variable "iam_password_policy_parameters" {
  description = "Input parameters for the iam-password-policy rule."
  type = object({
    maxPasswordAge             = optional(number, 90)
    minimumPasswordLength      = optional(number, 14)
    passwordReusePrevention    = optional(number, 24)
    requireLowercaseCharacters = optional(bool, true)
    requireNumbers             = optional(bool, true)
    requireSymbols             = optional(bool, true)
    requireUppercaseCharacters = optional(bool, true)
  })
}

variable "iam_policy_blacklisted_check_parameters" {
  description = "Input parameters for the iam-policy-blacklisted-check rule."
  type = object({
    exceptionList = optional(string, null)
    policyArns    = optional(string, "arn = aws = iam =  = aws = policy/AdministratorAccess")
  })
}

variable "iam_policy_in_use_parameters" {
  description = "Input parameters for the iam-policy-in-use rule."
  type = object({
    policyARN       = string
    policyUsageType = optional(string, null)
  })
}

variable "iam_policy_no_statements_with_admin_access_parameters" {
  description = "Input parameters for the iam-policy-no-statements-with-admin-access rule."
  type = object({
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
}

variable "iam_policy_no_statements_with_full_access_parameters" {
  description = "Input parameters for the iam-policy-no-statements-with-full-access rule."
  type = object({
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
}

variable "iam_role_managed_policy_check_parameters" {
  description = "Input parameters for the iam-role-managed-policy-check rule."
  type = object({
    managedPolicyArns = string
  })
}

variable "iam_user_group_membership_check_parameters" {
  description = "Input parameters for the iam-user-group-membership-check rule."
  type = object({
    groupNames = optional(string, null)
  })
}

variable "iam_user_unused_credentials_check_parameters" {
  description = "Input parameters for the iam-user-unused-credentials-check rule."
  type = object({
    maxCredentialUsageAge = optional(number, 90)
  })
}

variable "ec2_instances_in_vpc_parameters" {
  description = "Input parameters for the ec2-instances-in-vpc rule."
  type = object({
    vpcId = optional(string, null)
  })
}

variable "internet_gateway_authorized_vpc_only_parameters" {
  description = "Input parameters for the internet-gateway-authorized-vpc-only rule."
  type = object({
    authorizedVpcIds = optional(string, null)
  })
}

variable "kms_cmk_not_scheduled_for_deletion_parameters" {
  description = "Input parameters for the kms-cmk-not-scheduled-for-deletion rule."
  type = object({
    kmsKeyIds = optional(string, null)
  })
}

variable "lambda_concurrency_check_parameters" {
  description = "Input parameters for the lambda-concurrency-check rule."
  type = object({
    concurrencyLimitHigh = optional(string, null)
    concurrencyLimitLow  = optional(string, null)
  })
}

variable "lambda_dlq_check_parameters" {
  description = "Input parameters for the lambda-dlq-check rule."
  type = object({
    dlqArns = optional(string, null)
  })
}

variable "lambda_function_settings_check_parameters" {
  description = "Input parameters for the lambda-function-settings-check rule."
  type = object({
    memorySize = optional(number, 128)
    role       = optional(string, null)
    runtime    = string
    timeout    = optional(number, 3)
  })
}

variable "lambda_inside_vpc_parameters" {
  description = "Input parameters for the lambda-inside-vpc rule."
  type = object({
    subnetIds = optional(string, null)
  })
}

variable "lambda_vpc_multi_az_check_parameters" {
  description = "Input parameters for the lambda-vpc-multi-az-check rule."
  type = object({
    availabilityZones = optional(number, null)
  })
}

variable "multi_region_cloudtrail_enabled_parameters" {
  description = "Input parameters for the multi-region-cloudtrail-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArn = optional(string, null)
    includeManagementEvents   = optional(bool, null)
    readWriteType             = optional(string, null)
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
  })
}

variable "netfw_logging_enabled_parameters" {
  description = "Input parameters for the netfw-logging-enabled rule."
  type = object({
    logType = optional(string, null)
  })
}

variable "netfw_multi_az_enabled_parameters" {
  description = "Input parameters for the netfw-multi-az-enabled rule."
  type = object({
    availabilityZones = optional(number, null)
  })
}

variable "netfw_policy_default_action_fragment_packets_parameters" {
  description = "Input parameters for the netfw-policy-default-action-fragment-packets rule."
  type = object({
    statelessFragmentDefaultActions = string
  })
}

variable "netfw_policy_default_action_full_packets_parameters" {
  description = "Input parameters for the netfw-policy-default-action-full-packets rule."
  type = object({
    statelessDefaultActions = string
  })
}

variable "no_unrestricted_route_to_igw_parameters" {
  description = "Input parameters for the no-unrestricted-route-to-igw rule."
  type = object({
    routeTableIds = optional(string, null)
  })
}

variable "opensearch_audit_logging_enabled_parameters" {
  description = "Input parameters for the opensearch-audit-logging-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArnList = optional(string, null)
  })
}

variable "opensearch_https_required_parameters" {
  description = "Input parameters for the opensearch-https-required rule."
  type = object({
    tlsPolicies = optional(string, null)
  })
}

variable "opensearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the opensearch-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
  })
}

variable "rds_cluster_default_admin_check_parameters" {
  description = "Input parameters for the rds-cluster-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
}

variable "rds_enhanced_monitoring_enabled_parameters" {
  description = "Input parameters for the rds-enhanced-monitoring-enabled rule."
  type = object({
    monitoringInterval = optional(number, null)
  })
}

variable "rds_instance_default_admin_check_parameters" {
  description = "Input parameters for the rds-instance-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
}

variable "rds_instance_deletion_protection_enabled_parameters" {
  description = "Input parameters for the rds-instance-deletion-protection-enabled rule."
  type = object({
    databaseEngines = optional(string, null)
  })
}

variable "rds_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the rds-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "rds_logging_enabled_parameters" {
  description = "Input parameters for the rds-logging-enabled rule."
  type = object({
    additionalLogs = optional(string, null)
  })
}

variable "rds_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the rds-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "rds_storage_encrypted_parameters" {
  description = "Input parameters for the rds-storage-encrypted rule."
  type = object({
    kmsKeyId = optional(string, null)
  })
}

variable "redshift_audit_logging_enabled_parameters" {
  description = "Input parameters for the redshift-audit-logging-enabled rule."
  type = object({
    bucketNames = optional(string, null)
  })
}

variable "redshift_backup_enabled_parameters" {
  description = "Input parameters for the redshift-backup-enabled rule."
  type = object({
    maxRetentionPeriod = optional(number, null)
    minRetentionPeriod = optional(number, null)
  })
}

variable "redshift_cluster_configuration_check_parameters" {
  description = "Input parameters for the redshift-cluster-configuration-check rule."
  type = object({
    clusterDbEncrypted = optional(bool, true)
    loggingEnabled     = optional(bool, true)
    nodeTypes          = optional(string, "dc1.large")
  })
}

variable "redshift_cluster_kms_enabled_parameters" {
  description = "Input parameters for the redshift-cluster-kms-enabled rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "redshift_cluster_maintenancesettings_check_parameters" {
  description = "Input parameters for the redshift-cluster-maintenancesettings-check rule."
  type = object({
    allowVersionUpgrade              = optional(bool, true)
    automatedSnapshotRetentionPeriod = optional(number, 1)
    preferredMaintenanceWindow       = optional(string, null)
  })
}

variable "redshift_default_admin_check_parameters" {
  description = "Input parameters for the redshift-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
}

variable "redshift_default_db_name_check_parameters" {
  description = "Input parameters for the redshift-default-db-name-check rule."
  type = object({
    validDatabaseNames = optional(string, null)
  })
}

variable "required_tags_parameters" {
  description = "Input parameters for the required-tags rule."
  type = object({
    tag1Key   = optional(string, "CostCenter")
    tag1Value = optional(string, null)
    tag2Key   = optional(string, null)
    tag2Value = optional(string, null)
    tag3Key   = optional(string, null)
    tag3Value = optional(string, null)
    tag4Key   = optional(string, null)
    tag4Value = optional(string, null)
    tag5Key   = optional(string, null)
    tag5Value = optional(string, null)
    tag6Key   = optional(string, null)
    tag6Value = optional(string, null)
  })
}

variable "restricted_common_ports_parameters" {
  description = "Input parameters for the restricted-common-ports rule."
  type = object({
    blockedPort1 = optional(number, 20)
    blockedPort2 = optional(number, 21)
    blockedPort3 = optional(number, 3389)
    blockedPort4 = optional(number, 3306)
    blockedPort5 = optional(number, 4333)
  })
}

variable "s3_account_level_public_access_blocks_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks rule."
  type = object({
    blockPublicAcls       = optional(string, "True")
    blockPublicPolicy     = optional(string, "True")
    ignorePublicAcls      = optional(string, "True")
    restrictPublicBuckets = optional(string, "True")
  })
}

variable "s3_account_level_public_access_blocks_periodic_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks-periodic rule."
  type = object({
    blockPublicAcls       = optional(string, null)
    blockPublicPolicy     = optional(string, null)
    ignorePublicAcls      = optional(string, null)
    restrictPublicBuckets = optional(string, null)
  })
}

variable "s3_bucket_blacklisted_actions_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-blacklisted-actions-prohibited rule."
  type = object({
    blacklistedActionPattern = string
  })
}

variable "s3_bucket_default_lock_enabled_parameters" {
  description = "Input parameters for the s3-bucket-default-lock-enabled rule."
  type = object({
    mode = optional(string, null)
  })
}

variable "s3_bucket_level_public_access_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-level-public-access-prohibited rule."
  type = object({
    excludedPublicBuckets = optional(string, null)
  })
}

variable "s3_bucket_logging_enabled_parameters" {
  description = "Input parameters for the s3-bucket-logging-enabled rule."
  type = object({
    targetBucket = optional(string, null)
    targetPrefix = optional(string, null)
  })
}

variable "s3_bucket_policy_grantee_check_parameters" {
  description = "Input parameters for the s3-bucket-policy-grantee-check rule."
  type = object({
    awsPrincipals     = optional(string, null)
    federatedUsers    = optional(string, null)
    ipAddresses       = optional(string, null)
    servicePrincipals = optional(string, null)
    vpcIds            = optional(string, null)
  })
}

variable "s3_bucket_policy_not_more_permissive_parameters" {
  description = "Input parameters for the s3-bucket-policy-not-more-permissive rule."
  type = object({
    controlPolicy = string
  })
}

variable "s3_bucket_replication_enabled_parameters" {
  description = "Input parameters for the s3-bucket-replication-enabled rule."
  type = object({
    replicationType = optional(string, null)
  })
}

variable "s3_bucket_versioning_enabled_parameters" {
  description = "Input parameters for the s3-bucket-versioning-enabled rule."
  type = object({
    isMfaDeleteEnabled = optional(string, null)
  })
}

variable "s3_default_encryption_kms_parameters" {
  description = "Input parameters for the s3-default-encryption-kms rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "s3_event_notifications_enabled_parameters" {
  description = "Input parameters for the s3-event-notifications-enabled rule."
  type = object({
    destinationArn = optional(string, null)
    eventTypes     = optional(string, null)
  })
}

variable "s3_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the s3-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "s3_lifecycle_policy_check_parameters" {
  description = "Input parameters for the s3-lifecycle-policy-check rule."
  type = object({
    bucketNames                  = optional(string, null)
    targetExpirationDays         = optional(number, null)
    targetPrefix                 = optional(string, null)
    targetTransitionDays         = optional(number, null)
    targetTransitionStorageClass = optional(string, null)
  })
}

variable "s3_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the s3-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "s3_version_lifecycle_policy_check_parameters" {
  description = "Input parameters for the s3-version-lifecycle-policy-check rule."
  type = object({
    bucketNames = optional(string, null)
  })
}

variable "sagemaker_endpoint_configuration_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-endpoint-configuration-kms-key-configured rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "sagemaker_notebook_instance_inside_vpc_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-inside-vpc rule."
  type = object({
    subnetIds = optional(string, null)
  })
}

variable "sagemaker_notebook_instance_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-kms-key-configured rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "secretsmanager_rotation_enabled_check_parameters" {
  description = "Input parameters for the secretsmanager-rotation-enabled-check rule."
  type = object({
    maximumAllowedRotationFrequency        = optional(number, null)
    maximumAllowedRotationFrequencyInHours = optional(number, null)
  })
}

variable "secretsmanager_secret_periodic_rotation_parameters" {
  description = "Input parameters for the secretsmanager-secret-periodic-rotation rule."
  type = object({
    maxDaysSinceRotation = optional(number, null)
  })
}

variable "secretsmanager_secret_unused_parameters" {
  description = "Input parameters for the secretsmanager-secret-unused rule."
  type = object({
    unusedForDays = optional(number, null)
  })
}

variable "secretsmanager_using_cmk_parameters" {
  description = "Input parameters for the secretsmanager-using-cmk rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
}

variable "service_vpc_endpoint_enabled_parameters" {
  description = "Input parameters for the service-vpc-endpoint-enabled rule."
  type = object({
    serviceName = string
  })
}

variable "sns_encrypted_kms_parameters" {
  description = "Input parameters for the sns-encrypted-kms rule."
  type = object({
    kmsKeyIds = optional(string, null)
  })
}

variable "step_functions_state_machine_logging_enabled_parameters" {
  description = "Input parameters for the step-functions-state-machine-logging-enabled rule."
  type = object({
    cloudWatchLogGroupArns = optional(string, null)
    logLevel               = optional(string, null)
  })
}

variable "storagegateway_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the storagegateway-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "storagegateway_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the storagegateway-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "virtualmachine_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the virtualmachine-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
}

variable "virtualmachine_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the virtualmachine-resources-protected-by-backup-plan rule."
  type = object({
    backupVaultLockCheck = optional(string, null)
    crossAccountList     = optional(string, null)
    crossRegionList      = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    resourceId           = optional(string, null)
    resourceTags         = optional(string, null)
  })
}

variable "vpc_flow_logs_enabled_parameters" {
  description = "Input parameters for the vpc-flow-logs-enabled rule."
  type = object({
    trafficType = optional(string, null)
  })
}

variable "vpc_peering_dns_resolution_check_parameters" {
  description = "Input parameters for the vpc-peering-dns-resolution-check rule."
  type = object({
    vpcIds = optional(string, null)
  })
}

variable "vpc_sg_open_only_to_authorized_ports_parameters" {
  description = "Input parameters for the vpc-sg-open-only-to-authorized-ports rule."
  type = object({
    authorizedTcpPorts = optional(string, null)
    authorizedUdpPorts = optional(string, null)
  })
}

variable "wafv2_logging_enabled_parameters" {
  description = "Input parameters for the wafv2-logging-enabled rule."
  type = object({
    kinesisFirehoseDeliveryStreamArns = optional(string, null)
  })
}

variable "waf_classic_logging_enabled_parameters" {
  description = "Input parameters for the waf-classic-logging-enabled rule."
  type = object({
    kinesisFirehoseDeliveryStreamArns = optional(string, null)
  })
}
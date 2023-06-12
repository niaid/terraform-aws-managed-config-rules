variable "access_keys_rotated_parameters" {
  description = "Input parameters for the access-keys-rotated rule."
  type = object({
    maxAccessKeyAge = optional(number, 90)
  })
  default = {
    maxAccessKeyAge = 90
  }

}

variable "account_part_of_organizations_parameters" {
  description = "Input parameters for the account-part-of-organizations rule."
  type = object({
    MasterAccountId = optional(string, null)
  })
  default = {}
}

variable "acm_certificate_expiration_check_parameters" {
  description = "Input parameters for the acm-certificate-expiration-check rule."
  type = object({
    daysToExpiration = optional(number, 14)
  })
  default = {
    daysToExpiration = 14
  }

}

variable "alb_desync_mode_check_parameters" {
  description = "Input parameters for the alb-desync-mode-check rule."
  type = object({
    desyncMode = optional(string, null)
  })
  default = {}
}

variable "alb_waf_enabled_parameters" {
  description = "Input parameters for the alb-waf-enabled rule."
  type = object({
    wafWebAclIds = optional(string, null)
  })
  default = {}
}

variable "api_gwv2_authorization_type_configured_parameters" {
  description = "Input parameters for the api-gwv2-authorization-type-configured rule."
  type = object({
    authorizationType = optional(string, null)
  })
  default = {}
}

variable "api_gw_associated_with_waf_parameters" {
  description = "Input parameters for the api-gw-associated-with-waf rule."
  type = object({
    WebAclArns = optional(string, null)
  })
  default = {}
}

variable "api_gw_endpoint_type_check_parameters" {
  description = "Input parameters for the api-gw-endpoint-type-check rule."
  type = object({
    endpointConfigurationTypes = optional(string, null)
  })
  default = {}
}

variable "api_gw_execution_logging_enabled_parameters" {
  description = "Input parameters for the api-gw-execution-logging-enabled rule."
  type = object({
    loggingLevel = optional(string, "ERROR,INFO")
  })
  default = {
    loggingLevel = "ERROR,INFO"
  }

}

variable "api_gw_ssl_enabled_parameters" {
  description = "Input parameters for the api-gw-ssl-enabled rule."
  type = object({
    CertificateIDs = optional(string, null)
  })
  default = {}
}

variable "approved_amis_by_id_parameters" {
  description = "Input parameters for the approved-amis-by-id rule."
  type = object({
    amiIds = optional(string, null)
  })
  default = {}
}

variable "approved_amis_by_tag_parameters" {
  description = "Input parameters for the approved-amis-by-tag rule."
  type = object({
    amisByTagKeyAndValue = optional(string, "tag-key = tag-value,other-tag-key")
  })
  default = {
    amisByTagKeyAndValue = "tag-key:tag-value,other-tag-key"
  }

}

variable "appsync_associated_with_waf_parameters" {
  description = "Input parameters for the appsync-associated-with-waf rule."
  type = object({
    wafWebAclARNs = optional(string, null)
  })
  default = {}
}

variable "appsync_logging_enabled_parameters" {
  description = "Input parameters for the appsync-logging-enabled rule."
  type = object({
    fieldLoggingLevel = optional(string, null)
  })
  default = {}
}

variable "aurora_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the aurora-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

}

variable "aurora_mysql_backtracking_enabled_parameters" {
  description = "Input parameters for the aurora-mysql-backtracking-enabled rule."
  type = object({
    BacktrackWindowInHours = optional(number, null)
  })
  default = {}
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
  default = {}
}

variable "autoscaling_multiple_az_parameters" {
  description = "Input parameters for the autoscaling-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
  default = {}
}

variable "backup_plan_min_frequency_and_min_retention_check_parameters" {
  description = "Input parameters for the backup-plan-min-frequency-and-min-retention-check rule."
  type = object({
    requiredFrequencyUnit  = optional(string, "days")
    requiredFrequencyValue = optional(number, 1)
    requiredRetentionDays  = optional(number, 35)
  })
  default = {
    requiredFrequencyUnit  = "days"
    requiredFrequencyValue = 1
    requiredRetentionDays  = 35
  }

}

variable "backup_recovery_point_manual_deletion_disabled_parameters" {
  description = "Input parameters for the backup-recovery-point-manual-deletion-disabled rule."
  type = object({
    principalArnList = optional(string, null)
  })
  default = {}
}

variable "backup_recovery_point_minimum_retention_check_parameters" {
  description = "Input parameters for the backup-recovery-point-minimum-retention-check rule."
  type = object({
    requiredRetentionDays = optional(number, 35)
  })
  default = {
    requiredRetentionDays = 35
  }

}

variable "clb_desync_mode_check_parameters" {
  description = "Input parameters for the clb-desync-mode-check rule."
  type = object({
    desyncMode = optional(string, null)
  })
  default = {}
}

variable "clb_multiple_az_parameters" {
  description = "Input parameters for the clb-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
  default = {}
}

variable "cloudformation_stack_drift_detection_check_parameters" {
  description = "Input parameters for the cloudformation-stack-drift-detection-check rule."
  type = object({
    cloudformationRoleArn = optional(string, null)
  })
  default = {}
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
  default = {}
}

variable "cloudfront_accesslogs_enabled_parameters" {
  description = "Input parameters for the cloudfront-accesslogs-enabled rule."
  type = object({
    S3BucketName = optional(string, null)
  })
  default = {}
}

variable "cloudfront_associated_with_waf_parameters" {
  description = "Input parameters for the cloudfront-associated-with-waf rule."
  type = object({
    wafWebAclIds = optional(string, null)
  })
  default = {}
}

variable "cloudtrail_s3_dataevents_enabled_parameters" {
  description = "Input parameters for the cloudtrail-s3-dataevents-enabled rule."
  type = object({
    S3BucketNames = optional(string, null)
  })
  default = {}
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
  default = {
    alarmActionRequired            = "true"
    insufficientDataActionRequired = "true"
    okActionRequired               = "false"
  }

}

variable "cloudwatch_alarm_resource_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-resource-check rule."
  type = object({
    metricName   = optional(string, null)
    resourceType = optional(string, null)
  })
  default = {}
}

variable "cloudwatch_alarm_settings_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-settings-check rule."
  type = object({
    comparisonOperator = optional(string, null)
    evaluationPeriods  = optional(number, null)
    metricName         = optional(string, null)
    period             = optional(number, 300)
    statistic          = optional(string, null)
    threshold          = optional(number, null)
  })
  default = {
    period = 300
  }

}

variable "cloudwatch_log_group_encrypted_parameters" {
  description = "Input parameters for the cloudwatch-log-group-encrypted rule."
  type = object({
    KmsKeyId = optional(string, null)
  })
  default = {}
}

variable "cloud_trail_cloud_watch_logs_enabled_parameters" {
  description = "Input parameters for the cloud-trail-cloud-watch-logs-enabled rule."
  type = object({
    expectedDeliveryWindowAge = optional(number, null)
  })
  default = {}
}

variable "cloud_trail_enabled_parameters" {
  description = "Input parameters for the cloud-trail-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArn = optional(string, null)
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
  })
  default = {}
}

variable "codebuild_project_environment_privileged_check_parameters" {
  description = "Input parameters for the codebuild-project-environment-privileged-check rule."
  type = object({
    exemptedProjects = optional(string, null)
  })
  default = {}
}

variable "codebuild_project_logging_enabled_parameters" {
  description = "Input parameters for the codebuild-project-logging-enabled rule."
  type = object({
    cloudWatchGroupNames = optional(string, null)
    s3BucketNames        = optional(string, null)
  })
  default = {}
}

variable "codebuild_project_s3_logs_encrypted_parameters" {
  description = "Input parameters for the codebuild-project-s3-logs-encrypted rule."
  type = object({
    exemptedProjects = optional(string, null)
  })
  default = {}
}

variable "codedeploy_ec2_minimum_healthy_hosts_configured_parameters" {
  description = "Input parameters for the codedeploy-ec2-minimum-healthy-hosts-configured rule."
  type = object({
    minimumHealthyHostsFleetPercent = optional(number, 66)
    minimumHealthyHostsHostCount    = optional(number, 1)
  })
  default = {
    minimumHealthyHostsFleetPercent = 66
    minimumHealthyHostsHostCount    = 1
  }

}

variable "codepipeline_deployment_count_check_parameters" {
  description = "Input parameters for the codepipeline-deployment-count-check rule."
  type = object({
    deploymentLimit = optional(number, null)
  })
  default = {}
}

variable "codepipeline_region_fanout_check_parameters" {
  description = "Input parameters for the codepipeline-region-fanout-check rule."
  type = object({
    regionFanoutFactor = optional(number, 3)
  })
  default = {
    regionFanoutFactor = 3
  }

}

variable "cw_loggroup_retention_period_check_parameters" {
  description = "Input parameters for the cw-loggroup-retention-period-check rule."
  type = object({
    LogGroupNames    = optional(string, null)
    MinRetentionTime = optional(number, null)
  })
  default = {}
}

variable "db_instance_backup_enabled_parameters" {
  description = "Input parameters for the db-instance-backup-enabled rule."
  type = object({
    backupRetentionMinimum = optional(number, null)
    backupRetentionPeriod  = optional(number, null)
    checkReadReplicas      = optional(bool, null)
    preferredBackupWindow  = optional(string, null)
  })
  default = {}
}

variable "desired_instance_tenancy_parameters" {
  description = "Input parameters for the desired-instance-tenancy rule."
  type = object({
    hostId  = optional(string, null)
    imageId = optional(string, null)
    tenancy = optional(string, null)
  })
  default = {}
}

variable "desired_instance_type_parameters" {
  description = "Input parameters for the desired-instance-type rule."
  type = object({
    instanceType = optional(string, null)
  })
  default = {}
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
  default = {}
}

variable "dynamodb_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the dynamodb-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "dynamodb_table_encrypted_kms_parameters" {
  description = "Input parameters for the dynamodb-table-encrypted-kms rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "dynamodb_throughput_limit_check_parameters" {
  description = "Input parameters for the dynamodb-throughput-limit-check rule."
  type = object({
    accountRCUThresholdPercentage = optional(number, 80)
    accountWCUThresholdPercentage = optional(number, 80)
  })
  default = {
    accountRCUThresholdPercentage = 80
    accountWCUThresholdPercentage = 80
  }

}

variable "ebs_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the ebs-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "ec2_instance_multiple_eni_check_parameters" {
  description = "Input parameters for the ec2-instance-multiple-eni-check rule."
  type = object({
    NetworkInterfaceIds = optional(string, null)
  })
  default = {}
}

variable "ec2_instance_profile_attached_parameters" {
  description = "Input parameters for the ec2-instance-profile-attached rule."
  type = object({
    IamInstanceProfileArnList = optional(string, null)
  })
  default = {}
}

variable "ec2_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the ec2-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

}

variable "ec2_launch_template_public_ip_disabled_parameters" {
  description = "Input parameters for the ec2-launch-template-public-ip-disabled rule."
  type = object({
    exemptedLaunchTemplates = optional(string, null)
  })
  default = {}
}

variable "ec2_managedinstance_applications_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-blacklisted rule."
  type = object({
    applicationNames = optional(string, null)
    platformType     = optional(string, null)
  })
  default = {}
}

variable "ec2_managedinstance_applications_required_parameters" {
  description = "Input parameters for the ec2-managedinstance-applications-required rule."
  type = object({
    applicationNames = optional(string, null)
    platformType     = optional(string, null)
  })
  default = {}
}

variable "ec2_managedinstance_inventory_blacklisted_parameters" {
  description = "Input parameters for the ec2-managedinstance-inventory-blacklisted rule."
  type = object({
    inventoryNames = optional(string, null)
    platformType   = optional(string, null)
  })
  default = {}
}

variable "ec2_managedinstance_platform_check_parameters" {
  description = "Input parameters for the ec2-managedinstance-platform-check rule."
  type = object({
    agentVersion    = optional(string, null)
    platformName    = optional(string, null)
    platformType    = optional(string, null)
    platformVersion = optional(string, null)
  })
  default = {}
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
  default = {}
}

variable "ec2_stopped_instance_parameters" {
  description = "Input parameters for the ec2-stopped-instance rule."
  type = object({
    AllowedDays = optional(number, 30)
  })
  default = {
    AllowedDays = 30
  }

}

variable "ec2_token_hop_limit_check_parameters" {
  description = "Input parameters for the ec2-token-hop-limit-check rule."
  type = object({
    tokenHopLimit = optional(number, null)
  })
  default = {}
}

variable "ec2_volume_inuse_check_parameters" {
  description = "Input parameters for the ec2-volume-inuse-check rule."
  type = object({
    deleteOnTermination = optional(bool, null)
  })
  default = {}
}

variable "ecs_fargate_latest_platform_version_parameters" {
  description = "Input parameters for the ecs-fargate-latest-platform-version rule."
  type = object({
    latestLinuxVersion   = optional(string, null)
    latestWindowsVersion = optional(string, null)
  })
  default = {}
}

variable "ecs_no_environment_secrets_parameters" {
  description = "Input parameters for the ecs-no-environment-secrets rule."
  type = object({
    secretKeys = optional(string, null)
  })
  default = {}
}

variable "ecs_task_definition_user_for_host_mode_check_parameters" {
  description = "Input parameters for the ecs-task-definition-user-for-host-mode-check rule."
  type = object({
    SkipInactiveTaskDefinitions = optional(bool, null)
  })
  default = {}
}

variable "efs_access_point_enforce_root_directory_parameters" {
  description = "Input parameters for the efs-access-point-enforce-root-directory rule."
  type = object({
    approvedDirectories = optional(string, null)
  })
  default = {}
}

variable "efs_access_point_enforce_user_identity_parameters" {
  description = "Input parameters for the efs-access-point-enforce-user-identity rule."
  type = object({
    approvedGids = optional(string, null)
    approvedUids = optional(string, null)
  })
  default = {}
}

variable "efs_encrypted_check_parameters" {
  description = "Input parameters for the efs-encrypted-check rule."
  type = object({
    KmsKeyId = optional(string, null)
  })
  default = {}
}

variable "efs_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the efs-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "eks_cluster_oldest_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-oldest-supported-version rule."
  type = object({
    oldestVersionSupported = optional(string, null)
  })
  default = {}
}

variable "eks_cluster_supported_version_parameters" {
  description = "Input parameters for the eks-cluster-supported-version rule."
  type = object({
    oldestVersionSupported = optional(string, null)
  })
  default = {}
}

variable "eks_secrets_encrypted_parameters" {
  description = "Input parameters for the eks-secrets-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "elasticache_rbac_auth_enabled_parameters" {
  description = "Input parameters for the elasticache-rbac-auth-enabled rule."
  type = object({
    allowedUserGroupIDs = optional(string, null)
  })
  default = {}
}

variable "elasticache_redis_cluster_automatic_backup_check_parameters" {
  description = "Input parameters for the elasticache-redis-cluster-automatic-backup-check rule."
  type = object({
    snapshotRetentionPeriod = optional(number, 15)
  })
  default = {
    snapshotRetentionPeriod = 15
  }

}

variable "elasticache_repl_grp_encrypted_at_rest_parameters" {
  description = "Input parameters for the elasticache-repl-grp-encrypted-at-rest rule."
  type = object({
    approvedKMSKeyIds = optional(string, null)
  })
  default = {}
}

variable "elasticache_supported_engine_version_parameters" {
  description = "Input parameters for the elasticache-supported-engine-version rule."
  type = object({
    latestMemcachedVersion = optional(string, null)
    latestRedisVersion     = optional(string, null)
  })
  default = {}
}

variable "elasticsearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the elasticsearch-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
  })
  default = {}
}

variable "elastic_beanstalk_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the elastic-beanstalk-logs-to-cloudwatch rule."
  type = object({
    DeleteOnTerminate = optional(string, null)
    RetentionInDays   = optional(string, null)
  })
  default = {}
}

variable "elastic_beanstalk_managed_updates_enabled_parameters" {
  description = "Input parameters for the elastic-beanstalk-managed-updates-enabled rule."
  type = object({
    UpdateLevel = optional(string, null)
  })
  default = {}
}

variable "elbv2_acm_certificate_required_parameters" {
  description = "Input parameters for the elbv2-acm-certificate-required rule."
  type = object({
    AcmCertificatesAllowed = optional(string, null)
  })
  default = {}
}

variable "elbv2_multiple_az_parameters" {
  description = "Input parameters for the elbv2-multiple-az rule."
  type = object({
    minAvailabilityZones = optional(number, null)
  })
  default = {}
}

variable "elb_custom_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-custom-security-policy-ssl-check rule."
  type = object({
    sslProtocolsAndCiphers = optional(string, null)
  })
  default = {}
}

variable "elb_logging_enabled_parameters" {
  description = "Input parameters for the elb-logging-enabled rule."
  type = object({
    s3BucketNames = optional(string, null)
  })
  default = {}
}

variable "elb_predefined_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elb-predefined-security-policy-ssl-check rule."
  type = object({
    predefinedPolicyName = optional(string, null)
  })
  default = {}
}

variable "emr_kerberos_enabled_parameters" {
  description = "Input parameters for the emr-kerberos-enabled rule."
  type = object({
    AdminServer           = optional(string, null)
    Domain                = optional(string, null)
    KdcServer             = optional(string, null)
    Realm                 = optional(string, null)
    TicketLifetimeInHours = optional(number, null)
  })
  default = {}
}

variable "encrypted_volumes_parameters" {
  description = "Input parameters for the encrypted-volumes rule."
  type = object({
    kmsId = optional(string, null)
  })
  default = {}
}

variable "fms_shield_resource_policy_check_parameters" {
  description = "Input parameters for the fms-shield-resource-policy-check rule."
  type = object({
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    resourceTags          = optional(string, null)
    resourceTypes         = optional(string, null)
    webACLId              = optional(string, null)
  })
  default = {}
}

variable "fms_webacl_resource_policy_check_parameters" {
  description = "Input parameters for the fms-webacl-resource-policy-check rule."
  type = object({
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    resourceTags          = optional(string, null)
    webACLId              = optional(string, null)
  })
  default = {}
}

variable "fms_webacl_rulegroup_association_check_parameters" {
  description = "Input parameters for the fms-webacl-rulegroup-association-check rule."
  type = object({
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
    ruleGroups            = optional(string, null)
  })
  default = {}
}

variable "fsx_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the fsx-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "guardduty_enabled_centralized_parameters" {
  description = "Input parameters for the guardduty-enabled-centralized rule."
  type = object({
    CentralMonitoringAccount = optional(string, null)
  })
  default = {}
}

variable "guardduty_non_archived_findings_parameters" {
  description = "Input parameters for the guardduty-non-archived-findings rule."
  type = object({
    daysHighSev   = optional(number, 1)
    daysLowSev    = optional(number, 30)
    daysMediumSev = optional(number, 7)
  })
  default = {
    daysHighSev   = 1
    daysLowSev    = 30
    daysMediumSev = 7
  }

}

variable "iam_customer_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-customer-policy-blocked-kms-actions rule."
  type = object({
    blockedActionsPatterns          = optional(string, null)
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
  default = {}
}

variable "iam_inline_policy_blocked_kms_actions_parameters" {
  description = "Input parameters for the iam-inline-policy-blocked-kms-actions rule."
  type = object({
    blockedActionsPatterns         = optional(string, null)
    excludeRoleByManagementAccount = optional(bool, null)
  })
  default = {}
}

variable "iam_password_policy_parameters" {
  description = "Input parameters for the iam-password-policy rule."
  type = object({
    MaxPasswordAge             = optional(number, 90)
    MinimumPasswordLength      = optional(number, 14)
    PasswordReusePrevention    = optional(number, 24)
    RequireLowercaseCharacters = optional(bool, true)
    RequireNumbers             = optional(bool, true)
    RequireSymbols             = optional(bool, true)
    RequireUppercaseCharacters = optional(bool, true)
  })
  default = {
    MaxPasswordAge             = 90
    MinimumPasswordLength      = 14
    PasswordReusePrevention    = 24
    RequireLowercaseCharacters = true
    RequireNumbers             = true
    RequireSymbols             = true
    RequireUppercaseCharacters = true
  }

}

variable "iam_policy_blacklisted_check_parameters" {
  description = "Input parameters for the iam-policy-blacklisted-check rule."
  type = object({
    exceptionList = optional(string, null)
    policyArns    = optional(string, "arn = aws = iam =  = aws = policy/AdministratorAccess")
  })
  default = {
    policyArns = "arn:aws:iam::aws:policy/AdministratorAccess"
  }

}

variable "iam_policy_in_use_parameters" {
  description = "Input parameters for the iam-policy-in-use rule."
  type = object({
    policyARN       = optional(string, null)
    policyUsageType = optional(string, null)
  })
  default = {}
}

variable "iam_policy_no_statements_with_admin_access_parameters" {
  description = "Input parameters for the iam-policy-no-statements-with-admin-access rule."
  type = object({
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
  default = {}
}

variable "iam_policy_no_statements_with_full_access_parameters" {
  description = "Input parameters for the iam-policy-no-statements-with-full-access rule."
  type = object({
    excludePermissionBoundaryPolicy = optional(bool, null)
  })
  default = {}
}

variable "iam_role_managed_policy_check_parameters" {
  description = "Input parameters for the iam-role-managed-policy-check rule."
  type = object({
    managedPolicyArns = optional(string, null)
  })
  default = {}
}

variable "iam_user_group_membership_check_parameters" {
  description = "Input parameters for the iam-user-group-membership-check rule."
  type = object({
    groupNames = optional(string, null)
  })
  default = {}
}

variable "iam_user_unused_credentials_check_parameters" {
  description = "Input parameters for the iam-user-unused-credentials-check rule."
  type = object({
    maxCredentialUsageAge = optional(number, 90)
  })
  default = {
    maxCredentialUsageAge = 90
  }

}

variable "instances_in_vpc_parameters" {
  description = "Input parameters for the instances-in-vpc rule."
  type = object({
    vpcId = optional(string, null)
  })
  default = {}
}

variable "internet_gateway_authorized_vpc_only_parameters" {
  description = "Input parameters for the internet-gateway-authorized-vpc-only rule."
  type = object({
    AuthorizedVpcIds = optional(string, null)
  })
  default = {}
}

variable "kms_cmk_not_scheduled_for_deletion_parameters" {
  description = "Input parameters for the kms-cmk-not-scheduled-for-deletion rule."
  type = object({
    kmsKeyIds = optional(string, null)
  })
  default = {}
}

variable "lambda_concurrency_check_parameters" {
  description = "Input parameters for the lambda-concurrency-check rule."
  type = object({
    ConcurrencyLimitHigh = optional(string, null)
    ConcurrencyLimitLow  = optional(string, null)
  })
  default = {}
}

variable "lambda_dlq_check_parameters" {
  description = "Input parameters for the lambda-dlq-check rule."
  type = object({
    dlqArns = optional(string, null)
  })
  default = {}
}

variable "lambda_function_settings_check_parameters" {
  description = "Input parameters for the lambda-function-settings-check rule."
  type = object({
    memorySize = optional(number, 128)
    role       = optional(string, null)
    runtime    = optional(string, null)
    timeout    = optional(number, 3)
  })
  default = {
    memorySize = 128
    timeout    = 3
  }

}

variable "lambda_inside_vpc_parameters" {
  description = "Input parameters for the lambda-inside-vpc rule."
  type = object({
    subnetIds = optional(string, null)
  })
  default = {}
}

variable "lambda_vpc_multi_az_check_parameters" {
  description = "Input parameters for the lambda-vpc-multi-az-check rule."
  type = object({
    availabilityZones = optional(number, null)
  })
  default = {}
}

variable "multi_region_cloud_trail_enabled_parameters" {
  description = "Input parameters for the multi-region-cloud-trail-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArn = optional(string, null)
    includeManagementEvents   = optional(bool, null)
    readWriteType             = optional(string, null)
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
  })
  default = {}
}

variable "netfw_logging_enabled_parameters" {
  description = "Input parameters for the netfw-logging-enabled rule."
  type = object({
    logType = optional(string, null)
  })
  default = {}
}

variable "netfw_multi_az_enabled_parameters" {
  description = "Input parameters for the netfw-multi-az-enabled rule."
  type = object({
    availabilityZones = optional(number, null)
  })
  default = {}
}

variable "netfw_policy_default_action_fragment_packets_parameters" {
  description = "Input parameters for the netfw-policy-default-action-fragment-packets rule."
  type = object({
    statelessFragmentDefaultActions = optional(string, null)
  })
  default = {}
}

variable "netfw_policy_default_action_full_packets_parameters" {
  description = "Input parameters for the netfw-policy-default-action-full-packets rule."
  type = object({
    statelessDefaultActions = optional(string, null)
  })
  default = {}
}

variable "no_unrestricted_route_to_igw_parameters" {
  description = "Input parameters for the no-unrestricted-route-to-igw rule."
  type = object({
    routeTableIds = optional(string, null)
  })
  default = {}
}

variable "opensearch_audit_logging_enabled_parameters" {
  description = "Input parameters for the opensearch-audit-logging-enabled rule."
  type = object({
    cloudWatchLogsLogGroupArnList = optional(string, null)
  })
  default = {}
}

variable "opensearch_https_required_parameters" {
  description = "Input parameters for the opensearch-https-required rule."
  type = object({
    tlsPolicies = optional(string, null)
  })
  default = {}
}

variable "opensearch_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the opensearch-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
  })
  default = {}
}

variable "rds_cluster_default_admin_check_parameters" {
  description = "Input parameters for the rds-cluster-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
  default = {}
}

variable "rds_enhanced_monitoring_enabled_parameters" {
  description = "Input parameters for the rds-enhanced-monitoring-enabled rule."
  type = object({
    monitoringInterval = optional(number, null)
  })
  default = {}
}

variable "rds_instance_default_admin_check_parameters" {
  description = "Input parameters for the rds-instance-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
  default = {}
}

variable "rds_instance_deletion_protection_enabled_parameters" {
  description = "Input parameters for the rds-instance-deletion-protection-enabled rule."
  type = object({
    databaseEngines = optional(string, null)
  })
  default = {}
}

variable "rds_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the rds-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

}

variable "rds_logging_enabled_parameters" {
  description = "Input parameters for the rds-logging-enabled rule."
  type = object({
    additionalLogs = optional(string, null)
  })
  default = {}
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
  default = {}
}

variable "rds_storage_encrypted_parameters" {
  description = "Input parameters for the rds-storage-encrypted rule."
  type = object({
    kmsKeyId = optional(string, null)
  })
  default = {}
}

variable "redshift_audit_logging_enabled_parameters" {
  description = "Input parameters for the redshift-audit-logging-enabled rule."
  type = object({
    bucketNames = optional(string, null)
  })
  default = {}
}

variable "redshift_backup_enabled_parameters" {
  description = "Input parameters for the redshift-backup-enabled rule."
  type = object({
    MaxRetentionPeriod = optional(number, null)
    MinRetentionPeriod = optional(number, null)
  })
  default = {}
}

variable "redshift_cluster_configuration_check_parameters" {
  description = "Input parameters for the redshift-cluster-configuration-check rule."
  type = object({
    clusterDbEncrypted = optional(bool, true)
    loggingEnabled     = optional(bool, true)
    nodeTypes          = optional(string, "dc1.large")
  })
  default = {
    clusterDbEncrypted = true
    loggingEnabled     = true
    nodeTypes          = "dc1.large"
  }

}

variable "redshift_cluster_kms_enabled_parameters" {
  description = "Input parameters for the redshift-cluster-kms-enabled rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "redshift_cluster_maintenancesettings_check_parameters" {
  description = "Input parameters for the redshift-cluster-maintenancesettings-check rule."
  type = object({
    allowVersionUpgrade              = optional(bool, true)
    automatedSnapshotRetentionPeriod = optional(number, 1)
    preferredMaintenanceWindow       = optional(string, null)
  })
  default = {
    allowVersionUpgrade              = true
    automatedSnapshotRetentionPeriod = 1
  }

}

variable "redshift_default_admin_check_parameters" {
  description = "Input parameters for the redshift-default-admin-check rule."
  type = object({
    validAdminUserNames = optional(string, null)
  })
  default = {}
}

variable "redshift_default_db_name_check_parameters" {
  description = "Input parameters for the redshift-default-db-name-check rule."
  type = object({
    validDatabaseNames = optional(string, null)
  })
  default = {}
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
  default = {
    tag1Key = "CostCenter"
  }

}

variable "restricted_incoming_traffic_parameters" {
  description = "Input parameters for the restricted-incoming-traffic rule."
  type = object({
    blockedPort1 = optional(number, 20)
    blockedPort2 = optional(number, 21)
    blockedPort3 = optional(number, 3389)
    blockedPort4 = optional(number, 3306)
    blockedPort5 = optional(number, 4333)
  })
  default = {
    blockedPort1 = 20
    blockedPort2 = 21
    blockedPort3 = 3389
    blockedPort4 = 3306
    blockedPort5 = 4333
  }

}

variable "s3_account_level_public_access_blocks_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks rule."
  type = object({
    BlockPublicAcls       = optional(string, "True")
    BlockPublicPolicy     = optional(string, "True")
    IgnorePublicAcls      = optional(string, "True")
    RestrictPublicBuckets = optional(string, "True")
  })
  default = {
    BlockPublicAcls       = "True"
    BlockPublicPolicy     = "True"
    IgnorePublicAcls      = "True"
    RestrictPublicBuckets = "True"
  }

}

variable "s3_account_level_public_access_blocks_periodic_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks-periodic rule."
  type = object({
    BlockPublicAcls       = optional(string, null)
    BlockPublicPolicy     = optional(string, null)
    IgnorePublicAcls      = optional(string, null)
    RestrictPublicBuckets = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_blacklisted_actions_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-blacklisted-actions-prohibited rule."
  type = object({
    blacklistedActionPattern = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_default_lock_enabled_parameters" {
  description = "Input parameters for the s3-bucket-default-lock-enabled rule."
  type = object({
    mode = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_level_public_access_prohibited_parameters" {
  description = "Input parameters for the s3-bucket-level-public-access-prohibited rule."
  type = object({
    excludedPublicBuckets = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_logging_enabled_parameters" {
  description = "Input parameters for the s3-bucket-logging-enabled rule."
  type = object({
    targetBucket = optional(string, null)
    targetPrefix = optional(string, null)
  })
  default = {}
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
  default = {}
}

variable "s3_bucket_policy_not_more_permissive_parameters" {
  description = "Input parameters for the s3-bucket-policy-not-more-permissive rule."
  type = object({
    controlPolicy = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_replication_enabled_parameters" {
  description = "Input parameters for the s3-bucket-replication-enabled rule."
  type = object({
    ReplicationType = optional(string, null)
  })
  default = {}
}

variable "s3_bucket_versioning_enabled_parameters" {
  description = "Input parameters for the s3-bucket-versioning-enabled rule."
  type = object({
    isMfaDeleteEnabled = optional(string, null)
  })
  default = {}
}

variable "s3_default_encryption_kms_parameters" {
  description = "Input parameters for the s3-default-encryption-kms rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "s3_event_notifications_enabled_parameters" {
  description = "Input parameters for the s3-event-notifications-enabled rule."
  type = object({
    destinationArn = optional(string, null)
    eventTypes     = optional(string, null)
  })
  default = {}
}

variable "s3_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the s3-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
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
  default = {}
}

variable "s3_version_lifecycle_policy_check_parameters" {
  description = "Input parameters for the s3-version-lifecycle-policy-check rule."
  type = object({
    bucketNames = optional(string, null)
  })
  default = {}
}

variable "sagemaker_endpoint_configuration_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-endpoint-configuration-kms-key-configured rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "sagemaker_notebook_instance_inside_vpc_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-inside-vpc rule."
  type = object({
    SubnetIds = optional(string, null)
  })
  default = {}
}

variable "sagemaker_notebook_instance_kms_key_configured_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-kms-key-configured rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "secretsmanager_rotation_enabled_check_parameters" {
  description = "Input parameters for the secretsmanager-rotation-enabled-check rule."
  type = object({
    maximumAllowedRotationFrequency        = optional(number, null)
    maximumAllowedRotationFrequencyInHours = optional(number, null)
  })
  default = {}
}

variable "secretsmanager_secret_periodic_rotation_parameters" {
  description = "Input parameters for the secretsmanager-secret-periodic-rotation rule."
  type = object({
    maxDaysSinceRotation = optional(number, null)
  })
  default = {}
}

variable "secretsmanager_secret_unused_parameters" {
  description = "Input parameters for the secretsmanager-secret-unused rule."
  type = object({
    unusedForDays = optional(number, null)
  })
  default = {}
}

variable "secretsmanager_using_cmk_parameters" {
  description = "Input parameters for the secretsmanager-using-cmk rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}

variable "service_vpc_endpoint_enabled_parameters" {
  description = "Input parameters for the service-vpc-endpoint-enabled rule."
  type = object({
    serviceName = optional(string, null)
  })
  default = {}
}

variable "sns_encrypted_kms_parameters" {
  description = "Input parameters for the sns-encrypted-kms rule."
  type = object({
    kmsKeyIds = optional(string, null)
  })
  default = {}
}

variable "step_functions_state_machine_logging_enabled_parameters" {
  description = "Input parameters for the step-functions-state-machine-logging-enabled rule."
  type = object({
    cloudWatchLogGroupArns = optional(string, null)
    logLevel               = optional(string, null)
  })
  default = {}
}

variable "storagegateway_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the storagegateway-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "virtualmachine_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the virtualmachine-last-backup-recovery-point-created rule."
  type = object({
    recoveryPointAgeUnit  = optional(string, "days")
    recoveryPointAgeValue = optional(number, 1)
    resourceId            = optional(string, null)
    resourceTags          = optional(string, null)
  })
  default = {
    recoveryPointAgeUnit  = "days"
    recoveryPointAgeValue = 1
  }

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
  default = {}
}

variable "vpc_flow_logs_enabled_parameters" {
  description = "Input parameters for the vpc-flow-logs-enabled rule."
  type = object({
    trafficType = optional(string, null)
  })
  default = {}
}

variable "vpc_peering_dns_resolution_check_parameters" {
  description = "Input parameters for the vpc-peering-dns-resolution-check rule."
  type = object({
    vpcIds = optional(string, null)
  })
  default = {}
}

variable "vpc_sg_open_only_to_authorized_ports_parameters" {
  description = "Input parameters for the vpc-sg-open-only-to-authorized-ports rule."
  type = object({
    authorizedTcpPorts = optional(string, null)
    authorizedUdpPorts = optional(string, null)
  })
  default = {}
}

variable "wafv2_logging_enabled_parameters" {
  description = "Input parameters for the wafv2-logging-enabled rule."
  type = object({
    KinesisFirehoseDeliveryStreamArns = optional(string, null)
  })
  default = {}
}

variable "waf_classic_logging_enabled_parameters" {
  description = "Input parameters for the waf-classic-logging-enabled rule."
  type = object({
    KinesisFirehoseDeliveryStreamArns = optional(string, null)
  })
  default = {}
}
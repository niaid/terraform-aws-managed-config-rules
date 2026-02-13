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


variable "acmpca_certificate_authority_tagged_parameters" {
  description = "Input parameters for the acmpca-certificate-authority-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "acm_pca_root_ca_disabled_parameters" {
  description = "Input parameters for the acm-pca-root-ca-disabled rule."
  type = object({
    exemptedCAArns = optional(string, null)
  })
  default = {}
}


variable "active_mq_supported_version_parameters" {
  description = "Input parameters for the active-mq-supported-version rule."
  type = object({
    supportedEngineVersion = optional(string, null)
  })
  default = {}
}


variable "alb_desync_mode_check_parameters" {
  description = "Input parameters for the alb-desync-mode-check rule."
  type = object({
    desyncMode = optional(string, null)
  })
  default = {}
}


variable "alb_listener_tagged_parameters" {
  description = "Input parameters for the alb-listener-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "alb_tagged_parameters" {
  description = "Input parameters for the alb-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "amplify_app_tagged_parameters" {
  description = "Input parameters for the amplify-app-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "amplify_branch_tagged_parameters" {
  description = "Input parameters for the amplify-branch-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "api_gw_rest_api_tagged_parameters" {
  description = "Input parameters for the api-gw-rest-api-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "api_gw_ssl_enabled_parameters" {
  description = "Input parameters for the api-gw-ssl-enabled rule."
  type = object({
    CertificateIDs = optional(string, null)
  })
  default = {}
}


variable "api_gw_stage_tagged_parameters" {
  description = "Input parameters for the api-gw-stage-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appconfig_application_tagged_parameters" {
  description = "Input parameters for the appconfig-application-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appconfig_configuration_profile_tagged_parameters" {
  description = "Input parameters for the appconfig-configuration-profile-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appconfig_deployment_strategy_minimum_final_bake_time_parameters" {
  description = "Input parameters for the appconfig-deployment-strategy-minimum-final-bake-time rule."
  type = object({
    minBakeTime = optional(number, 30)
  })
  default = {
    minBakeTime = 30
  }

}


variable "appconfig_deployment_strategy_tagged_parameters" {
  description = "Input parameters for the appconfig-deployment-strategy-tagged rule."
  type = object({
    includePredefinedSystemResources = optional(bool, false)
    requiredKeyTags                  = optional(string, null)
  })
  default = {
    includePredefinedSystemResources = false
  }

}


variable "appconfig_environment_tagged_parameters" {
  description = "Input parameters for the appconfig-environment-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appconfig_extension_association_tagged_parameters" {
  description = "Input parameters for the appconfig-extension-association-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appflow_flow_tagged_parameters" {
  description = "Input parameters for the appflow-flow-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appflow_flow_trigger_type_check_parameters" {
  description = "Input parameters for the appflow-flow-trigger-type-check rule."
  type = object({
    triggerType = optional(string, null)
  })
  default = {}
}


variable "appintegrations_event_integration_tagged_parameters" {
  description = "Input parameters for the appintegrations-event-integration-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_gateway_route_tagged_parameters" {
  description = "Input parameters for the appmesh-gateway-route-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_mesh_tagged_parameters" {
  description = "Input parameters for the appmesh-mesh-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_route_tagged_parameters" {
  description = "Input parameters for the appmesh-route-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_gateway_tagged_parameters" {
  description = "Input parameters for the appmesh-virtual-gateway-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_node_cloud_map_ip_pref_check_parameters" {
  description = "Input parameters for the appmesh-virtual-node-cloud-map-ip-pref-check rule."
  type = object({
    ipPreference = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_node_dns_ip_pref_check_parameters" {
  description = "Input parameters for the appmesh-virtual-node-dns-ip-pref-check rule."
  type = object({
    ipPreference = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_node_tagged_parameters" {
  description = "Input parameters for the appmesh-virtual-node-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_router_tagged_parameters" {
  description = "Input parameters for the appmesh-virtual-router-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appmesh_virtual_service_tagged_parameters" {
  description = "Input parameters for the appmesh-virtual-service-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    amisByTagKeyAndValue = optional(string, "tag-key:tag-value,other-tag-key")
  })
  default = {
    amisByTagKeyAndValue = "tag-key:tag-value,other-tag-key"
  }

}


variable "apprunner_service_ip_address_type_check_parameters" {
  description = "Input parameters for the apprunner-service-ip-address-type-check rule."
  type = object({
    ipAddressType = optional(string, null)
  })
  default = {}
}


variable "apprunner_service_max_unhealthy_threshold_parameters" {
  description = "Input parameters for the apprunner-service-max-unhealthy-threshold rule."
  type = object({
    maxUnhealthyThreshold = optional(number, null)
  })
  default = {}
}


variable "apprunner_service_tagged_parameters" {
  description = "Input parameters for the apprunner-service-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "apprunner_vpc_connector_tagged_parameters" {
  description = "Input parameters for the apprunner-vpc-connector-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "appsync_associated_with_waf_parameters" {
  description = "Input parameters for the appsync-associated-with-waf rule."
  type = object({
    wafWebAclARNs = optional(string, null)
  })
  default = {}
}


variable "appsync_authorization_check_parameters" {
  description = "Input parameters for the appsync-authorization-check rule."
  type = object({
    AllowedAuthorizationTypes = optional(string, null)
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


variable "aps_rule_groups_namespace_tagged_parameters" {
  description = "Input parameters for the aps-rule-groups-namespace-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "auditmanager_assessment_tagged_parameters" {
  description = "Input parameters for the auditmanager-assessment-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "aurora_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the aurora-last-backup-recovery-point-created rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "aurora_meets_restore_time_target_parameters" {
  description = "Input parameters for the aurora-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "aurora_mysql_backtracking_enabled_parameters" {
  description = "Input parameters for the aurora-mysql-backtracking-enabled rule."
  type = object({
    BacktrackWindowInHours = optional(number, null)
  })
  default = {}
}


variable "aurora_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the aurora-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "aurora_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the aurora-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
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
    requiredFrequencyValue = optional(number, 1)
    requiredRetentionDays  = optional(number, 35)
    requiredFrequencyUnit  = optional(string, "days")
  })
  default = {
    requiredFrequencyValue = 1
    requiredRetentionDays  = 35
    requiredFrequencyUnit  = "days"
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


variable "batch_compute_environment_tagged_parameters" {
  description = "Input parameters for the batch-compute-environment-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "batch_job_queue_tagged_parameters" {
  description = "Input parameters for the batch-job-queue-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "batch_managed_compute_env_allocation_strategy_check_parameters" {
  description = "Input parameters for the batch-managed-compute-env-allocation-strategy-check rule."
  type = object({
    allocationStrategy = optional(string, null)
  })
  default = {}
}


variable "batch_managed_compute_env_compute_resources_tagged_parameters" {
  description = "Input parameters for the batch-managed-compute-env-compute-resources-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "batch_managed_spot_compute_environment_max_bid_parameters" {
  description = "Input parameters for the batch-managed-spot-compute-environment-max-bid rule."
  type = object({
    maxBidPercentage = optional(number, null)
  })
  default = {}
}


variable "batch_scheduling_policy_tagged_parameters" {
  description = "Input parameters for the batch-scheduling-policy-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "cassandra_keyspace_tagged_parameters" {
  description = "Input parameters for the cassandra-keyspace-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
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
    snsTopic2 = optional(string, null)
    snsTopic1 = optional(string, null)
    snsTopic5 = optional(string, null)
    snsTopic4 = optional(string, null)
    snsTopic3 = optional(string, null)
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


variable "cloudfront_ssl_policy_check_parameters" {
  description = "Input parameters for the cloudfront-ssl-policy-check rule."
  type = object({
    securityPolicies = optional(string, null)
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
    okActionRequired               = optional(string, "false")
    insufficientDataActionRequired = optional(string, "true")
    alarmActionRequired            = optional(string, "true")
    action1                        = optional(string, null)
    action2                        = optional(string, null)
    action3                        = optional(string, null)
    action4                        = optional(string, null)
    action5                        = optional(string, null)
  })
  default = {
    okActionRequired               = "false"
    insufficientDataActionRequired = "true"
    alarmActionRequired            = "true"
  }

}


variable "cloudwatch_alarm_resource_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-resource-check rule."
  type = object({
    resourceType = optional(string, null)
    metricName   = optional(string, null)
  })
  default = {}
}


variable "cloudwatch_alarm_settings_check_parameters" {
  description = "Input parameters for the cloudwatch-alarm-settings-check rule."
  type = object({
    metricName         = optional(string, null)
    period             = optional(number, 300)
    statistic          = optional(string, null)
    comparisonOperator = optional(string, null)
    threshold          = optional(number, null)
    evaluationPeriods  = optional(number, null)
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


variable "cloudwatch_metric_stream_tagged_parameters" {
  description = "Input parameters for the cloudwatch-metric-stream-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "cloudtrail_enabled_parameters" {
  description = "Input parameters for the cloudtrail-enabled rule."
  type = object({
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
    cloudWatchLogsLogGroupArn = optional(string, null)
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
    s3BucketNames        = optional(string, null)
    cloudWatchGroupNames = optional(string, null)
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


variable "codebuild_report_group_tagged_parameters" {
  description = "Input parameters for the codebuild-report-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "codeguruprofiler_profiling_group_tagged_parameters" {
  description = "Input parameters for the codeguruprofiler-profiling-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "codegurureviewer_repository_association_tagged_parameters" {
  description = "Input parameters for the codegurureviewer-repository-association-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
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


variable "cognito_user_pool_advanced_security_enabled_parameters" {
  description = "Input parameters for the cognito-user-pool-advanced-security-enabled rule."
  type = object({
    SecurityMode = optional(string, null)
  })
  default = {}
}


variable "cognito_user_pool_password_policy_check_parameters" {
  description = "Input parameters for the cognito-user-pool-password-policy-check rule."
  type = object({
    requireSymbols            = optional(bool, true)
    temporaryPasswordValidity = optional(number, 7)
    minLength                 = optional(number, 8)
    requireNumbers            = optional(bool, true)
    requireUppercase          = optional(bool, true)
    requireLowercase          = optional(bool, true)
  })
  default = {
    requireSymbols            = true
    temporaryPasswordValidity = 7
    minLength                 = 8
    requireNumbers            = true
    requireUppercase          = true
    requireLowercase          = true
  }

}


variable "cognito_user_pool_tagged_parameters" {
  description = "Input parameters for the cognito-user-pool-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "customerprofiles_domain_tagged_parameters" {
  description = "Input parameters for the customerprofiles-domain-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "customerprofiles_object_type_tagged_parameters" {
  description = "Input parameters for the customerprofiles-object-type-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "cw_loggroup_retention_period_check_parameters" {
  description = "Input parameters for the cw-loggroup-retention-period-check rule."
  type = object({
    LogGroupNames    = optional(string, null)
    MinRetentionTime = optional(number, null)
  })
  default = {}
}


variable "datasync_task_logging_enabled_parameters" {
  description = "Input parameters for the datasync-task-logging-enabled rule."
  type = object({
    logLevel = optional(string, null)
  })
  default = {}
}


variable "datasync_task_tagged_parameters" {
  description = "Input parameters for the datasync-task-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    tenancy = optional(string, null)
    imageId = optional(string, null)
    hostId  = optional(string, null)
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


variable "dms_endpoint_tagged_parameters" {
  description = "Input parameters for the dms-endpoint-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "dms_replication_task_tagged_parameters" {
  description = "Input parameters for the dms-replication-task-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "docdb_cluster_backup_retention_check_parameters" {
  description = "Input parameters for the docdb-cluster-backup-retention-check rule."
  type = object({
    minimumBackupRetentionPeriod = optional(number, null)
  })
  default = {}
}


variable "docdb_cluster_encrypted_parameters" {
  description = "Input parameters for the docdb-cluster-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "docdb_cluster_encrypted_in_transit_parameters" {
  description = "Input parameters for the docdb-cluster-encrypted-in-transit rule."
  type = object({
    excludeTlsParameters = optional(string, null)
  })
  default = {}
}


variable "dynamodb_autoscaling_enabled_parameters" {
  description = "Input parameters for the dynamodb-autoscaling-enabled rule."
  type = object({
    minProvisionedReadCapacity  = optional(number, null)
    maxProvisionedReadCapacity  = optional(number, null)
    targetReadUtilization       = optional(number, null)
    minProvisionedWriteCapacity = optional(number, null)
    maxProvisionedWriteCapacity = optional(number, null)
    targetWriteUtilization      = optional(number, null)
  })
  default = {}
}


variable "dynamodb_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the dynamodb-last-backup-recovery-point-created rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "dynamodb_meets_restore_time_target_parameters" {
  description = "Input parameters for the dynamodb-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "dynamodb_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the dynamodb-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
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
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "ebs_meets_restore_time_target_parameters" {
  description = "Input parameters for the ebs-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "ebs_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the ebs-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "ebs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ebs-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "ec2_capacity_reservation_tagged_parameters" {
  description = "Input parameters for the ec2-capacity-reservation-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_carrier_gateway_tagged_parameters" {
  description = "Input parameters for the ec2-carrier-gateway-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_client_vpn_endpoint_tagged_parameters" {
  description = "Input parameters for the ec2-client-vpn-endpoint-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_dhcp_options_tagged_parameters" {
  description = "Input parameters for the ec2-dhcp-options-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_fleet_tagged_parameters" {
  description = "Input parameters for the ec2-fleet-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_instance_launched_with_allowed_ami_parameters" {
  description = "Input parameters for the ec2-instance-launched-with-allowed-ami rule."
  type = object({
    InstanceStateNameList = optional(string, null)
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
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "ec2_launch_template_public_ip_disabled_parameters" {
  description = "Input parameters for the ec2-launch-template-public-ip-disabled rule."
  type = object({
    exemptedLaunchTemplates = optional(string, null)
  })
  default = {}
}


variable "ec2_launch_template_tagged_parameters" {
  description = "Input parameters for the ec2-launch-template-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    platformType    = optional(string, null)
    platformVersion = optional(string, null)
    agentVersion    = optional(string, null)
    platformName    = optional(string, null)
  })
  default = {}
}


variable "ec2_meets_restore_time_target_parameters" {
  description = "Input parameters for the ec2-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "ec2_network_insights_access_scope_analysis_tagged_parameters" {
  description = "Input parameters for the ec2-network-insights-access-scope-analysis-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_network_insights_access_scope_tagged_parameters" {
  description = "Input parameters for the ec2-network-insights-access-scope-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_network_insights_analysis_tagged_parameters" {
  description = "Input parameters for the ec2-network-insights-analysis-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_network_insights_path_tagged_parameters" {
  description = "Input parameters for the ec2-network-insights-path-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_prefix_list_tagged_parameters" {
  description = "Input parameters for the ec2-prefix-list-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the ec2-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "ec2_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the ec2-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
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


variable "ec2_traffic_mirror_filter_tagged_parameters" {
  description = "Input parameters for the ec2-traffic-mirror-filter-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_traffic_mirror_session_tagged_parameters" {
  description = "Input parameters for the ec2-traffic-mirror-session-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_traffic_mirror_target_tagged_parameters" {
  description = "Input parameters for the ec2-traffic-mirror-target-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ec2_transit_gateway_multicast_domain_tagged_parameters" {
  description = "Input parameters for the ec2-transit-gateway-multicast-domain-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "ec2_vpn_connection_tagged_parameters" {
  description = "Input parameters for the ec2-vpn-connection-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ecr_repository_cmk_encryption_enabled_parameters" {
  description = "Input parameters for the ecr-repository-cmk-encryption-enabled rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "ecr_repository_tagged_parameters" {
  description = "Input parameters for the ecr-repository-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ecs_capacity_provider_tagged_parameters" {
  description = "Input parameters for the ecs-capacity-provider-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    approvedUids = optional(string, null)
    approvedGids = optional(string, null)
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


variable "efs_filesystem_ct_encrypted_parameters" {
  description = "Input parameters for the efs-filesystem-ct-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "efs_file_system_tagged_parameters" {
  description = "Input parameters for the efs-file-system-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "efs_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the efs-last-backup-recovery-point-created rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "efs_meets_restore_time_target_parameters" {
  description = "Input parameters for the efs-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "efs_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the efs-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "efs_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the efs-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "eks_addon_tagged_parameters" {
  description = "Input parameters for the eks-addon-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "eks_cluster_log_enabled_parameters" {
  description = "Input parameters for the eks-cluster-log-enabled rule."
  type = object({
    logTypes = optional(string, null)
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


variable "eks_cluster_secrets_encrypted_parameters" {
  description = "Input parameters for the eks-cluster-secrets-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
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


variable "eks_fargate_profile_tagged_parameters" {
  description = "Input parameters for the eks-fargate-profile-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "elasticache_automatic_backup_check_enabled_parameters" {
  description = "Input parameters for the elasticache-automatic-backup-check-enabled rule."
  type = object({
    snapshotRetentionPeriod = optional(number, null)
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
    RetentionInDays   = optional(string, null)
    DeleteOnTerminate = optional(string, null)
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


variable "elbv2_predefined_security_policy_ssl_check_parameters" {
  description = "Input parameters for the elbv2-predefined-security-policy-ssl-check rule."
  type = object({
    sslPolicies = optional(string, null)
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


variable "elb_tagged_parameters" {
  description = "Input parameters for the elb-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "emr_kerberos_enabled_parameters" {
  description = "Input parameters for the emr-kerberos-enabled rule."
  type = object({
    TicketLifetimeInHours = optional(number, null)
    Realm                 = optional(string, null)
    Domain                = optional(string, null)
    AdminServer           = optional(string, null)
    KdcServer             = optional(string, null)
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


variable "event_data_store_cmk_encryption_enabled_parameters" {
  description = "Input parameters for the event-data-store-cmk-encryption-enabled rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "evidently_launch_tagged_parameters" {
  description = "Input parameters for the evidently-launch-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "evidently_project_tagged_parameters" {
  description = "Input parameters for the evidently-project-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "evidently_segment_tagged_parameters" {
  description = "Input parameters for the evidently-segment-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "fis_experiment_template_tagged_parameters" {
  description = "Input parameters for the fis-experiment-template-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "fms_shield_resource_policy_check_parameters" {
  description = "Input parameters for the fms-shield-resource-policy-check rule."
  type = object({
    webACLId              = optional(string, null)
    resourceTypes         = optional(string, null)
    resourceTags          = optional(string, null)
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
  })
  default = {}
}


variable "fms_webacl_resource_policy_check_parameters" {
  description = "Input parameters for the fms-webacl-resource-policy-check rule."
  type = object({
    webACLId              = optional(string, null)
    resourceTags          = optional(string, null)
    excludeResourceTags   = optional(bool, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
  })
  default = {}
}


variable "fms_webacl_rulegroup_association_check_parameters" {
  description = "Input parameters for the fms-webacl-rulegroup-association-check rule."
  type = object({
    ruleGroups            = optional(string, null)
    fmsManagedToken       = optional(string, null)
    fmsRemediationEnabled = optional(bool, null)
  })
  default = {}
}


variable "frauddetector_entity_type_tagged_parameters" {
  description = "Input parameters for the frauddetector-entity-type-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "frauddetector_label_tagged_parameters" {
  description = "Input parameters for the frauddetector-label-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "frauddetector_outcome_tagged_parameters" {
  description = "Input parameters for the frauddetector-outcome-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "frauddetector_variable_tagged_parameters" {
  description = "Input parameters for the frauddetector-variable-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "fsx_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the fsx-last-backup-recovery-point-created rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "fsx_meets_restore_time_target_parameters" {
  description = "Input parameters for the fsx-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "fsx_ontap_deployment_type_check_parameters" {
  description = "Input parameters for the fsx-ontap-deployment-type-check rule."
  type = object({
    deploymentTypes = optional(string, null)
  })
  default = {}
}


variable "fsx_openzfs_deployment_type_check_parameters" {
  description = "Input parameters for the fsx-openzfs-deployment-type-check rule."
  type = object({
    deploymentTypes = optional(string, null)
  })
  default = {}
}


variable "fsx_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the fsx-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "fsx_windows_deployment_type_check_parameters" {
  description = "Input parameters for the fsx-windows-deployment-type-check rule."
  type = object({
    deploymentTypes = optional(string, null)
  })
  default = {}
}


variable "glb_listener_tagged_parameters" {
  description = "Input parameters for the glb-listener-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "glb_tagged_parameters" {
  description = "Input parameters for the glb-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "glue_ml_transform_tagged_parameters" {
  description = "Input parameters for the glue-ml-transform-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "glue_spark_job_supported_version_parameters" {
  description = "Input parameters for the glue-spark-job-supported-version rule."
  type = object({
    minimumSupportedGlueVersion = optional(string, null)
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
    daysLowSev    = optional(number, 30)
    daysMediumSev = optional(number, 7)
    daysHighSev   = optional(number, 1)
  })
  default = {
    daysLowSev    = 30
    daysMediumSev = 7
    daysHighSev   = 1
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


variable "iam_oidc_provider_tagged_parameters" {
  description = "Input parameters for the iam-oidc-provider-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iam_password_policy_parameters" {
  description = "Input parameters for the iam-password-policy rule."
  type = object({
    RequireUppercaseCharacters = optional(bool, true)
    RequireLowercaseCharacters = optional(bool, true)
    RequireSymbols             = optional(bool, true)
    RequireNumbers             = optional(bool, true)
    MinimumPasswordLength      = optional(number, 14)
    PasswordReusePrevention    = optional(number, 24)
    MaxPasswordAge             = optional(number, 90)
  })
  default = {
    RequireUppercaseCharacters = true
    RequireLowercaseCharacters = true
    RequireSymbols             = true
    RequireNumbers             = true
    MinimumPasswordLength      = 14
    PasswordReusePrevention    = 24
    MaxPasswordAge             = 90
  }

}


variable "iam_policy_blacklisted_check_parameters" {
  description = "Input parameters for the iam-policy-blacklisted-check rule."
  type = object({
    policyArns    = optional(string, "arn:aws:iam::aws:policy/AdministratorAccess")
    exceptionList = optional(string, null)
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


variable "iam_saml_provider_tagged_parameters" {
  description = "Input parameters for the iam-saml-provider-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iam_server_certificate_tagged_parameters" {
  description = "Input parameters for the iam-server-certificate-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "ec2_instances_in_vpc_parameters" {
  description = "Input parameters for the ec2-instances-in-vpc rule."
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


variable "iotdevicedefender_custom_metric_tagged_parameters" {
  description = "Input parameters for the iotdevicedefender-custom-metric-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotevents_alarm_model_tagged_parameters" {
  description = "Input parameters for the iotevents-alarm-model-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotevents_detector_model_tagged_parameters" {
  description = "Input parameters for the iotevents-detector-model-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotevents_input_tagged_parameters" {
  description = "Input parameters for the iotevents-input-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotsitewise_asset_model_tagged_parameters" {
  description = "Input parameters for the iotsitewise-asset-model-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotsitewise_dashboard_tagged_parameters" {
  description = "Input parameters for the iotsitewise-dashboard-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotsitewise_gateway_tagged_parameters" {
  description = "Input parameters for the iotsitewise-gateway-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotsitewise_portal_tagged_parameters" {
  description = "Input parameters for the iotsitewise-portal-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotsitewise_project_tagged_parameters" {
  description = "Input parameters for the iotsitewise-project-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iottwinmaker_component_type_tagged_parameters" {
  description = "Input parameters for the iottwinmaker-component-type-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iottwinmaker_entity_tagged_parameters" {
  description = "Input parameters for the iottwinmaker-entity-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iottwinmaker_scene_tagged_parameters" {
  description = "Input parameters for the iottwinmaker-scene-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iottwinmaker_sync_job_tagged_parameters" {
  description = "Input parameters for the iottwinmaker-sync-job-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iottwinmaker_workspace_tagged_parameters" {
  description = "Input parameters for the iottwinmaker-workspace-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotwireless_fuota_task_tagged_parameters" {
  description = "Input parameters for the iotwireless-fuota-task-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotwireless_multicast_group_tagged_parameters" {
  description = "Input parameters for the iotwireless-multicast-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iotwireless_service_profile_tagged_parameters" {
  description = "Input parameters for the iotwireless-service-profile-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iot_job_template_tagged_parameters" {
  description = "Input parameters for the iot-job-template-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iot_provisioning_template_tagged_parameters" {
  description = "Input parameters for the iot-provisioning-template-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "iot_scheduled_audit_tagged_parameters" {
  description = "Input parameters for the iot-scheduled-audit-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ivs_channel_tagged_parameters" {
  description = "Input parameters for the ivs-channel-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ivs_playback_key_pair_tagged_parameters" {
  description = "Input parameters for the ivs-playback-key-pair-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "ivs_recording_configuration_tagged_parameters" {
  description = "Input parameters for the ivs-recording-configuration-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "kinesis_firehose_delivery_stream_encrypted_parameters" {
  description = "Input parameters for the kinesis-firehose-delivery-stream-encrypted rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "kinesis_stream_backup_retention_check_parameters" {
  description = "Input parameters for the kinesis-stream-backup-retention-check rule."
  type = object({
    minimumBackupRetentionPeriod = optional(string, null)
  })
  default = {}
}


variable "kinesis_video_stream_minimum_data_retention_parameters" {
  description = "Input parameters for the kinesis-video-stream-minimum-data-retention rule."
  type = object({
    minDataRetentionInHours = optional(number, null)
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


variable "kms_key_tagged_parameters" {
  description = "Input parameters for the kms-key-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    runtime    = optional(string, null)
    role       = optional(string, null)
    memorySize = optional(number, 128)
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


variable "lightsail_bucket_tagged_parameters" {
  description = "Input parameters for the lightsail-bucket-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "lightsail_certificate_tagged_parameters" {
  description = "Input parameters for the lightsail-certificate-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "lightsail_disk_tagged_parameters" {
  description = "Input parameters for the lightsail-disk-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "mariadb_publish_logs_to_cloudwatch_logs_parameters" {
  description = "Input parameters for the mariadb-publish-logs-to-cloudwatch-logs rule."
  type = object({
    logTypes = optional(string, null)
  })
  default = {}
}


variable "msk_cluster_tagged_parameters" {
  description = "Input parameters for the msk-cluster-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "multi_region_cloudtrail_enabled_parameters" {
  description = "Input parameters for the multi-region-cloudtrail-enabled rule."
  type = object({
    s3BucketName              = optional(string, null)
    snsTopicArn               = optional(string, null)
    cloudWatchLogsLogGroupArn = optional(string, null)
    includeManagementEvents   = optional(bool, null)
    readWriteType             = optional(string, null)
  })
  default = {}
}


variable "neptune_cluster_backup_retention_check_parameters" {
  description = "Input parameters for the neptune-cluster-backup-retention-check rule."
  type = object({
    minimumBackupRetentionPeriod = optional(number, null)
  })
  default = {}
}


variable "neptune_cluster_encrypted_parameters" {
  description = "Input parameters for the neptune-cluster-encrypted rule."
  type = object({
    KmsKeyArns = optional(string, null)
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


variable "nlb_listener_tagged_parameters" {
  description = "Input parameters for the nlb-listener-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "nlb_tagged_parameters" {
  description = "Input parameters for the nlb-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "rabbit_mq_supported_version_parameters" {
  description = "Input parameters for the rabbit-mq-supported-version rule."
  type = object({
    supportedEngineVersion = optional(string, null)
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


variable "rds_event_subscription_tagged_parameters" {
  description = "Input parameters for the rds-event-subscription-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "rds_logging_enabled_parameters" {
  description = "Input parameters for the rds-logging-enabled rule."
  type = object({
    additionalLogs = optional(string, null)
  })
  default = {}
}


variable "rds_meets_restore_time_target_parameters" {
  description = "Input parameters for the rds-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "rds_option_group_tagged_parameters" {
  description = "Input parameters for the rds-option-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "rds_postgresql_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the rds-postgresql-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
  })
  default = {}
}


variable "rds_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the rds-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "rds_sql_server_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the rds-sql-server-logs-to-cloudwatch rule."
  type = object({
    logTypes = optional(string, null)
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
    MinRetentionPeriod = optional(number, null)
    MaxRetentionPeriod = optional(number, null)
  })
  default = {}
}


variable "redshift_cluster_configuration_check_parameters" {
  description = "Input parameters for the redshift-cluster-configuration-check rule."
  type = object({
    loggingEnabled     = optional(bool, true)
    clusterDbEncrypted = optional(bool, true)
    nodeTypes          = optional(string, "dc1.large")
  })
  default = {
    loggingEnabled     = true
    clusterDbEncrypted = true
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
    preferredMaintenanceWindow       = optional(string, null)
    automatedSnapshotRetentionPeriod = optional(number, 1)
  })
  default = {
    allowVersionUpgrade              = true
    automatedSnapshotRetentionPeriod = 1
  }

}


variable "redshift_cluster_parameter_group_tagged_parameters" {
  description = "Input parameters for the redshift-cluster-parameter-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
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


variable "redshift_serverless_namespace_cmk_encryption_parameters" {
  description = "Input parameters for the redshift-serverless-namespace-cmk-encryption rule."
  type = object({
    kmsKeyArns = optional(string, null)
  })
  default = {}
}


variable "redshift_serverless_publish_logs_to_cloudwatch_parameters" {
  description = "Input parameters for the redshift-serverless-publish-logs-to-cloudwatch rule."
  type = object({
    logType = optional(string, null)
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


variable "restricted_common_ports_parameters" {
  description = "Input parameters for the restricted-common-ports rule."
  type = object({
    blockedPort1 = optional(number, 20)
    blockedPort2 = optional(number, 21)
    blockedPort3 = optional(number, 3389)
    blockedPort4 = optional(number, 3306)
    blockedPort5 = optional(number, 4333)
    blockedPorts = optional(string, null)
  })
  default = {
    blockedPort1 = 20
    blockedPort2 = 21
    blockedPort3 = 3389
    blockedPort4 = 3306
    blockedPort5 = 4333
  }

}


variable "route53_health_check_tagged_parameters" {
  description = "Input parameters for the route53-health-check-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "route53_hosted_zone_tagged_parameters" {
  description = "Input parameters for the route53-hosted-zone-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "route53_resolver_firewall_domain_list_tagged_parameters" {
  description = "Input parameters for the route53-resolver-firewall-domain-list-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "route53_resolver_firewall_rule_group_association_tagged_parameters" {
  description = "Input parameters for the route53-resolver-firewall-rule-group-association-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "route53_resolver_firewall_rule_group_tagged_parameters" {
  description = "Input parameters for the route53-resolver-firewall-rule-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "route53_resolver_resolver_rule_tagged_parameters" {
  description = "Input parameters for the route53-resolver-resolver-rule-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "rum_app_monitor_tagged_parameters" {
  description = "Input parameters for the rum-app-monitor-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "s3express_dir_bucket_lifecycle_rules_check_parameters" {
  description = "Input parameters for the s3express-dir-bucket-lifecycle-rules-check rule."
  type = object({
    targetExpirationDays = optional(number, null)
  })
  default = {}
}


variable "s3_access_point_public_access_blocks_parameters" {
  description = "Input parameters for the s3-access-point-public-access-blocks rule."
  type = object({
    excludedAccessPoints = optional(string, null)
  })
  default = {}
}


variable "s3_account_level_public_access_blocks_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks rule."
  type = object({
    RestrictPublicBuckets = optional(string, "True")
    BlockPublicPolicy     = optional(string, "True")
    BlockPublicAcls       = optional(string, "True")
    IgnorePublicAcls      = optional(string, "True")
  })
  default = {
    RestrictPublicBuckets = "True"
    BlockPublicPolicy     = "True"
    BlockPublicAcls       = "True"
    IgnorePublicAcls      = "True"
  }

}


variable "s3_account_level_public_access_blocks_periodic_parameters" {
  description = "Input parameters for the s3-account-level-public-access-blocks-periodic rule."
  type = object({
    IgnorePublicAcls      = optional(string, null)
    BlockPublicPolicy     = optional(string, null)
    BlockPublicAcls       = optional(string, null)
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
    targetPrefix = optional(string, null)
    targetBucket = optional(string, null)
  })
  default = {}
}


variable "s3_bucket_policy_grantee_check_parameters" {
  description = "Input parameters for the s3-bucket-policy-grantee-check rule."
  type = object({
    awsPrincipals     = optional(string, null)
    servicePrincipals = optional(string, null)
    federatedUsers    = optional(string, null)
    ipAddresses       = optional(string, null)
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


variable "s3_bucket_tagged_parameters" {
  description = "Input parameters for the s3-bucket-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "s3_lifecycle_policy_check_parameters" {
  description = "Input parameters for the s3-lifecycle-policy-check rule."
  type = object({
    targetTransitionDays         = optional(number, null)
    targetExpirationDays         = optional(number, null)
    targetTransitionStorageClass = optional(string, null)
    targetPrefix                 = optional(string, null)
    bucketNames                  = optional(string, null)
  })
  default = {}
}


variable "s3_meets_restore_time_target_parameters" {
  description = "Input parameters for the s3-meets-restore-time-target rule."
  type = object({
    maxRestoreTime = optional(number, null)
    resourceTags   = optional(string, null)
    resourceId     = optional(string, null)
  })
  default = {}
}


variable "s3_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the s3-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "s3_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the s3-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
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


variable "sagemaker_app_image_config_tagged_parameters" {
  description = "Input parameters for the sagemaker-app-image-config-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "sagemaker_domain_tagged_parameters" {
  description = "Input parameters for the sagemaker-domain-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "sagemaker_feature_group_tagged_parameters" {
  description = "Input parameters for the sagemaker-feature-group-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "sagemaker_image_tagged_parameters" {
  description = "Input parameters for the sagemaker-image-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "sagemaker_notebook_instance_platform_version_parameters" {
  description = "Input parameters for the sagemaker-notebook-instance-platform-version rule."
  type = object({
    supportedPlatformIdentifierVersions = optional(string, null)
  })
  default = {}
}


variable "secretsmanager_rotation_enabled_check_parameters" {
  description = "Input parameters for the secretsmanager-rotation-enabled-check rule."
  type = object({
    maximumAllowedRotationFrequencyInHours = optional(number, null)
    maximumAllowedRotationFrequency        = optional(number, null)
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


variable "service_catalog_portfolio_tagged_parameters" {
  description = "Input parameters for the service-catalog-portfolio-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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


variable "ssm_document_tagged_parameters" {
  description = "Input parameters for the ssm-document-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "stepfunctions_state_machine_tagged_parameters" {
  description = "Input parameters for the stepfunctions-state-machine-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
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
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "storagegateway_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the storagegateway-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "storagegateway_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the storagegateway-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "transfer_agreement_tagged_parameters" {
  description = "Input parameters for the transfer-agreement-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "transfer_certificate_tagged_parameters" {
  description = "Input parameters for the transfer-certificate-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "transfer_connector_tagged_parameters" {
  description = "Input parameters for the transfer-connector-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "transfer_profile_tagged_parameters" {
  description = "Input parameters for the transfer-profile-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "transfer_workflow_tagged_parameters" {
  description = "Input parameters for the transfer-workflow-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "virtualmachine_last_backup_recovery_point_created_parameters" {
  description = "Input parameters for the virtualmachine-last-backup-recovery-point-created rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "virtualmachine_resources_in_logically_air_gapped_vault_parameters" {
  description = "Input parameters for the virtualmachine-resources-in-logically-air-gapped-vault rule."
  type = object({
    resourceTags          = optional(string, null)
    resourceId            = optional(string, null)
    recoveryPointAgeValue = optional(number, 1)
    recoveryPointAgeUnit  = optional(string, "days")
  })
  default = {
    recoveryPointAgeValue = 1
    recoveryPointAgeUnit  = "days"
  }

}


variable "virtualmachine_resources_protected_by_backup_plan_parameters" {
  description = "Input parameters for the virtualmachine-resources-protected-by-backup-plan rule."
  type = object({
    resourceTags         = optional(string, null)
    resourceId           = optional(string, null)
    crossRegionList      = optional(string, null)
    crossAccountList     = optional(string, null)
    maxRetentionDays     = optional(number, null)
    minRetentionDays     = optional(number, null)
    backupVaultLockCheck = optional(string, null)
  })
  default = {}
}


variable "vpc_endpoint_enabled_parameters" {
  description = "Input parameters for the vpc-endpoint-enabled rule."
  type = object({
    serviceNames             = optional(string, null)
    vpcIds                   = optional(string, null)
    scopeConfigResourceTypes = optional(string, null)
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


variable "vpc_sg_port_restriction_check_parameters" {
  description = "Input parameters for the vpc-sg-port-restriction-check rule."
  type = object({
    restrictPorts                 = optional(string, null)
    protocolType                  = optional(string, null)
    excludeExternalSecurityGroups = optional(bool, null)
    ipType                        = optional(string, null)
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


variable "workspaces_connection_alias_tagged_parameters" {
  description = "Input parameters for the workspaces-connection-alias-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}


variable "workspaces_workspace_tagged_parameters" {
  description = "Input parameters for the workspaces-workspace-tagged rule."
  type = object({
    requiredKeyTags = optional(string, null)
  })
  default = {}
}

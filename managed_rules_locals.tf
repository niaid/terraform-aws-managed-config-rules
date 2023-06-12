locals {
  managed_rules = {
    access-keys-rotated = {
      description      = "Checks if the active access keys are rotated within the number of days specified in maxAccessKeyAge . The rule is NON_COMPLIANT if the access keys have not been rotated for more than maxAccessKeyAge number of days."
      input_parameters = var.access_keys_rotated_parameters
      severity         = "Medium"
    }

    account-part-of-organizations = {
      description      = "Checks if an AWS account is part of AWS Organizations. The rule is NON_COMPLIANT if an AWS account is not part of AWS Organizations or AWS Organizations master account ID does not match rule parameter MasterAccountId ."
      input_parameters = var.account_part_of_organizations_parameters
      severity         = "Low"
    }

    acm-certificate-expiration-check = {
      description          = "Checks if AWS Certificate Manager Certificates in your account are marked for expiration within the specified number of days. Certificates provided by ACM are automatically renewed. ACM does not automatically renew certificates that you import. The rule..."
      input_parameters     = var.acm_certificate_expiration_check_parameters
      resource_types_scope = ["AWS::ACM::Certificate"]
      severity             = "Medium"
    }

    acm-certificate-rsa-check = {
      description          = "Checks if RSA certificates managed by AWS Certificate Manager (ACM) have a key length of at least 2048 bits.The rule is NON_COMPLIANT if the minimum key length is less than 2048 bits."
      resource_types_scope = ["AWS::ACM::Certificate"]
      severity             = "Medium"
    }

    alb-desync-mode-check = {
      description          = "Checks if an Application Load Balancer (ALB) is configured with a user defined desync mitigation mode. The rule is NON_COMPLIANT if ALB desync mitigation mode does not match with the user defined desync mitigation mode."
      input_parameters     = var.alb_desync_mode_check_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    alb-http-drop-invalid-header-enabled = {
      description          = "Checks if rule evaluates AWS Application Load Balancers (ALB) to ensure they are configured to drop http headers. The rule is NON_COMPLIANT if the value of routing.http.drop_invalid_header_fields.enabled is set to false."
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    alb-http-to-https-redirection-check = {
      description = "Checks if HTTP to HTTPS redirection is configured on all HTTP listeners of Application Load Balancers. The rule is NON_COMPLIANT if one or more HTTP listeners of Application Load Balancer do not have HTTP to HTTPS redirection configured. The rule is..."
      severity    = "Medium"
    }

    alb-waf-enabled = {
      description          = "Checks if AWS WAF is enabled on Application Load Balancers (ALBs). The rule is NON_COMPLIANT if key: waf.enabled is set to false."
      input_parameters     = var.alb_waf_enabled_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    api-gwv2-access-logs-enabled = {
      description          = "Checks if Amazon API Gateway V2 stages have access logging enabled. The rule is NON_COMPLIANT if accessLogSettings is not present in Stage configuration."
      resource_types_scope = ["AWS::ApiGatewayV2::Stage"]
      severity             = "Medium"
    }

    api-gwv2-authorization-type-configured = {
      description          = "Checks if Amazon API Gatewayv2 API routes have an authorization type set. This rule is NON_COMPLIANT if the authorization type is NONE."
      input_parameters     = var.api_gwv2_authorization_type_configured_parameters
      resource_types_scope = ["AWS::ApiGatewayV2::Route"]
      severity             = "Medium"
    }

    api-gw-associated-with-waf = {
      description          = "Checks if an Amazon API Gateway API stage is using an AWS WAF web access control list (web ACL). The rule is NON_COMPLIANT if an AWS WAF Web ACL is not used or if a used AWS Web ACL does not match what is listed in the rule parameter."
      input_parameters     = var.api_gw_associated_with_waf_parameters
      resource_types_scope = ["AWS::ApiGateway::Stage"]
      severity             = "Medium"
    }

    api-gw-cache-enabled-and-encrypted = {
      description          = "Checks if all methods in Amazon API Gateway stages have cache enabled and cache encrypted. The rule is NON_COMPLIANT if any method in an Amazon API Gateway stage is not configured to cache or the cache is not encrypted."
      resource_types_scope = ["AWS::ApiGateway::Stage"]
      severity             = "Medium"
    }

    api-gw-endpoint-type-check = {
      description          = "Checks if Amazon API Gateway APIs are of the type specified in the rule parameter endpointConfigurationType . The rule returns NON_COMPLIANT if the REST API does not match the endpoint type configured in the rule parameter."
      input_parameters     = var.api_gw_endpoint_type_check_parameters
      resource_types_scope = ["AWS::ApiGateway::RestApi"]
      severity             = "Medium"
    }

    api-gw-execution-logging-enabled = {
      description          = "Checks if all methods in Amazon API Gateway stages have logging enabled. The rule is NON_COMPLIANT if logging is not enabled, or if loggingLevel is neither ERROR nor INFO."
      input_parameters     = var.api_gw_execution_logging_enabled_parameters
      resource_types_scope = ["AWS::ApiGateway::Stage", "AWS::ApiGatewayV2::Stage"]
      severity             = "Medium"
    }

    api-gw-ssl-enabled = {
      description          = "Checks if a REST API stage uses an SSL certificate. The rule is NON_COMPLIANT if the REST API stage does not have an associated SSL certificate."
      input_parameters     = var.api_gw_ssl_enabled_parameters
      resource_types_scope = ["AWS::ApiGateway::Stage"]
      severity             = "Medium"
    }

    api-gw-xray-enabled = {
      description          = "Checks if AWS X-Ray tracing is enabled on Amazon API Gateway REST APIs. The rule is COMPLIANT if X-Ray tracing is enabled and NON_COMPLIANT otherwise."
      resource_types_scope = ["AWS::ApiGateway::Stage"]
      severity             = "Low"
    }

    approved-amis-by-id = {
      description          = "Checks if running EC2 instances are using specified Amazon Machine Images (AMIs). Specify a list of approved AMI IDs. Running instances with AMIs that are not on this list are NON_COMPLIANT."
      input_parameters     = var.approved_amis_by_id_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Medium"
    }

    approved-amis-by-tag = {
      description          = "Checks if running instances are using specified Amazon Machine Images (AMIs). Specify the tags that identify the AMIs. Running instances with AMIs that don t have at least one of the specified tags are NON_COMPLIANT."
      input_parameters     = var.approved_amis_by_tag_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Medium"
    }

    appsync-associated-with-waf = {
      description          = "Checks if AWS AppSync APIs are associated with AWS WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT for an AWS AppSync API if it is not associated with a web ACL."
      input_parameters     = var.appsync_associated_with_waf_parameters
      resource_types_scope = ["AWS::AppSync::GraphQLApi"]
      severity             = "Medium"
    }

    appsync-cache-encryption-at-rest = {
      description          = "Checks if an AWS AppSync API cache has encryption at rest enabled. This rule is NON_COMPLIANT if AtRestEncryptionEnabled is false."
      resource_types_scope = ["AWS::AppSync::GraphQLApi"]
      severity             = "Medium"
    }

    appsync-logging-enabled = {
      description          = "Checks if an AWS AppSync API has logging enabled. The rule is NON_COMPLIANT if logging is not enabled, or fieldLogLevel is neither ERROR nor ALL."
      input_parameters     = var.appsync_logging_enabled_parameters
      resource_types_scope = ["AWS::AppSync::GraphQLApi"]
      severity             = "Medium"
    }

    aurora-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Aurora DB clusters. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) DB Cluster does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.aurora_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    aurora-mysql-backtracking-enabled = {
      description          = "Checks if an Amazon Aurora MySQL cluster has backtracking enabled. The rule is NON_COMPLIANT if the Aurora cluster uses MySQL and it does not have backtracking enabled."
      input_parameters     = var.aurora_mysql_backtracking_enabled_parameters
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    aurora-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Aurora DB clusters are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon Relational Database Service (Amazon RDS) Database Cluster is not protected by a backup plan."
      input_parameters     = var.aurora_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    autoscaling-capacity-rebalancing = {
      description          = "Checks if Capacity Rebalancing is enabled for Amazon EC2 Auto Scaling groups that use multiple instance types. The rule is NON_COMPLIANT if capacity Rebalancing is not enabled."
      resource_types_scope = ["AWS::AutoScaling::AutoScalingGroup"]
      severity             = "Low"
    }

    autoscaling-group-elb-healthcheck-required = {
      description          = "Checks if your Amazon EC2 Auto Scaling groups that are associated with a Classic Load Balancer use Elastic Load Balancing health checks. The rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling groups are not using Elastic Load Balancing health checks."
      resource_types_scope = ["AWS::AutoScaling::AutoScalingGroup"]
      severity             = "Low"
    }

    autoscaling-launchconfig-requires-imdsv2 = {
      description          = "Checks whether only IMDSv2 is enabled. This rule is NON_COMPLIANT if the Metadata version is not included in the launch configuration or if both Metadata V1 and V2 are enabled."
      resource_types_scope = ["AWS::AutoScaling::LaunchConfiguration"]
      severity             = "Low"
    }

    autoscaling-launch-config-hop-limit = {
      description          = "Checks the number of network hops that the metadata token can travel. This rule is NON_COMPLIANT if the Metadata response hop limit is greater than 1."
      resource_types_scope = ["AWS::AutoScaling::LaunchConfiguration"]
      severity             = "Low"
    }

    autoscaling-launch-config-public-ip-disabled = {
      description          = "Checks if Amazon EC2 Auto Scaling groups have public IP addresses enabled through Launch Configurations. The rule is NON_COMPLIANT if the Launch Configuration for an Amazon EC2 Auto Scaling group has AssociatePublicIpAddress set to true ."
      resource_types_scope = ["AWS::AutoScaling::LaunchConfiguration"]
      severity             = "Medium"
    }

    autoscaling-launch-template = {
      description          = "Checks if an Amazon Elastic Compute Cloud (EC2) Auto Scaling group is created from an EC2 launch template. The rule is NON_COMPLIANT if the scaling group is not created from an EC2 launch template."
      resource_types_scope = ["AWS::AutoScaling::AutoScalingGroup"]
      severity             = "Low"
    }

    autoscaling-multiple-az = {
      description          = "Checks if the Auto Scaling group spans multiple Availability Zones. The rule is NON_COMPLIANT if the Auto Scaling group does not span multiple Availability Zones."
      input_parameters     = var.autoscaling_multiple_az_parameters
      resource_types_scope = ["AWS::AutoScaling::AutoScalingGroup"]
      severity             = "Medium"
    }

    autoscaling-multiple-instance-types = {
      description          = "Checks if an Amazon Elastic Compute Cloud (Amazon EC2) Auto Scaling group uses multiple instance types. This rule is NON_COMPLIANT if the Amazon EC2 Auto Scaling group has only one instance type defined."
      resource_types_scope = ["AWS::AutoScaling::AutoScalingGroup"]
      severity             = "Low"
    }

    backup-plan-min-frequency-and-min-retention-check = {
      description          = "Checks if a backup plan has a backup rule that satisfies the required frequency and retention period. The rule is NON_COMPLIANT if recovery points are not created at least as often as the specified frequency or expire before the specified period."
      input_parameters     = var.backup_plan_min_frequency_and_min_retention_check_parameters
      resource_types_scope = ["AWS::Backup::BackupPlan"]
      severity             = "Medium"
    }

    backup-recovery-point-encrypted = {
      description          = "Checks if a recovery point is encrypted. The rule is NON_COMPLIANT if the recovery point is not encrypted."
      resource_types_scope = ["AWS::Backup::RecoveryPoint"]
      severity             = "Medium"
    }

    backup-recovery-point-manual-deletion-disabled = {
      description          = "Checks if a backup vault has an attached resource-based policy which prevents deletion of recovery points. The rule is NON_COMPLIANT if the Backup Vault does not have resource-based policies or has policies without a suitable Deny statement (statement..."
      input_parameters     = var.backup_recovery_point_manual_deletion_disabled_parameters
      resource_types_scope = ["AWS::Backup::BackupVault"]
      severity             = "Medium"
    }

    backup-recovery-point-minimum-retention-check = {
      description          = "Checks if a recovery point expires no earlier than after the specified period. The rule is NON_COMPLIANT if the recovery point has a retention point that is less than the required retention period."
      input_parameters     = var.backup_recovery_point_minimum_retention_check_parameters
      resource_types_scope = ["AWS::Backup::RecoveryPoint"]
      severity             = "Medium"
    }

    beanstalk-enhanced-health-reporting-enabled = {
      description          = "Checks if an AWS Elastic Beanstalk environment is configured for enhanced health reporting. The rule is COMPLIANT if the environment is configured for enhanced health reporting. The rule is NON_COMPLIANT if the environment is configured for basic health..."
      resource_types_scope = ["AWS::ElasticBeanstalk::Environment"]
      severity             = "Low"
    }

    clb-desync-mode-check = {
      description          = "Checks if Classic Load Balancers (CLB) are configured with a user defined Desync mitigation mode. The rule is NON_COMPLIANT if CLB Desync mitigation mode does not match with user defined Desync mitigation mode."
      input_parameters     = var.clb_desync_mode_check_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    clb-multiple-az = {
      description          = "Checks if a Classic Load Balancer spans multiple Availability Zones (AZs). The rule is NON_COMPLIANT if a Classic Load Balancer spans less than 2 AZs or does not span number of AZs mentioned in the minAvailabilityZones parameter (if provided)."
      input_parameters     = var.clb_multiple_az_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    cloudformation-stack-drift-detection-check = {
      description          = "Checks if the actual configuration of a Cloud Formation stack differs, or has drifted, from the expected configuration. A stack is considered to have drifted if one or more of its resources differ from their expected configuration. The rule and the..."
      input_parameters     = var.cloudformation_stack_drift_detection_check_parameters
      resource_types_scope = ["AWS::CloudFormation::Stack"]
      severity             = "Low"
    }

    cloudformation-stack-notification-check = {
      description          = "Checks if your CloudFormation stacks send event notifications to an Amazon SNS topic. Optionally checks if specified Amazon SNS topics are used. The rule is NON_COMPLIANT if CloudFormation stacks do not send notifications."
      input_parameters     = var.cloudformation_stack_notification_check_parameters
      resource_types_scope = ["AWS::CloudFormation::Stack"]
      severity             = "Low"
    }

    cloudfront-accesslogs-enabled = {
      description          = "Checks if Amazon CloudFront distributions are configured to capture information from Amazon Simple Storage Service (Amazon S3) server access logs. The rule is NON_COMPLIANT if a CloudFront distribution does not have logging configured."
      input_parameters     = var.cloudfront_accesslogs_enabled_parameters
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-associated-with-waf = {
      description          = "Checks if Amazon CloudFront distributions are associated with either web application firewall (WAF) or WAFv2 web access control lists (ACLs). The rule is NON_COMPLIANT if a CloudFront distribution is not associated with a WAF web ACL."
      input_parameters     = var.cloudfront_associated_with_waf_parameters
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-custom-ssl-certificate = {
      description          = "Checks if the certificate associated with an Amazon CloudFront distribution is the default SSL certificate. The rule is NON_COMPLIANT if a CloudFront distribution uses the default SSL certificate."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Low"
    }

    cloudfront-default-root-object-configured = {
      description          = "Checks if an Amazon CloudFront distribution is configured to return a specific object that is the default root object. The rule is NON_COMPLIANT if Amazon CloudFront distribution does not have a default root object configured."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Critical"
    }

    cloudfront-no-deprecated-ssl-protocols = {
      description          = "Checks if CloudFront distributions are using deprecated SSL protocols for HTTPS communication between CloudFront edge locations and custom origins. This rule is NON_COMPLIANT for a CloudFront distribution if any OriginSslProtocols includes SSLv3 ."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "High"
    }

    cloudfront-origin-access-identity-enabled = {
      description          = "Checks if CloudFront distribution with Amazon S3 Origin type has origin access identity configured. The rule is NON_COMPLIANT if the CloudFront distribution is backed by S3 and any origin type is not OAI configured, or the origin is not an S3 bucket."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-origin-failover-enabled = {
      description          = "Checks if an origin group is configured for the distribution of at least two origins in the origin group for Amazon CloudFront. The rule is NON_COMPLIANT if there are no origin groups for the distribution."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Low"
    }

    cloudfront-s3-origin-access-control-enabled = {
      description          = "Checks if an Amazon CloudFront distribution with an Amazon Simple Storage Service (Amazon S3) Origin type has origin access control (OAC) enabled. The rule is NON_COMPLIANT for CloudFront distributions with Amazon S3 origins that don t have OAC enabled."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-s3-origin-non-existent-bucket = {
      description          = "Checks if Amazon CloudFront distributions point to a non-existent S3 bucket. The rule is NON_COMPLIANT if S3OriginConfig for a CloudFront distribution points to a non-existent S3 bucket. The rule does not evaluate S3 buckets with static website hosting."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-security-policy-check = {
      description          = "Checks if Amazon CloudFront distributions are using a minimum security policy and cipher suite of TLSv1.2 or greater for viewer connections. This rule is NON_COMPLIANT for a CloudFront distribution if the minimumProtocolVersion is below TLSv1.2_2018."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-sni-enabled = {
      description          = "Checks if Amazon CloudFront distributions are using a custom SSL certificate and are configured to use SNI to serve HTTPS requests. The rule is NON_COMPLIANT if a custom SSL certificate is associated but the SSL support method is a dedicated IP address."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudfront-traffic-to-origin-encrypted = {
      description          = "Checks if Amazon CloudFront distributions are encrypting traffic to custom origins. The rule is NON_COMPLIANT if OriginProtocolPolicy is http-only or if OriginProtocolPolicy is match-viewer and ViewerProtocolPolicy is allow-all ."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Critical"
    }

    cloudfront-viewer-policy-https = {
      description          = "Checks if your Amazon CloudFront distributions use HTTPS (directly or via a redirection). The rule is NON_COMPLIANT if the value of ViewerProtocolPolicy is set to allow-all for the DefaultCacheBehavior or for the CacheBehaviors."
      resource_types_scope = ["AWS::CloudFront::Distribution"]
      severity             = "Medium"
    }

    cloudtrail-s3-dataevents-enabled = {
      description      = "Checks if at least one AWS CloudTrail trail is logging Amazon Simple Storage Service (Amazon S3) data events for all S3 buckets. The rule is NON_COMPLIANT if there are trails or if no trails record S3 data events."
      input_parameters = var.cloudtrail_s3_dataevents_enabled_parameters
      severity         = "Medium"
    }

    cloudtrail-security-trail-enabled = {
      description = "Checks that there is at least one AWS CloudTrail trail defined with security best practices. This rule is COMPLIANT if there is at least one trail that meets all of the following:"
      severity    = "Medium"
    }

    cloudwatch-alarm-action-check = {
      description          = "Checks if CloudWatch alarms have an action configured for the ALARM, INSUFFICIENT_DATA, or OK state. Optionally checks if any actions match a named ARN. The rule is NON_COMPLIANT if there is no action specified for the alarm or optional parameter."
      input_parameters     = var.cloudwatch_alarm_action_check_parameters
      resource_types_scope = ["AWS::CloudWatch::Alarm"]
      severity             = "Medium"
    }

    cloudwatch-alarm-action-enabled-check = {
      description          = "Checks if Amazon CloudWatch alarms actions are in enabled state. The rule is NON_COMPLIANT if the CloudWatch alarms actions are not in enabled state."
      resource_types_scope = ["AWS::CloudWatch::Alarm"]
      severity             = "High"
    }

    cloudwatch-alarm-resource-check = {
      description      = "Checks if a resource type has a CloudWatch alarm for the named metric. For resource type, you can specify EBS volumes, EC2 instances, Amazon RDS clusters, or S3 buckets. The rule is COMPLIANT if the named metric has a resource ID and CloudWatch alarm."
      input_parameters = var.cloudwatch_alarm_resource_check_parameters
      severity         = "Medium"
    }

    cloudwatch-alarm-settings-check = {
      description          = "Checks whether CloudWatch alarms with the given metric name have the specified settings."
      input_parameters     = var.cloudwatch_alarm_settings_check_parameters
      resource_types_scope = ["AWS::CloudWatch::Alarm"]
      severity             = "Medium"
    }

    cloudwatch-log-group-encrypted = {
      description      = "Checks if Amazon CloudWatch Log Groups are encrypted with any AWS KMS key or a specified AWS KMS key Id. The rule is NON_COMPLIANT if a CloudWatch Log Group is not encrypted with a KMS key or is encrypted with a KMS key not supplied in the rule parameter."
      input_parameters = var.cloudwatch_log_group_encrypted_parameters
      severity         = "Medium"
    }

    cloud-trail-cloud-watch-logs-enabled = {
      description      = "Checks if AWS CloudTrail trails are configured to send logs to CloudWatch logs. The trail is NON_COMPLIANT if the CloudWatchLogsLogGroupArn property of the trail is empty."
      input_parameters = var.cloud_trail_cloud_watch_logs_enabled_parameters
      severity         = "Low"
    }

    cloud-trail-enabled = {
      description      = "Checks if an AWS CloudTrail trail is enabled in your AWS account. The rule is NON_COMPLIANT if a trail is not enabled. Optionally, the rule checks a specific S3 bucket, Amazon Simple Notification Service (Amazon SNS) topic, and CloudWatch log group."
      input_parameters = var.cloud_trail_enabled_parameters
      severity         = "High"
    }

    cloud-trail-encryption-enabled = {
      description = "Checks if AWS CloudTrail is configured to use the server side encryption (SSE) AWS Key Management Service (AWS KMS) encryption. The rule is COMPLIANT if the KmsKeyId is defined."
      severity    = "Medium"
    }

    cloud-trail-log-file-validation-enabled = {
      description = "Checks if AWS CloudTrail creates a signed digest file with logs. AWS recommends that the file validation must be enabled on all trails. The rule is NON_COMPLIANT if the validation is not enabled."
      severity    = "Low"
    }

    cmk-backing-key-rotation-enabled = {
      description = "Checks if automatic key rotation is enabled for each key and matches to the key ID of the customer created AWS KMS key. The rule is NON_COMPLIANT if the AWS Config recorder role for a resource does not have the kms:DescribeKey permission."
      severity    = "Medium"
    }

    codebuild-project-artifact-encryption = {
      description          = "Checks if an AWS CodeBuild project has encryption enabled for all of its artifacts. The rule is NON_COMPLIANT if encryptionDisabled is set to true for any primary or secondary (if present) artifact configurations."
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Medium"
    }

    codebuild-project-environment-privileged-check = {
      description          = "Checks if an AWS CodeBuild project environment has privileged mode enabled. The rule is NON_COMPLIANT for a CodeBuild project if privilegedMode is set to true ."
      input_parameters     = var.codebuild_project_environment_privileged_check_parameters
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Medium"
    }

    codebuild-project-envvar-awscred-check = {
      description          = "Checks if the project contains environment variables AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY. The rule is NON_COMPLIANT when the project environment variables contains plaintext credentials."
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Critical"
    }

    codebuild-project-logging-enabled = {
      description          = "Checks if an AWS CodeBuild project environment has at least one log option enabled. The rule is NON_COMPLIANT if the status of all present log configurations is set to DISABLED ."
      input_parameters     = var.codebuild_project_logging_enabled_parameters
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Medium"
    }

    codebuild-project-s3-logs-encrypted = {
      description          = "Checks if a AWS CodeBuild project configured with Amazon S3 Logs has encryption enabled for its logs. The rule is NON_COMPLIANT if encryptionDisabled is set to true in a S3LogsConfig of a CodeBuild project."
      input_parameters     = var.codebuild_project_s3_logs_encrypted_parameters
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Medium"
    }

    codebuild-project-source-repo-url-check = {
      description          = "Checks if the GitHub or Bitbucket source repository URL contains either personal access tokens or sign-in credentials. The rule is COMPLIANT with the usage of OAuth to grant authorization for accessing GitHub or Bitbucket repositories."
      resource_types_scope = ["AWS::CodeBuild::Project"]
      severity             = "Critical"
    }

    codedeploy-auto-rollback-monitor-enabled = {
      description          = "Checks if the deployment group is configured with automatic deployment rollback and deployment monitoring with alarms attached. The rule is NON_COMPLIANT if AutoRollbackConfiguration or AlarmConfiguration has not been configured or is not enabled."
      resource_types_scope = ["AWS::CodeDeploy::DeploymentGroup"]
      severity             = "Medium"
    }

    codedeploy-ec2-minimum-healthy-hosts-configured = {
      description          = "Checks if the deployment group for EC2/On-Premises Compute Platform is configured with a minimum healthy hosts fleet percentage or host count greater than or equal to the input threshold. The rule is NON_COMPLIANT if either is below the threshold."
      input_parameters     = var.codedeploy_ec2_minimum_healthy_hosts_configured_parameters
      resource_types_scope = ["AWS::CodeDeploy::DeploymentGroup"]
      severity             = "Medium"
    }

    codedeploy-lambda-allatonce-traffic-shift-disabled = {
      description          = "Checks if the deployment group for Lambda Compute Platform is not using the default deployment configuration. The rule is NON_COMPLIANT if the deployment group is using the deployment configuration CodeDeployDefault.LambdaAllAtOnce ."
      resource_types_scope = ["AWS::CodeDeploy::DeploymentGroup"]
      severity             = "Medium"
    }

    codepipeline-deployment-count-check = {
      description          = "Checks if the first deployment stage of AWS CodePipeline performs more than one deployment. Optionally checks if each of the subsequent remaining stages deploy to more than the specified number of deployments ( deploymentLimit )."
      input_parameters     = var.codepipeline_deployment_count_check_parameters
      resource_types_scope = ["AWS::CodePipeline::Pipeline"]
      severity             = "Low"
    }

    codepipeline-region-fanout-check = {
      description          = "Checks if each stage in the AWS CodePipeline deploys to more than N times the number of the regions the AWS CodePipeline has deployed in all the previous combined stages, where N is the region fanout number. The first deployment stage can deploy to a..."
      input_parameters     = var.codepipeline_region_fanout_check_parameters
      resource_types_scope = ["AWS::CodePipeline::Pipeline"]
      severity             = "Low"
    }

    custom-schema-registry-policy-attached = {
      description          = "Checks if custom Amazon EventBridge schema registries have a resource policy attached. The rule is NON_COMPLIANT for custom schema registries without a resource policy attached."
      resource_types_scope = ["AWS::EventSchemas::Registry"]
      severity             = "Medium"
    }

    cw-loggroup-retention-period-check = {
      description      = "Checks if Amazon CloudWatch LogGroup retention period is set to specific number of days. The rule is NON_COMPLIANT if the retention period for the log group is less than the MinRetentionTime parameter."
      input_parameters = var.cw_loggroup_retention_period_check_parameters
      severity         = "Medium"
    }

    dax-encryption-enabled = {
      description = "Checks if Amazon DynamoDB Accelerator (DAX) clusters are encrypted. The rule is NON_COMPLIANT if a DAX cluster is not encrypted."
      severity    = "Medium"
    }

    db-instance-backup-enabled = {
      description          = "Checks if RDS DB instances have backups enabled. Optionally, the rule checks the backup retention period and the backup window."
      input_parameters     = var.db_instance_backup_enabled_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    desired-instance-tenancy = {
      description          = "Checks EC2 instances for a tenancy value. Also checks if AMI IDs are specified to be launched from those AMIs or if Host IDs are launched on those Dedicated Hosts. The rule is COMPLIANT if the instance matches a host and an AMI, if specified, in a list."
      input_parameters     = var.desired_instance_tenancy_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    desired-instance-type = {
      description          = "Checks if your EC2 instances are of a specific instance type. The rule is NON_COMPLIANT if an EC2 instance is not specified in the parameter list. For a list of supported EC2 instance types, see Instance types in the EC2 User Guide for Linux Instances."
      input_parameters     = var.desired_instance_type_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    dms-replication-not-public = {
      description = "Checks if AWS Database Migration Service (AWS DMS) replication instances are public. The rule is NON_COMPLIANT if PubliclyAccessible field is set to true."
      severity    = "Critical"
    }

    dynamodb-autoscaling-enabled = {
      description          = "Checks if Amazon DynamoDB tables or global secondary indexes can process read/write capacity using on-demand mode or provisioned mode with auto scaling enabled. The rule is NON_COMPLIANT if either mode is used without auto scaling enabled"
      input_parameters     = var.dynamodb_autoscaling_enabled_parameters
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Low"
    }

    dynamodb-in-backup-plan = {
      description          = "Checks whether Amazon DynamoDB table is present in AWS Backup Plans. The rule is NON_COMPLIANT if Amazon DynamoDB tables are not present in any AWS Backup plan."
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon DynamoDB Tables within the specified period. The rule is NON_COMPLIANT if the DynamoDB Table does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.dynamodb_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-pitr-enabled = {
      description          = "Checks if point-in-time recovery (PITR) is enabled for Amazon DynamoDB tables. The rule is NON_COMPLIANT if PITR is not enabled for DynamoDB tables."
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon DynamoDB tables are protected by a backup plan. The rule is NON_COMPLIANT if the DynamoDB Table is not covered by a backup plan."
      input_parameters     = var.dynamodb_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-table-encrypted-kms = {
      description          = "Checks if Amazon DynamoDB table is encrypted with AWS Key Management Service (KMS). The rule is NON_COMPLIANT if Amazon DynamoDB table is not encrypted with AWS KMS. The rule is also NON_COMPLIANT if the encrypted AWS KMS key is not present in..."
      input_parameters     = var.dynamodb_table_encrypted_kms_parameters
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-table-encryption-enabled = {
      description          = "Checks if the Amazon DynamoDB tables are encrypted and checks their status. The rule is COMPLIANT if the status is enabled or enabling."
      resource_types_scope = ["AWS::DynamoDB::Table"]
      severity             = "Medium"
    }

    dynamodb-throughput-limit-check = {
      description      = "Checks if provisioned DynamoDB throughput is approaching the maximum limit for your account. By default, the rule checks if provisioned throughput exceeds a threshold of 80 percent of your account limits."
      input_parameters = var.dynamodb_throughput_limit_check_parameters
      severity         = "Medium"
    }

    ebs-in-backup-plan = {
      description = "Check if Amazon Elastic Block Store (Amazon EBS) volumes are added in backup plans of AWS Backup. The rule is NON_COMPLIANT if Amazon EBS volumes are not included in backup plans."
      severity    = "Medium"
    }

    ebs-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Elastic Block Store (Amazon EBS). The rule is NON_COMPLIANT if the Amazon EBS volume does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.ebs_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::EC2::Volume"]
      severity             = "Medium"
    }

    ebs-optimized-instance = {
      description          = "Checks if Amazon EBS optimization is enabled for your Amazon Elastic Compute Cloud (Amazon EC2) instances that can be Amazon EBS-optimized. The rule is NON_COMPLIANT if EBS optimization is not enabled for an Amazon EC2 instance that can be EBS-optimized."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ebs-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Elastic Block Store (Amazon EBS) volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EBS volume is not covered by a backup plan."
      input_parameters     = var.ebs_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::EC2::Volume"]
      severity             = "Medium"
    }

    ebs-snapshot-public-restorable-check = {
      description = "Checks if Amazon Elastic Block Store (Amazon EBS) snapshots are not publicly restorable. The rule is NON_COMPLIANT if one or more snapshots with RestorableByUserIds field are set to all, that is, Amazon EBS snapshots are public."
      severity    = "Critical"
    }

    ec2-client-vpn-not-authorize-all = {
      description          = "Checks if the AWS Client VPN authorization rules authorizes connection access for all clients. The rule is NON_COMPLIANT if AccessAll is present and set to true."
      resource_types_scope = ["AWS::EC2::ClientVpnEndpoint"]
      severity             = "Medium"
    }

    ec2-ebs-encryption-by-default = {
      description = "Checks if Amazon Elastic Block Store (EBS) encryption is enabled by default. The rule is NON_COMPLIANT if the encryption is not enabled."
      severity    = "Medium"
    }

    ec2-imdsv2-check = {
      description          = "Checks if your Amazon Elastic Compute Cloud (Amazon EC2) instance metadata version is configured with Instance Metadata Service Version 2 (IMDSv2). The rule is NON_COMPLIANT if the HttpTokens is set to optional."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "High"
    }

    ec2-instance-detailed-monitoring-enabled = {
      description          = "Checks if detailed monitoring is enabled for EC2 instances. The rule is NON_COMPLIANT if detailed monitoring is not enabled."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-instance-managed-by-ssm = {
      description          = "Checks if your Amazon EC2 instances are managed by AWS Systems Manager (SSM Agent). The rule is NON_COMPLIANT if the EC2 instance previously associated with an SSM Agent instance inventory becomes unreachable or is not managed by SSM Agent."
      resource_types_scope = ["AWS::EC2::Instance", "AWS::SSM::ManagedInstanceInventory"]
      severity             = "Medium"
    }

    ec2-instance-multiple-eni-check = {
      description          = "Checks if Amazon Elastic Compute Cloud (Amazon EC2) uses multiple Elastic Network Interfaces (ENIs) or Elastic Fabric Adapters (EFAs). The rule is NON_COMPLIANT an Amazon EC2 instance use multiple network interfaces."
      input_parameters     = var.ec2_instance_multiple_eni_check_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-instance-no-public-ip = {
      description          = "Checks if EC2 instances have a public IP association. The rule is NON_COMPLIANT if the publicIp field is present in the EC2 instance configuration item. The rule applies only to IPv4."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "High"
    }

    ec2-instance-profile-attached = {
      description          = "Checks if an EC2 instance has an AWS Identity and Access Management (IAM) profile attached to it. The rule is NON_COMPLIANT if no IAM profile is attached to the EC2 instance."
      input_parameters     = var.ec2_instance_profile_attached_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Elastic Compute Cloud (Amazon EC2) instances. The rule is NON_COMPLIANT if the Amazon EC2 instance does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.ec2_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Medium"
    }

    ec2-launch-template-public-ip-disabled = {
      description          = "Checks if Amazon EC2 Launch Templates are set to assign public IP addresses to Network Interfaces. The rule is NON_COMPLIANT if the default version of an EC2 Launch Template has at least 1 Network Interface with AssociatePublicIpAddress set to true ."
      input_parameters     = var.ec2_launch_template_public_ip_disabled_parameters
      resource_types_scope = ["AWS::EC2::LaunchTemplate"]
      severity             = "Medium"
    }

    ec2-managedinstance-applications-blacklisted = {
      description          = "Checks if none of the specified applications are installed on the instance. Optionally, specify the version. Newer versions will not be denylisted. Optionally, specify the platform to apply the rule only to instances running that platform."
      input_parameters     = var.ec2_managedinstance_applications_blacklisted_parameters
      resource_types_scope = ["AWS::SSM::ManagedInstanceInventory"]
      severity             = "Medium"
    }

    ec2-managedinstance-applications-required = {
      description          = "Checks if all of the specified applications are installed on the instance. Optionally, specify the minimum acceptable version. You can also specify the platform to apply the rule only to instances running that platform."
      input_parameters     = var.ec2_managedinstance_applications_required_parameters
      resource_types_scope = ["AWS::SSM::ManagedInstanceInventory"]
      severity             = "Medium"
    }

    ec2-managedinstance-association-compliance-status-check = {
      description          = "Checks if the status of the AWS Systems Manager association compliance is COMPLIANT or NON_COMPLIANT after the association execution on the instance. The rule is compliant if the field status is COMPLIANT.For more information about associations, see..."
      resource_types_scope = ["AWS::SSM::AssociationCompliance"]
      severity             = "Low"
    }

    ec2-managedinstance-inventory-blacklisted = {
      description          = "Checks whether instances managed by Amazon EC2 Systems Manager are configured to collect blacklisted inventory types."
      input_parameters     = var.ec2_managedinstance_inventory_blacklisted_parameters
      resource_types_scope = ["AWS::SSM::ManagedInstanceInventory"]
      severity             = "Medium"
    }

    ec2-managedinstance-patch-compliance-status-check = {
      description          = "Checks if the compliance status of the AWS Systems Manager patch compliance is COMPLIANT or NON_COMPLIANT after the patch installation on the instance. The rule is compliant if the field status is COMPLIANT."
      resource_types_scope = ["AWS::SSM::PatchCompliance"]
      severity             = "Medium"
    }

    ec2-managedinstance-platform-check = {
      description          = "Checks whether EC2 managed instances have the desired configurations."
      input_parameters     = var.ec2_managedinstance_platform_check_parameters
      resource_types_scope = ["AWS::SSM::ManagedInstanceInventory"]
      severity             = "Medium"
    }

    ec2-no-amazon-key-pair = {
      description          = "Checks if running Amazon Elastic Compute Cloud (EC2) instances are launched using amazon key pairs. The rule is NON_COMPLIANT if a running EC2 instance is launched with a key pair."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-paravirtual-instance-check = {
      description          = "Checks if the virtualization type of an EC2 instance is paravirtual. This rule is NON_COMPLIANT for an EC2 instance if virtualizationType is set to paravirtual ."
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Elastic Compute Cloud (Amazon EC2) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon EC2 instance is not covered by a backup plan."
      input_parameters     = var.ec2_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Medium"
    }

    ec2-security-group-attached-to-eni = {
      description          = "Checks if non-default security groups are attached to elastic network interfaces. The rule is NON_COMPLIANT if the security group is not associated with a network interface."
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "Low"
    }

    ec2-security-group-attached-to-eni-periodic = {
      description          = "Checks if non-default security groups are attached to Elastic network interfaces (ENIs). The rule is NON_COMPLIANT if the security group is not associated with an ENI. Security groups not owned by the calling account evaluate as NOT_APPLICABLE."
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "Low"
    }

    ec2-stopped-instance = {
      description      = "Checks if there are Amazon Elastic Compute Cloud (Amazon EC2) instances stopped for more than the allowed number of days. The rule is NON_COMPLIANT if the state of an Amazon EC2 instance has been stopped for longer than the allowed number of days, or if..."
      input_parameters = var.ec2_stopped_instance_parameters
      severity         = "Low"
    }

    ec2-token-hop-limit-check = {
      description          = "Checks if an Amazon Elastic Compute Cloud (EC2) instance metadata has a specified token hop limit that is below the desired limit. The rule is NON_COMPLIANT for an instance if it has a hop limit value above the intended limit."
      input_parameters     = var.ec2_token_hop_limit_check_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Low"
    }

    ec2-transit-gateway-auto-vpc-attach-disabled = {
      description          = "Checks if Amazon Elastic Compute Cloud (Amazon EC2) Transit Gateways have AutoAcceptSharedAttachments enabled. The rule is NON_COMPLIANT for a Transit Gateway if AutoAcceptSharedAttachments is set to enable ."
      resource_types_scope = ["AWS::EC2::TransitGateway"]
      severity             = "Low"
    }

    ec2-volume-inuse-check = {
      description          = "Checks if EBS volumes are attached to EC2 instances. Optionally checks if EBS volumes are marked for deletion when an instance is terminated."
      input_parameters     = var.ec2_volume_inuse_check_parameters
      resource_types_scope = ["AWS::EC2::Volume"]
      severity             = "Low"
    }

    ecr-private-image-scanning-enabled = {
      description          = "Checks if a private Amazon Elastic Container Registry (ECR) repository has image scanning enabled. The rule is NON_COMPLIANT if the private ECR repository's scan frequency is not on scan on push or continuous scan."
      resource_types_scope = ["AWS::ECR::Repository"]
      severity             = "Medium"
    }

    ecr-private-lifecycle-policy-configured = {
      description          = "Checks if a private Amazon Elastic Container Registry (ECR) repository has at least one lifecycle policy configured. The rule is NON_COMPLIANT if no lifecycle policy is configured for the ECR private repository."
      resource_types_scope = ["AWS::ECR::Repository"]
      severity             = "Medium"
    }

    ecr-private-tag-immutability-enabled = {
      description          = "Checks if a private Amazon Elastic Container Registry (ECR) repository has tag immutability enabled. This rule is NON_COMPLIANT if tag immutability is not enabled for the private ECR repository."
      resource_types_scope = ["AWS::ECR::Repository"]
      severity             = "Medium"
    }

    ecs-awsvpc-networking-enabled = {
      description          = "Checks if the networking mode for active ECSTaskDefinitions is set to awsvpc . This rule is NON_COMPLIANT if active ECSTaskDefinitions is not set to awsvpc ."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Medium"
    }

    ecs-containers-nonprivileged = {
      description          = "Checks if the privileged parameter in the container definition of ECSTaskDefinitions is set to true . The rule is NON_COMPLIANT if the privileged parameter is true ."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Medium"
    }

    ecs-containers-readonly-access = {
      description          = "Checks if Amazon Elastic Container Service (Amazon ECS) Containers only have read-only access to its root filesystems. The rule is NON_COMPLIANT if the readonlyRootFilesystem parameter in the container definition of ECSTaskDefinitions is set to false ."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Medium"
    }

    ecs-container-insights-enabled = {
      description          = "Checks if Amazon Elastic Container Service clusters have container insights enabled. The rule is NON_COMPLIANT if container insights are not enabled."
      resource_types_scope = ["AWS::ECS::Cluster"]
      severity             = "Medium"
    }

    ecs-fargate-latest-platform-version = {
      description          = "Checks if ECS Fargate services is set to the latest platform version. The rule is NON_COMPLIANT if PlatformVersion for the Fargate launch type is not set to LATEST, or if neither latestLinuxVersion nor latestWindowsVersion are provided as parameters."
      input_parameters     = var.ecs_fargate_latest_platform_version_parameters
      resource_types_scope = ["AWS::ECS::Service"]
      severity             = "Low"
    }

    ecs-no-environment-secrets = {
      description          = "Checks if secrets are passed as container environment variables. The rule is NON_COMPLIANT if 1 or more environment variable key matches a key listed in the secretKeys parameter (excluding environmental variables from other locations such as Amazon S3)."
      input_parameters     = var.ecs_no_environment_secrets_parameters
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Critical"
    }

    ecs-task-definition-log-configuration = {
      description          = "Checks if logConfiguration is set on active ECS Task Definitions. This rule is NON_COMPLIANT if an active ECSTaskDefinition does not have the logConfiguration resource defined or the value for logConfiguration is null in at least one container definition."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Medium"
    }

    ecs-task-definition-memory-hard-limit = {
      description          = "Checks if Amazon Elastic Container Service (ECS) task definitions have a set memory limit for its container definitions. The rule is NON_COMPLIANT for a task definition if the memory parameter is absent for one container definition."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "Medium"
    }

    ecs-task-definition-nonroot-user = {
      description          = "Checks if ECSTaskDefinitions specify a user for Amazon Elastic Container Service (Amazon ECS) EC2 launch type containers to run on. The rule is NON_COMPLIANT if the user parameter is not present or set to root ."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "High"
    }

    ecs-task-definition-pid-mode-check = {
      description          = "Checks if ECSTaskDefinitions are configured to share a host's process namespace with its Amazon Elastic Container Service (Amazon ECS) containers. The rule is NON_COMPLIANT if the pidMode parameter is set to host ."
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "High"
    }

    ecs-task-definition-user-for-host-mode-check = {
      description          = "Checks if an Amazon Elastic Container Service (Amazon ECS) task definition with host networking mode has privileged or user container definitions. The rule is NON_COMPLIANT for task definitions with host network mode and container definitions of..."
      input_parameters     = var.ecs_task_definition_user_for_host_mode_check_parameters
      resource_types_scope = ["AWS::ECS::TaskDefinition"]
      severity             = "High"
    }

    efs-access-point-enforce-root-directory = {
      description          = "Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a root directory. The rule is NON_COMPLIANT if the value of Path is set to / (default root directory of the file system)."
      input_parameters     = var.efs_access_point_enforce_root_directory_parameters
      resource_types_scope = ["AWS::EFS::AccessPoint"]
      severity             = "Medium"
    }

    efs-access-point-enforce-user-identity = {
      description          = "Checks if Amazon Elastic File System (Amazon EFS) access points are configured to enforce a user identity. The rule is NON_COMPLIANT if PosixUser is not defined or if parameters are provided and there is no match in the corresponding parameter."
      input_parameters     = var.efs_access_point_enforce_user_identity_parameters
      resource_types_scope = ["AWS::EFS::AccessPoint"]
      severity             = "High"
    }

    efs-encrypted-check = {
      description      = "Checks if Amazon Elastic File System (Amazon EFS) is configured to encrypt the file data using AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the encrypted key is set to false on DescribeFileSystems or if the KmsKeyId key on..."
      input_parameters = var.efs_encrypted_check_parameters
      severity         = "Medium"
    }

    efs-in-backup-plan = {
      description = "Checks if Amazon Elastic File System (Amazon EFS) file systems are added in the backup plans of AWS Backup. The rule is NON_COMPLIANT if EFS file systems are not included in the backup plans."
      severity    = "Medium"
    }

    efs-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Elastic File System (Amazon EFS) File Systems. The rule is NON_COMPLIANT if the Amazon EFS File System does not have a corresponding Recovery Point created within the specified time period."
      input_parameters     = var.efs_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::EFS::FileSystem"]
      severity             = "Medium"
    }

    efs-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Elastic File System (Amazon EFS) File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the EFS File System is not covered by a backup plan."
      input_parameters     = var.efs_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::EFS::FileSystem"]
      severity             = "Medium"
    }

    eip-attached = {
      description          = "Checks if all Elastic IP addresses that are allocated to an AWS account are attached to EC2 instances or in-use elastic network interfaces. The rule is NON_COMPLIANT if the AssociationId is null for the Elastic IP address."
      resource_types_scope = ["AWS::EC2::EIP"]
      severity             = "Low"
    }

    eks-cluster-logging-enabled = {
      description          = "Checks if an Amazon Elastic Kubernetes Service (Amazon EKS) cluster is configured with logging enabled. The rule is NON_COMPLIANT if logging for Amazon EKS clusters is not enabled for all log types."
      resource_types_scope = ["AWS::EKS::Cluster"]
      severity             = "Medium"
    }

    eks-cluster-oldest-supported-version = {
      description          = "Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running the oldest supported version. The rule is NON_COMPLIANT if an EKS cluster is running oldest supported version (equal to the parameter oldestVersionSupported )."
      input_parameters     = var.eks_cluster_oldest_supported_version_parameters
      resource_types_scope = ["AWS::EKS::Cluster"]
      severity             = "Medium"
    }

    eks-cluster-supported-version = {
      description          = "Checks if an Amazon Elastic Kubernetes Service (EKS) cluster is running a supported Kubernetes version. This rule is NON_COMPLIANT if an EKS cluster is running an unsupported version (less than the parameter oldestVersionSupported )."
      input_parameters     = var.eks_cluster_supported_version_parameters
      resource_types_scope = ["AWS::EKS::Cluster"]
      severity             = "Medium"
    }

    eks-endpoint-no-public-access = {
      description = "Checks if the Amazon Elastic Kubernetes Service (Amazon EKS) endpoint is not publicly accessible. The rule is NON_COMPLIANT if the endpoint is publicly accessible."
      severity    = "Medium"
    }

    eks-secrets-encrypted = {
      description      = "Checks if Amazon Elastic Kubernetes Service clusters are configured to have Kubernetes secrets encrypted using AWS Key Management Service (KMS) keys."
      input_parameters = var.eks_secrets_encrypted_parameters
      severity         = "Medium"
    }

    elasticache-auto-minor-version-upgrade-check = {
      description          = "Checks if Amazon ElastiCache for Redis clusters have auto minor version upgrades enabled. The rule is NON_COMPLIANT for an ElastiCache cluster if it is using the Redis engine and AutoMinorVersionUpgrade is not set to true ."
      resource_types_scope = ["AWS::ElastiCache::CacheCluster"]
      severity             = "Medium"
    }

    elasticache-rbac-auth-enabled = {
      description          = "Checks if Amazon ElastiCache replication groups have RBAC authentication enabled. The rule is NON_COMPLIANT if the Redis version is 6 or above and UserGroupIds is missing, empty, or does not match an entry provided by the allowedUserGroupIDs parameter."
      input_parameters     = var.elasticache_rbac_auth_enabled_parameters
      resource_types_scope = ["AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-redis-cluster-automatic-backup-check = {
      description          = "Check if the Amazon ElastiCache Redis clusters have automatic backup turned on. The rule is NON_COMPLIANT if the SnapshotRetentionLimit for Redis cluster is less than the SnapshotRetentionPeriod parameter. For example: If the parameter is 15 then the..."
      input_parameters     = var.elasticache_redis_cluster_automatic_backup_check_parameters
      resource_types_scope = ["AWS::ElastiCache::CacheCluster", "AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-repl-grp-auto-failover-enabled = {
      description          = "Checks if Amazon ElastiCache Redis replication groups have automatic failover enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if AutomaticFailover is not set to enabled ."
      resource_types_scope = ["AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-repl-grp-encrypted-at-rest = {
      description          = "Checks if Amazon ElastiCache replication groups have encryption-at-rest enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if AtRestEncryptionEnabled is disabled or if the KMS key ARN does not match the approvedKMSKeyArns parameter."
      input_parameters     = var.elasticache_repl_grp_encrypted_at_rest_parameters
      resource_types_scope = ["AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-repl-grp-encrypted-in-transit = {
      description          = "Checks if Amazon ElastiCache replication groups have encryption-in-transit enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if TransitEncryptionEnabled is set to false ."
      resource_types_scope = ["AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-repl-grp-redis-auth-enabled = {
      description          = "Checks if Amazon ElastiCache replication groups have Redis AUTH enabled. The rule is NON_COMPLIANT for an ElastiCache replication group if the Redis version of its nodes is below 6 (Version 6+ use Redis ACLs) and AuthToken is missing or is empty/null."
      resource_types_scope = ["AWS::ElastiCache::ReplicationGroup"]
      severity             = "Medium"
    }

    elasticache-subnet-group-check = {
      description          = "Checks if Amazon ElastiCache clusters are configured with a custom subnet group. The rule is NON_COMPLIANT for an ElastiCache cluster if it is using a default subnet group."
      resource_types_scope = ["AWS::ElastiCache::CacheCluster"]
      severity             = "Medium"
    }

    elasticache-supported-engine-version = {
      description          = "Checks if ElastiCache clusters are running a version greater or equal to the recommended engine version. The rule is NON_COMPLIANT if the EngineVersion for an ElastiCache cluster is less than the specified recommended version for its given engine."
      input_parameters     = var.elasticache_supported_engine_version_parameters
      resource_types_scope = ["AWS::ElastiCache::CacheCluster"]
      severity             = "Medium"
    }

    elasticsearch-encrypted-at-rest = {
      description = "Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled."
      severity    = "Medium"
    }

    elasticsearch-in-vpc-only = {
      description = "Checks if Amazon OpenSearch Service (previously called Elasticsearch) domains are in Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public."
      severity    = "Critical"
    }

    elasticsearch-logs-to-cloudwatch = {
      description          = "Checks if Amazon OpenSearch Service domains are configured to send logs to Amazon CloudWatch Logs. The rule is COMPLIANT if a log is enabled for an Amazon ES domain. This rule is NON_COMPLIANT if logging is not configured."
      input_parameters     = var.elasticsearch_logs_to_cloudwatch_parameters
      resource_types_scope = ["AWS::Elasticsearch::Domain"]
      severity             = "Low"
    }

    elasticsearch-node-to-node-encryption-check = {
      description          = "Check if OpenSearch Service (previously called Elasticsearch) nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is not enabled on the domain."
      resource_types_scope = ["AWS::Elasticsearch::Domain"]
      severity             = "Medium"
    }

    elastic-beanstalk-logs-to-cloudwatch = {
      description          = "Checks if AWS Elastic Beanstalk environments are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if the value of StreamLogs is false."
      input_parameters     = var.elastic_beanstalk_logs_to_cloudwatch_parameters
      resource_types_scope = ["AWS::ElasticBeanstalk::Environment"]
      severity             = "Medium"
    }

    elastic-beanstalk-managed-updates-enabled = {
      description          = "Checks if managed platform updates in an AWS Elastic Beanstalk environment is enabled. The rule is COMPLIANT if the value for ManagedActionsEnabled is set to true. The rule is NON_COMPLIANT if the value for ManagedActionsEnabled is set to false, or if a..."
      input_parameters     = var.elastic_beanstalk_managed_updates_enabled_parameters
      resource_types_scope = ["AWS::ElasticBeanstalk::Environment"]
      severity             = "Medium"
    }

    elbv2-acm-certificate-required = {
      description      = "Checks if Application Load Balancers and Network Load Balancers have listeners that are configured to use certificates from AWS Certificate Manager (ACM). This rule is NON_COMPLIANT if at least 1 load balancer has at least 1 listener that is configured..."
      input_parameters = var.elbv2_acm_certificate_required_parameters
      severity         = "Medium"
    }

    elbv2-multiple-az = {
      description          = "Checks if an Elastic Load Balancer V2 (Application, Network, or Gateway Load Balancer) has registered instances from multiple Availability Zones (AZ s). The rule is NON_COMPLIANT if an Elastic Load Balancer V2 has instances registered in less than 2 AZ's."
      input_parameters     = var.elbv2_multiple_az_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    elb-acm-certificate-required = {
      description          = "Checks if the Classic Load Balancers use SSL certificates provided by AWS Certificate Manager. To use this rule, use an SSL or HTTPS listener with your Classic Load Balancer. This rule is only applicable to Classic Load Balancers. This rule does not..."
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Low"
    }

    elb-cross-zone-load-balancing-enabled = {
      description          = "Checks if cross-zone load balancing is enabled for Classic Load Balancers. The rule is NON_COMPLIANT if cross-zone load balancing is not enabled for Classic Load Balancers."
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    elb-custom-security-policy-ssl-check = {
      description          = "Checks whether your Classic Load Balancer SSL listeners are using a custom policy. The rule is only applicable if there are SSL listeners for the Classic Load Balancer."
      input_parameters     = var.elb_custom_security_policy_ssl_check_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    elb-deletion-protection-enabled = {
      description          = "Checks if an Elastic Load Balancer has deletion protection enabled. The rule is NON_COMPLIANT if deletion_protection.enabled is false."
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    elb-logging-enabled = {
      description          = "Checks if the Application Load Balancer and the Classic Load Balancer have logging enabled. The rule is NON_COMPLIANT if the access_logs.s3.enabled is false or access_logs.S3.bucket is not equal to the s3BucketName that you provided."
      input_parameters     = var.elb_logging_enabled_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    elb-predefined-security-policy-ssl-check = {
      description          = "Checks if your Classic Load Balancer SSL listeners use a predefined policy. The rule is NON_COMPLIANT if the Classic Load Balancer HTTPS/SSL listener's policy does not equal the value of the parameter predefinedPolicyName ."
      input_parameters     = var.elb_predefined_security_policy_ssl_check_parameters
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    elb-tls-https-listeners-only = {
      description          = "Checks if your Classic Load Balancer is configured with SSL or HTTPS listeners. The rule is NON_COMPLIANT if a listener is not configured with SSL or HTTPS."
      resource_types_scope = ["AWS::ElasticLoadBalancing::LoadBalancer"]
      severity             = "Medium"
    }

    emr-kerberos-enabled = {
      description      = "Checks if Amazon EMR clusters have Kerberos enabled. The rule is NON_COMPLIANT if a security configuration is not attached to the cluster or the security configuration does not satisfy the specified rule parameters."
      input_parameters = var.emr_kerberos_enabled_parameters
      severity         = "Medium"
    }

    emr-master-no-public-ip = {
      description          = "Checks if Amazon EMR clusters master nodes have public IPs. The rule is NON_COMPLIANT if the master node has a public IP."
      resource_types_scope = ["AWS::EMR::Cluster"]
      severity             = "High"
    }

    encrypted-volumes = {
      description          = "Checks if attached Amazon EBS volumes are encrypted and optionally are encrypted with a specified KMS key. The rule is NON_COMPLIANT if attached EBS volumes are unencrypted or are encrypted with a KMS key not in the supplied parameters."
      input_parameters     = var.encrypted_volumes_parameters
      resource_types_scope = ["AWS::EC2::Volume"]
      severity             = "Medium"
    }

    fms-shield-resource-policy-check = {
      description          = "Checks whether an Application Load Balancer, Amazon CloudFront distributions, Elastic Load Balancer or Elastic IP has AWS Shield protection. It also checks if they have web ACL associated for Application Load Balancer and Amazon CloudFront distributions."
      input_parameters     = var.fms_shield_resource_policy_check_parameters
      resource_types_scope = ["AWS::CloudFront::Distribution", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::WAFRegional::WebACL", "AWS::EC2::EIP", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ShieldRegional::Protection", "AWS::Shield::Protection"]
      severity             = "Medium"
    }

    fms-webacl-resource-policy-check = {
      description          = "Checks if the web ACL is associated with an Application Load Balancer, API Gateway stage, or Amazon CloudFront distributions. When AWS Firewall Manager creates this rule, the FMS policy owner specifies the WebACLId in the FMS policy and can optionally..."
      input_parameters     = var.fms_webacl_resource_policy_check_parameters
      resource_types_scope = ["AWS::CloudFront::Distribution", "AWS::ApiGateway::Stage", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::WAFRegional::WebACL"]
      severity             = "Medium"
    }

    fms-webacl-rulegroup-association-check = {
      description          = "Checks if the rule groups associate with the web ACL at the correct priority. The correct priority is decided by the rank of the rule groups in the ruleGroups parameter. When AWS Firewall Manager creates this rule, it assigns the highest priority 0..."
      input_parameters     = var.fms_webacl_rulegroup_association_check_parameters
      resource_types_scope = ["AWS::WAF::WebACL", "AWS::WAFRegional::WebACL"]
      severity             = "Medium"
    }

    fsx-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon FSx File Systems. The rule is NON_COMPLIANT if the Amazon FSx File System does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.fsx_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::FSx::FileSystem"]
      severity             = "Medium"
    }

    fsx-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon FSx File Systems are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon FSx File System is not covered by a backup plan."
      input_parameters     = var.fsx_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::FSx::FileSystem"]
      severity             = "Medium"
    }

    guardduty-enabled-centralized = {
      description      = "Checks if Amazon GuardDuty is enabled in your AWS account and AWS Region. If you provide an AWS account for centralization, the rule evaluates the GuardDuty results in the centralized account. The rule is COMPLIANT when GuardDuty is enabled."
      input_parameters = var.guardduty_enabled_centralized_parameters
      severity         = "High"
    }

    guardduty-non-archived-findings = {
      description      = "Checks if Amazon GuardDuty has findings that are non-archived. The rule is NON_COMPLIANT if GuardDuty has non-archived low/medium/high severity findings older than the specified number in the daysLowSev/daysMediumSev/ daysHighSev parameter."
      input_parameters = var.guardduty_non_archived_findings_parameters
      severity         = "Medium"
    }

    iam-customer-policy-blocked-kms-actions = {
      description          = "Checks if the managed AWS Identity and Access Management (IAM) policies that you create do not allow blocked actions on AWS KMS) keys. The rule is NON_COMPLIANT if any blocked action is allowed on AWS KMS keys by the managed IAM policy."
      input_parameters     = var.iam_customer_policy_blocked_kms_actions_parameters
      resource_types_scope = ["AWS::IAM::Policy"]
      severity             = "Medium"
    }

    iam-group-has-users-check = {
      description          = "Checks whether IAM groups have at least one IAM user."
      resource_types_scope = ["AWS::IAM::Group"]
      severity             = "Medium"
    }

    iam-inline-policy-blocked-kms-actions = {
      description          = "Checks if the inline policies attached to your IAM users, roles, and groups do not allow blocked actions on all AWS KMS keys. The rule is NON_COMPLIANT if any blocked action is allowed on all AWS KMS keys in an inline policy."
      input_parameters     = var.iam_inline_policy_blocked_kms_actions_parameters
      resource_types_scope = ["AWS::IAM::Group", "AWS::IAM::Role", "AWS::IAM::User"]
      severity             = "Medium"
    }

    iam-no-inline-policy-check = {
      description          = "Checks if the inline policy feature is not in use. The rule is NON_COMPLIANT if an AWS Identity and Access Management (IAM) user, IAM role or IAM group has any inline policy."
      resource_types_scope = ["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"]
      severity             = "Medium"
    }

    iam-password-policy = {
      description      = "Checks if the account password policy for AWS Identity and Access Management (IAM) users meets the specified requirements indicated in the parameters. The rule is NON_COMPLIANT if the account password policy does not meet the specified requirements."
      input_parameters = var.iam_password_policy_parameters
      severity         = "Medium"
    }

    iam-policy-blacklisted-check = {
      description          = "Checks in each AWS Identity and Access Management (IAM) resource, if a policy Amazon Resource Name (ARN) in the input parameter is attached to the IAM resource. The rule is NON_COMPLIANT if the policy ARN is attached to the IAM resource."
      input_parameters     = var.iam_policy_blacklisted_check_parameters
      resource_types_scope = ["AWS::IAM::User", "AWS::IAM::Group", "AWS::IAM::Role"]
      severity             = "Medium"
    }

    iam-policy-in-use = {
      description      = "Checks whether the IAM policy ARN is attached to an IAM user, or a group with one or more IAM users, or an IAM role with one or more trusted entity."
      input_parameters = var.iam_policy_in_use_parameters
      severity         = "Medium"
    }

    iam-policy-no-statements-with-admin-access = {
      description          = "Checks if AWS Identity and Access Management (IAM) policies that you create have Allow statements that grant permissions to all actions on all resources. The rule is NON_COMPLIANT if any customer managed IAM policy statement includes Effect : Allow with..."
      input_parameters     = var.iam_policy_no_statements_with_admin_access_parameters
      resource_types_scope = ["AWS::IAM::Policy"]
      severity             = "High"
    }

    iam-policy-no-statements-with-full-access = {
      description          = "Checks if AWS Identity and Access Management (IAM) policies that you create grant permissions to all actions on individual AWS resources. The rule is NON_COMPLIANT if any customer managed IAM policy allows full access to at least 1 AWS service."
      input_parameters     = var.iam_policy_no_statements_with_full_access_parameters
      resource_types_scope = ["AWS::IAM::Policy"]
      severity             = "Low"
    }

    iam-role-managed-policy-check = {
      description          = "Checks if all AWS managed policies specified in the list of managed policies are attached to the AWS Identity and Access Management (IAM) role. The rule is NON_COMPLIANT if an AWS managed policy is not attached to the IAM role."
      input_parameters     = var.iam_role_managed_policy_check_parameters
      resource_types_scope = ["AWS::IAM::Role"]
      severity             = "Medium"
    }

    iam-root-access-key-check = {
      description = "Checks if the root user access key is available. The rule is COMPLIANT if the user access key does not exist. Otherwise, NON_COMPLIANT."
      severity    = "Critical"
    }

    iam-user-group-membership-check = {
      description          = "Checks whether IAM users are members of at least one IAM group."
      input_parameters     = var.iam_user_group_membership_check_parameters
      resource_types_scope = ["AWS::IAM::User"]
      severity             = "Medium"
    }

    iam-user-mfa-enabled = {
      description = "Checks if the AWS Identity and Access Management (IAM) users have multi-factor authentication (MFA) enabled. The rule is NON_COMPLIANT if MFA is not enabled for at least one IAM user."
      severity    = "Medium"
    }

    iam-user-no-policies-check = {
      description          = "Checks if none of your AWS Identity and Access Management (IAM) users have policies attached. IAM users must inherit permissions from IAM groups or roles. The rule is NON_COMPLIANT if there is at least one IAM user with policies attached."
      resource_types_scope = ["AWS::IAM::User"]
      severity             = "Low"
    }

    iam-user-unused-credentials-check = {
      description      = "Checks if your AWS Identity and Access Management (IAM) users have passwords or active access keys that have not been used within the specified number of days you provided. The rule is NON_COMPLIANT if there are inactive accounts not recently used."
      input_parameters = var.iam_user_unused_credentials_check_parameters
      severity         = "Medium"
    }

    incoming-ssh-disabled = {
      description          = "Checks if the incoming SSH traffic for the security groups is accessible. The rule is COMPLIANT when IP addresses of the incoming SSH traffic in the security groups are restricted (CIDR other than 0.0.0.0/0). This rule applies only to IPv4."
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "High"
    }

    instances-in-vpc = {
      description          = "Checks if your EC2 instances belong to a virtual private cloud (VPC). Optionally, you can specify the VPC ID to associate with your instances."
      input_parameters     = var.instances_in_vpc_parameters
      resource_types_scope = ["AWS::EC2::Instance"]
      severity             = "Medium"
    }

    internet-gateway-authorized-vpc-only = {
      description          = "Checks if internet gateways are attached to an authorized virtual private cloud (Amazon VPC). The rule is NON_COMPLIANT if internet gateways are attached to an unauthorized VPC."
      input_parameters     = var.internet_gateway_authorized_vpc_only_parameters
      resource_types_scope = ["AWS::EC2::InternetGateway"]
      severity             = "High"
    }

    kinesis-stream-encrypted = {
      description          = "Checks if Amazon Kinesis streams are encrypted at rest with server-side encryption. The rule is NON_COMPLIANT for a Kinesis stream if StreamEncryption is not present."
      resource_types_scope = ["AWS::Kinesis::Stream"]
      severity             = "High"
    }

    kms-cmk-not-scheduled-for-deletion = {
      description          = "Checks if AWS KMS keys are not scheduled for deletion in AWS Key Management Service (AWS KMS). The rule is NON_COMPLAINT if KMS keys are scheduled for deletion."
      input_parameters     = var.kms_cmk_not_scheduled_for_deletion_parameters
      resource_types_scope = ["AWS::KMS::Key"]
      severity             = "Critical"
    }

    lambda-concurrency-check = {
      description          = "Checks if the Lambda function is configured with a function-level concurrent execution limit. The rule is NON_COMPLIANT if the Lambda function is not configured with a function-level concurrent execution limit."
      input_parameters     = var.lambda_concurrency_check_parameters
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Medium"
    }

    lambda-dlq-check = {
      description          = "Checks if a Lambda function is configured with a dead-letter queue. The rule is NON_COMPLIANT if the Lambda function is not configured with a dead-letter queue."
      input_parameters     = var.lambda_dlq_check_parameters
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Low"
    }

    lambda-function-public-access-prohibited = {
      description          = "Checks if the AWS Lambda function policy attached to the Lambda resource prohibits public access. If the Lambda function policy allows public access it is NON_COMPLIANT."
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Critical"
    }

    lambda-function-settings-check = {
      description          = "Checks if the AWS Lambda function settings for runtime, role, timeout, and memory size match the expected values. The rule ignores functions with the Image package type. The rule is NON_COMPLIANT if the Lambda function settings do not match the expected..."
      input_parameters     = var.lambda_function_settings_check_parameters
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Medium"
    }

    lambda-inside-vpc = {
      description          = "Checks if a Lambda function is allowed access to a virtual private cloud (VPC). The rule is NON_COMPLIANT if the Lambda function is not VPC enabled."
      input_parameters     = var.lambda_inside_vpc_parameters
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Low"
    }

    lambda-vpc-multi-az-check = {
      description          = "Checks if Lambda has more than 1 availability zone associated. The rule is NON_COMPLIANT if only 1 availability zone is associated with the Lambda or the number of availability zones associated is less than number specified in the optional parameter."
      input_parameters     = var.lambda_vpc_multi_az_check_parameters
      resource_types_scope = ["AWS::Lambda::Function"]
      severity             = "Medium"
    }

    macie-status-check = {
      description          = "Checks if Amazon Macie is enabled in your account per region. The rule is NON_COMPLIANT if the status attribute is not set to ENABLED ."
      resource_types_scope = ["AWS::::Account"]
      severity             = "Medium"
    }

    mfa-enabled-for-iam-console-access = {
      description = "Checks if AWS multi-factor authentication (MFA) is enabled for all AWS Identity and Access Management (IAM) users that use a console password. The rule is COMPLIANT if MFA is enabled."
      severity    = "Medium"
    }

    mq-automatic-minor-version-upgrade-enabled = {
      description          = "Checks if automatic minor version upgrades are enabled for Amazon MQ brokers. The rule is NON_COMPLIANT if the AutoMinorVersionUpgrade field is not enabled for an Amazon MQ broker."
      resource_types_scope = ["AWS::AmazonMQ::Broker"]
      severity             = "Medium"
    }

    mq-cloudwatch-audit-logging-enabled = {
      description          = "Checks if Amazon MQ brokers have Amazon CloudWatch audit logging enabled. The rule is NON_COMPLIANT if a broker does not have audit logging enabled."
      resource_types_scope = ["AWS::AmazonMQ::Broker"]
      severity             = "Medium"
    }

    mq-no-public-access = {
      description          = "Checks if Amazon MQ brokers are not publicly accessible. The rule is NON_COMPLIANT if the PubliclyAccessible field is set to true for an Amazon MQ broker."
      resource_types_scope = ["AWS::AmazonMQ::Broker"]
      severity             = "Medium"
    }

    multi-region-cloud-trail-enabled = {
      description      = "Checks if there is at least one multi-region AWS CloudTrail. The rule is NON_COMPLIANT if the trails do not match input parameters.The rule is NON_COMPLIANT if the ExcludeManagementEventSources field is not empty or if AWS CloudTrail is configured to..."
      input_parameters = var.multi_region_cloud_trail_enabled_parameters
      severity         = "Critical"
    }

    nacl-no-unrestricted-ssh-rdp = {
      description          = "Checks if default ports for SSH/RDP ingress traffic for network access control lists (NACLs) is unrestricted. The rule is NON_COMPLIANT if a NACL inbound entry allows a source TCP or UDP CIDR block for ports 22 or 3389."
      resource_types_scope = ["AWS::EC2::NetworkAcl"]
      severity             = "High"
    }

    netfw-logging-enabled = {
      description          = "Checks if AWS Network Firewall firewalls have logging enabled. The rule is NON_COMPLIANT if a logging type is not configured. You can specify which logging type you want the rule to check."
      input_parameters     = var.netfw_logging_enabled_parameters
      resource_types_scope = ["AWS::NetworkFirewall::LoggingConfiguration"]
      severity             = "Medium"
    }

    netfw-multi-az-enabled = {
      description          = "Checks if AWS Network Firewall firewalls are deployed across multiple Availability Zones. The rule is NON_COMPLIANT if firewalls are deployed in only one Availability Zone or in fewer zones than the number listed in the optional parameter."
      input_parameters     = var.netfw_multi_az_enabled_parameters
      resource_types_scope = ["AWS::NetworkFirewall::Firewall"]
      severity             = "Medium"
    }

    netfw-policy-default-action-fragment-packets = {
      description          = "Checks if an AWS Network Firewall policy is configured with a user defined stateless default action for fragmented packets. The rule is NON_COMPLIANT if stateless default action for fragmented packets does not match with user defined default action."
      input_parameters     = var.netfw_policy_default_action_fragment_packets_parameters
      resource_types_scope = ["AWS::NetworkFirewall::FirewallPolicy"]
      severity             = "High"
    }

    netfw-policy-default-action-full-packets = {
      description          = "Checks if an AWS Network Firewall policy is configured with a user defined default stateless action for full packets. This rule is NON_COMPLIANT if default stateless action for full packets does not match with user defined default stateless action."
      input_parameters     = var.netfw_policy_default_action_full_packets_parameters
      resource_types_scope = ["AWS::NetworkFirewall::FirewallPolicy"]
      severity             = "High"
    }

    netfw-policy-rule-group-associated = {
      description          = "Check AWS Network Firewall policy is associated with stateful OR stateless rule groups. This rule is NON_COMPLIANT if no stateful or stateless rule groups are associated with the Network Firewall policy else COMPLIANT if any one of the rule group exists."
      resource_types_scope = ["AWS::NetworkFirewall::FirewallPolicy"]
      severity             = "High"
    }

    netfw-stateless-rule-group-not-empty = {
      description          = "Checks if a Stateless Network Firewall Rule Group contains rules. The rule is NON_COMPLIANT if there are no rules in a Stateless Network Firewall Rule Group."
      resource_types_scope = ["AWS::NetworkFirewall::RuleGroup"]
      severity             = "Medium"
    }

    nlb-cross-zone-load-balancing-enabled = {
      description          = "Checks if cross-zone load balancing is enabled on Network Load Balancers (NLBs). The rule is NON_COMPLIANT if cross-zone load balancing is not enabled for an NLB."
      resource_types_scope = ["AWS::ElasticLoadBalancingV2::LoadBalancer"]
      severity             = "Medium"
    }

    no-unrestricted-route-to-igw = {
      description          = "Checks if there are public routes in the route table to an Internet gateway (IGW). The rule is NON_COMPLIANT if a route to an IGW has a destination CIDR block of 0.0.0.0/0 or ::/0 or if a destination CIDR block does not match the rule parameter."
      input_parameters     = var.no_unrestricted_route_to_igw_parameters
      resource_types_scope = ["AWS::EC2::RouteTable"]
      severity             = "Medium"
    }

    opensearch-access-control-enabled = {
      description          = "Checks if Amazon OpenSearch Service domains have fine-grained access control enabled. The rule is NON_COMPLIANT if AdvancedSecurityOptions is not enabled for the OpenSearch Service domain."
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "High"
    }

    opensearch-audit-logging-enabled = {
      description          = "Checks if Amazon OpenSearch Service domains have audit logging enabled. The rule is NON_COMPLIANT if an OpenSearch Service domain does not have audit logging enabled."
      input_parameters     = var.opensearch_audit_logging_enabled_parameters
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "Medium"
    }

    opensearch-data-node-fault-tolerance = {
      description          = "Checks if Amazon OpenSearch Service domains are configured with at least three data nodes and zoneAwarenessEnabled is true. The rule is NON_COMPLIANT for an OpenSearch domain if instanceCount is less than 3 or zoneAwarenessEnabled is set to false ."
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "Medium"
    }

    opensearch-encrypted-at-rest = {
      description          = "Checks if Amazon OpenSearch Service domains have encryption at rest configuration enabled. The rule is NON_COMPLIANT if the EncryptionAtRestOptions field is not enabled."
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "High"
    }

    opensearch-https-required = {
      description          = "Checks whether connections to OpenSearch domains are using HTTPS. The rule is NON_COMPLIANT if the Amazon OpenSearch domain EnforceHTTPS is not true or is true and TLSSecurityPolicy is not in tlsPolicies ."
      input_parameters     = var.opensearch_https_required_parameters
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "High"
    }

    opensearch-in-vpc-only = {
      description          = "Checks if Amazon OpenSearch Service domains are in an Amazon Virtual Private Cloud (VPC). The rule is NON_COMPLIANT if an OpenSearch Service domain endpoint is public."
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "High"
    }

    opensearch-logs-to-cloudwatch = {
      description          = "Checks if Amazon OpenSearch Service domains are configured to send logs to Amazon CloudWatch Logs. The rule is NON_COMPLIANT if logging is not configured."
      input_parameters     = var.opensearch_logs_to_cloudwatch_parameters
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "Medium"
    }

    opensearch-node-to-node-encryption-check = {
      description          = "Check if Amazon OpenSearch Service nodes are encrypted end to end. The rule is NON_COMPLIANT if the node-to-node encryption is not enabled on the domain"
      resource_types_scope = ["AWS::OpenSearch::Domain"]
      severity             = "High"
    }

    rds-automatic-minor-version-upgrade-enabled = {
      description          = "Checks if Amazon Relational Database Service (Amazon RDS) database instances are configured for automatic minor version upgrades. The rule is NON_COMPLIANT if the value of autoMinorVersionUpgrade is false."
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "High"
    }

    rds-cluster-default-admin-check = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) database cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username is set to the default value."
      input_parameters     = var.rds_cluster_default_admin_check_parameters
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    rds-cluster-deletion-protection-enabled = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) cluster has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon RDS cluster does not have deletion protection enabled."
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Low"
    }

    rds-cluster-iam-authentication-enabled = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) cluster has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS Cluster does not have IAM authentication enabled."
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    rds-cluster-multi-az-enabled = {
      description          = "Checks if Multi-Availability Zone (Multi-AZ) replication is enabled on Amazon Aurora and Hermes clusters managed by Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if an Amazon RDS instance is not configured with Multi-AZ."
      resource_types_scope = ["AWS::RDS::DBCluster"]
      severity             = "Medium"
    }

    rds-db-security-group-not-allowed = {
      description          = "Checks if there are any Amazon Relational Database Service (RDS) DB security groups that are not the default DB security group. The rule is NON_COMPLIANT is there are any DB security groups that are not the default DB security group."
      resource_types_scope = ["AWS::RDS::DBSecurityGroup"]
      severity             = "Medium"
    }

    rds-enhanced-monitoring-enabled = {
      description          = "Checks if enhanced monitoring is enabled for Amazon RDS instances. This rule is NON_COMPLIANT if monitoringInterval is 0 in the configuration item of the RDS instance, or if monitoringInterval does not match the rule parameter value."
      input_parameters     = var.rds_enhanced_monitoring_enabled_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Low"
    }

    rds-instance-default-admin-check = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) database has changed the admin username from its default value. This rule will only run on RDS database instances. The rule is NON_COMPLIANT if the admin username is set to the default value."
      input_parameters     = var.rds_instance_default_admin_check_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-instance-deletion-protection-enabled = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has deletion protection enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have deletion protection enabled; for example, deletionProtection is set to false."
      input_parameters     = var.rds_instance_deletion_protection_enabled_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-instance-iam-authentication-enabled = {
      description          = "Checks if an Amazon Relational Database Service (Amazon RDS) instance has AWS Identity and Access Management (IAM) authentication enabled. The rule is NON_COMPLIANT if an Amazon RDS instance does not have IAM authentication enabled."
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-instance-public-access-check = {
      description          = "Checks if the Amazon Relational Database Service (Amazon RDS) instances are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is true in the instance configuration item."
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Critical"
    }

    rds-in-backup-plan = {
      description = "Checks if Amazon Relational Database Service (Amazon RDS) databases are present in AWS Backup plans. The rule is NON_COMPLIANT if Amazon RDS databases are not included in any AWS Backup plan."
      severity    = "Medium"
    }

    rds-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Relational Database Service (Amazon RDS). The rule is NON_COMPLIANT if the Amazon RDS instance does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.rds_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "High"
    }

    rds-logging-enabled = {
      description          = "Checks if respective logs of Amazon Relational Database Service (Amazon RDS) are enabled. The rule is NON_COMPLIANT if any log types are not enabled."
      input_parameters     = var.rds_logging_enabled_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-multi-az-support = {
      description          = "Checks whether high availability is enabled for your RDS DB instances."
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Relational Database Service (Amazon RDS) instances are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon RDS Database instance is not covered by a backup plan."
      input_parameters     = var.rds_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    rds-snapshots-public-prohibited = {
      description          = "Checks if Amazon Relational Database Service (Amazon RDS) snapshots are public. The rule is NON_COMPLIANT if any existing and new Amazon RDS snapshots are public."
      resource_types_scope = ["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
      severity             = "Critical"
    }

    rds-snapshot-encrypted = {
      description          = "Checks if Amazon Relational Database Service (Amazon RDS) DB snapshots are encrypted. The rule is NON_COMPLIANT if the Amazon RDS DB snapshots are not encrypted."
      resource_types_scope = ["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
      severity             = "Medium"
    }

    rds-storage-encrypted = {
      description          = "Checks if storage encryption is enabled for your Amazon Relational Database Service (Amazon RDS) DB instances. The rule is NON_COMPLIANT if storage encryption is not enabled."
      input_parameters     = var.rds_storage_encrypted_parameters
      resource_types_scope = ["AWS::RDS::DBInstance"]
      severity             = "Medium"
    }

    redshift-audit-logging-enabled = {
      description          = "Checks if Amazon Redshift clusters are logging audits to a specific bucket. The rule is NON_COMPLIANT if audit logging is not enabled for a Redshift cluster or if the bucketNames parameter is provided but the audit logging destination does not match."
      input_parameters     = var.redshift_audit_logging_enabled_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-backup-enabled = {
      description          = "Checks that Amazon Redshift automated snapshots are enabled for clusters. The rule is NON_COMPLIANT if the value for automatedSnapshotRetentionPeriod is greater than MaxRetentionPeriod or less than MinRetentionPeriod or the value is 0."
      input_parameters     = var.redshift_backup_enabled_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-cluster-configuration-check = {
      description          = "Checks if Amazon Redshift clusters have the specified settings. The rule is NON_COMPLIANT if the Amazon Redshift cluster is not encrypted or encrypted with another key, or if a cluster does not have audit logging enabled."
      input_parameters     = var.redshift_cluster_configuration_check_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-cluster-kms-enabled = {
      description          = "Checks if Amazon Redshift clusters are using a specified AWS Key Management Service (AWS KMS) key for encryption. The rule is COMPLIANT if encryption is enabled and the cluster is encrypted with the key provided in the kmsKeyArn parameter. The rule is..."
      input_parameters     = var.redshift_cluster_kms_enabled_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-cluster-maintenancesettings-check = {
      description          = "Checks if Amazon Redshift clusters have the specified maintenance settings. The rule is NON_COMPLIANT if the automatic upgrades to major version is disabled."
      input_parameters     = var.redshift_cluster_maintenancesettings_check_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-cluster-public-access-check = {
      description          = "Checks if Amazon Redshift clusters are not publicly accessible. The rule is NON_COMPLIANT if the publiclyAccessible field is True in the cluster configuration item."
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Critical"
    }

    redshift-default-admin-check = {
      description          = "Checks if an Amazon Redshift cluster has changed the admin username from its default value. The rule is NON_COMPLIANT if the admin username for a Redshift cluster is set to “awsuser” or if the username does not match what is listed in parameter."
      input_parameters     = var.redshift_default_admin_check_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-default-db-name-check = {
      description          = "Checks if a Redshift cluster has changed its database name from the default value. The rule is NON_COMPLIANT if the database name for a Redshift cluster is set to “dev”, or if the optional parameter is provided and the database name does not match."
      input_parameters     = var.redshift_default_db_name_check_parameters
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    redshift-enhanced-vpc-routing-enabled = {
      description          = "Checks if Amazon Redshift cluster has enhancedVpcRouting enabled. The rule is NON_COMPLIANT if enhancedVpcRouting is not enabled or if the configuration.enhancedVpcRouting field is false ."
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "High"
    }

    redshift-require-tls-ssl = {
      description          = "Checks if Amazon Redshift clusters require TLS/SSL encryption to connect to SQL clients. The rule is NON_COMPLIANT if any Amazon Redshift cluster has parameter require_SSL not set to true."
      resource_types_scope = ["AWS::Redshift::Cluster"]
      severity             = "Medium"
    }

    required-tags = {
      description          = "Checks if your resources have the tags that you specify. For example, you can check whether your Amazon EC2 instances have the CostCenter tag. Separate multiple values with commas.You can check up to 6 tags at a time."
      input_parameters     = var.required_tags_parameters
      resource_types_scope = ["AWS::ACM::Certificate", "AWS::AutoScaling::AutoScalingGroup", "AWS::CloudFormation::Stack", "AWS::CodeBuild::Project", "AWS::DynamoDB::Table", "AWS::EC2::CustomerGateway", "AWS::EC2::Instance", "AWS::EC2::InternetGateway", "AWS::EC2::NetworkAcl", "AWS::EC2::NetworkInterface", "AWS::EC2::RouteTable", "AWS::EC2::SecurityGroup", "AWS::EC2::Subnet", "AWS::EC2::Volume", "AWS::EC2::VPC", "AWS::EC2::VPNConnection", "AWS::EC2::VPNGateway", "AWS::ElasticLoadBalancing::LoadBalancer", "AWS::ElasticLoadBalancingV2::LoadBalancer", "AWS::RDS::DBInstance", "AWS::RDS::DBSecurityGroup", "AWS::RDS::DBSnapshot", "AWS::RDS::DBSubnetGroup", "AWS::RDS::EventSubscription", "AWS::Redshift::Cluster", "AWS::Redshift::ClusterParameterGroup", "AWS::Redshift::ClusterSecurityGroup", "AWS::Redshift::ClusterSnapshot", "AWS::Redshift::ClusterSubnetGroup", "AWS::S3::Bucket"]
      severity             = "Medium"
    }

    restricted-incoming-traffic = {
      description          = "Checks if the security groups in use do not allow unrestricted incoming Transmission Control Protocol (TCP) traffic to the specified ports for IPv4. The rule is COMPLIANT if IP addresses for inbound TCP connections are restricted to the specified ports."
      input_parameters     = var.restricted_incoming_traffic_parameters
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "High"
    }

    root-account-hardware-mfa-enabled = {
      description = "Checks if your AWS account is enabled to use multi-factor authentication (MFA) hardware device to sign in with root credentials. The rule is NON_COMPLIANT if any virtual MFA devices are permitted for signing in with root credentials."
      severity    = "Critical"
    }

    root-account-mfa-enabled = {
      description = "Checks if the root user of your AWS account requires multi-factor authentication for console sign-in. The rule is NON_COMPLIANT if the AWS Identity and Access Management (IAM) root account user does not have multi-factor authentication (MFA) enabled."
      severity    = "Critical"
    }

    s3-account-level-public-access-blocks = {
      description          = "Checks if the required public access block settings are configured from account level. The rule is only NON_COMPLIANT when the fields set below do not match the corresponding fields in the configuration item."
      input_parameters     = var.s3_account_level_public_access_blocks_parameters
      resource_types_scope = ["AWS::S3::AccountPublicAccessBlock"]
      severity             = "Medium"
    }

    s3-account-level-public-access-blocks-periodic = {
      description      = "Checks if the required public access block settings are configured at the account level. The rule is NON_COMPLAINT if the configuration item does not match one or more settings from parameters (or default)."
      input_parameters = var.s3_account_level_public_access_blocks_periodic_parameters
      severity         = "Medium"
    }

    s3-bucket-acl-prohibited = {
      description          = "Checks if Amazon Simple Storage Service (Amazon S3) Buckets allow user permissions through access control lists (ACLs). The rule is NON_COMPLIANT if ACLs are configured for user access in Amazon S3 Buckets."
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-blacklisted-actions-prohibited = {
      description          = "Checks if an Amazon Simple Storage Service (Amazon S3) bucket policy does not allow blocklisted bucket-level and object-level actions on resources in the bucket for principals from other AWS accounts.For example, the rule checks that the Amazon S3..."
      input_parameters     = var.s3_bucket_blacklisted_actions_prohibited_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "High"
    }

    s3-bucket-default-lock-enabled = {
      description          = "Checks if the S3 bucket has lock enabled, by default. The rule is NON_COMPLIANT if the lock is not enabled."
      input_parameters     = var.s3_bucket_default_lock_enabled_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-level-public-access-prohibited = {
      description          = "Checks if S3 buckets are publicly accessible. The rule is NON_COMPLIANT if an S3 bucket is not listed in the excludedPublicBuckets parameter and bucket level settings are public."
      input_parameters     = var.s3_bucket_level_public_access_prohibited_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Critical"
    }

    s3-bucket-logging-enabled = {
      description          = "Checks if logging is enabled for your S3 buckets. The rule is NON_COMPLIANT if logging is not enabled."
      input_parameters     = var.s3_bucket_logging_enabled_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-policy-grantee-check = {
      description          = "Checks that the access granted by the Amazon S3 bucket is restricted by any of the AWS principals, federated users, service principals, IP addresses, or VPCs that you provide. The rule is COMPLIANT if a bucket policy is not present."
      input_parameters     = var.s3_bucket_policy_grantee_check_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-policy-not-more-permissive = {
      description          = "Checks if your Amazon Simple Storage Service bucket policies do not allow other inter-account permissions than the control Amazon S3 bucket policy that you provide."
      input_parameters     = var.s3_bucket_policy_not_more_permissive_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-public-read-prohibited = {
      description          = "Checks if your Amazon S3 buckets do not allow public read access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Critical"
    }

    s3-bucket-public-write-prohibited = {
      description          = "Checks if your Amazon S3 buckets do not allow public write access. The rule checks the Block Public Access settings, the bucket policy, and the bucket access control list (ACL)."
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Critical"
    }

    s3-bucket-replication-enabled = {
      description          = "Checks if S3 buckets have replication rules enabled. The rule is NON_COMPLIANT if an S3 bucket does not have a replication rule or has a replication rule that is not enabled."
      input_parameters     = var.s3_bucket_replication_enabled_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Low"
    }

    s3-bucket-server-side-encryption-enabled = {
      description          = "Checks if your Amazon S3 bucket either has the Amazon S3 default encryption enabledor that the Amazon S3 bucket policy explicitly denies put-object requests without server side encryption that uses AES-256 or AWS Key Management Service.The rule is..."
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-ssl-requests-only = {
      description          = "Checks if S3 buckets have policies that require requests to use SSL/TLS. The rule is NON_COMPLIANT if any S3 bucket has policies allowing HTTP requests."
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-bucket-versioning-enabled = {
      description          = "Checks if versioning is enabled for your S3 buckets. Optionally, the rule checks if MFA delete is enabled for your S3 buckets."
      input_parameters     = var.s3_bucket_versioning_enabled_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-default-encryption-kms = {
      description          = "Checks if the S3 buckets are encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the S3 bucket is not encrypted with an AWS KMS key."
      input_parameters     = var.s3_default_encryption_kms_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-event-notifications-enabled = {
      description          = "Checks if Amazon S3 Events Notifications are enabled on an S3 bucket. The rule is NON_COMPLIANT if S3 Events Notifications are not set on a bucket, or if the event type or destination do not match the eventTypes and destinationArn parameters."
      input_parameters     = var.s3_event_notifications_enabled_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Low"
    }

    s3-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for Amazon Simple Storage Service (Amazon S3). The rule is NON_COMPLIANT if the Amazon S3 bucket does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.s3_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-lifecycle-policy-check = {
      description          = "Checks if a lifecycle rule is configured for an Amazon Simple Storage Service (Amazon S3) bucket. The rule is NON_COMPLIANT if there is no active lifecycle configuration rules or the configuration does not match with the parameter values."
      input_parameters     = var.s3_lifecycle_policy_check_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    s3-resources-protected-by-backup-plan = {
      description          = "Checks if Amazon Simple Storage Service (Amazon S3) buckets are protected by a backup plan. The rule is NON_COMPLIANT if the Amazon S3 bucket is not covered by a backup plan."
      input_parameters     = var.s3_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "High"
    }

    s3-version-lifecycle-policy-check = {
      description          = "Checks if Amazon Simple Storage Service (Amazon S3) version enabled buckets have lifecycle policy configured. The rule is NON_COMPLIANT if Amazon S3 lifecycle policy is not enabled."
      input_parameters     = var.s3_version_lifecycle_policy_check_parameters
      resource_types_scope = ["AWS::S3::Bucket"]
      severity             = "Medium"
    }

    sagemaker-endpoint-configuration-kms-key-configured = {
      description      = "Checks if AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker endpoint configuration. The rule is NON_COMPLIANT if KmsKeyId is not specified for the Amazon SageMaker endpoint configuration."
      input_parameters = var.sagemaker_endpoint_configuration_kms_key_configured_parameters
      severity         = "Medium"
    }

    sagemaker-notebook-instance-inside-vpc = {
      description          = "Checks if an Amazon SageMaker notebook instance is launched within a VPC or within a list of approved subnets. The rule is NON_COMPLIANT if a notebook instance is not launched within a VPC or if its subnet ID is not included in the parameter list."
      input_parameters     = var.sagemaker_notebook_instance_inside_vpc_parameters
      resource_types_scope = ["AWS::SageMaker::NotebookInstance"]
      severity             = "Medium"
    }

    sagemaker-notebook-instance-kms-key-configured = {
      description      = "Checks if an AWS Key Management Service (AWS KMS) key is configured for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if KmsKeyId is not specified for the SageMaker notebook instance."
      input_parameters = var.sagemaker_notebook_instance_kms_key_configured_parameters
      severity         = "Medium"
    }

    sagemaker-notebook-instance-root-access-check = {
      description          = "Checks if the Amazon SageMaker RootAccess setting is enabled for Amazon SageMaker notebook instances. The rule is NON_COMPLIANT if the RootAccess setting is set to Enabled for an Amazon SageMaker notebook instance."
      resource_types_scope = ["AWS::SageMaker::NotebookInstance"]
      severity             = "Medium"
    }

    sagemaker-notebook-no-direct-internet-access = {
      description = "Checks if direct internet access is disabled for an Amazon SageMaker notebook instance. The rule is NON_COMPLIANT if a SageMaker notebook instance is internet-enabled."
      severity    = "High"
    }

    secretsmanager-rotation-enabled-check = {
      description          = "Checks if AWS Secrets Manager secret has rotation enabled. The rule also checks an optional maximumAllowedRotationFrequency parameter. If the parameter is specified, the rotation frequency of the secret is compared with the maximum allowed frequency...."
      input_parameters     = var.secretsmanager_rotation_enabled_check_parameters
      resource_types_scope = ["AWS::SecretsManager::Secret"]
      severity             = "Medium"
    }

    secretsmanager-scheduled-rotation-success-check = {
      description          = "Checks if AWS Secrets Manager secrets rotated successfully according to the rotation schedule. Secrets Manager calculates the date the rotation should happen. The rule is NON_COMPLIANT if the date passes and the secret isn t rotated."
      resource_types_scope = ["AWS::SecretsManager::Secret"]
      severity             = "Medium"
    }

    secretsmanager-secret-periodic-rotation = {
      description      = "Checks if AWS Secrets Manager secrets have been rotated in the past specified number of days. The rule is NON_COMPLIANT if a secret has not been rotated for more than maxDaysSinceRotation number of days. The default value is 90 days."
      input_parameters = var.secretsmanager_secret_periodic_rotation_parameters
      severity         = "Medium"
    }

    secretsmanager-secret-unused = {
      description      = "Checks if AWS Secrets Manager secrets have been accessed within a specified number of days. The rule is NON_COMPLIANT if a secret has not been accessed in unusedForDays number of days. The default value is 90 days."
      input_parameters = var.secretsmanager_secret_unused_parameters
      severity         = "Medium"
    }

    secretsmanager-using-cmk = {
      description          = "Checks if all secrets in AWS Secrets Manager are encrypted using the AWS managed key ( aws/secretsmanager ) or a customer managed key that was created in AWS Key Management Service (AWS KMS). The rule is COMPLIANT if a secret is encrypted using a..."
      input_parameters     = var.secretsmanager_using_cmk_parameters
      resource_types_scope = ["AWS::SecretsManager::Secret"]
      severity             = "Medium"
    }

    securityhub-enabled = {
      description = "Checks if AWS Security Hub is enabled for an AWS Account. The rule is NON_COMPLIANT if AWS Security Hub is not enabled."
      severity    = "Medium"
    }

    security-account-information-provided = {
      description          = "Checks if you have provided security contact information for your AWS account contacts. The rule is NON_COMPLIANT if security contact information within the account is not provided."
      resource_types_scope = ["AWS::::Account"]
      severity             = "Medium"
    }

    service-vpc-endpoint-enabled = {
      description      = "Checks if Service Endpoint for the service provided in rule parameter is created for each Amazon Virtual Private Cloud (Amazon VPC). The rule is NON_COMPLIANT if an Amazon VPC doesn t have an Amazon VPC endpoint created for the service."
      input_parameters = var.service_vpc_endpoint_enabled_parameters
      severity         = "Medium"
    }

    ses-malware-scanning-enabled = {
      description          = "Checks if malware and spam scanning on receiving messages is enabled for Amazon Simple Email Service (Amazon SES). The rule is NON_COMPLIANT if malware and spam scanning is not enabled."
      resource_types_scope = ["AWS::SES::ReceiptRule"]
      severity             = "Medium"
    }

    shield-advanced-enabled-autorenew = {
      description = "Checks if AWS Shield Advanced is enabled in your AWS account and this subscription is set to automatically renew. The rule is COMPLIANT if Shield Advanced is enabled and auto renew is enabled."
      severity    = "Medium"
    }

    shield-drt-access = {
      description = "Checks if the Shield Response Team (SRT) can access your AWS account. The rule is NON_COMPLIANT if AWS Shield Advanced is enabled but the role for SRT access is not configured."
      severity    = "Medium"
    }

    sns-encrypted-kms = {
      description          = "Checks if an SNS topic is encrypted with AWS Key Management Service (AWS KMS). The rule is NON_COMPLIANT if the SNS topic is not encrypted with AWS KMS or if a KMS key ID used to encrypt the SNS topic is not present in the kmsKeyIds input parameter."
      input_parameters     = var.sns_encrypted_kms_parameters
      resource_types_scope = ["AWS::SNS::Topic"]
      severity             = "Medium"
    }

    sns-topic-message-delivery-notification-enabled = {
      description          = "Checks if Amazon Simple Notification Service (SNS) logging is enabled for the delivery status of notification messages sent to a topic for the endpoints. The rule is NON_COMPLIANT if the delivery status notification for messages is not enabled."
      resource_types_scope = ["AWS::SNS::Topic"]
      severity             = "Low"
    }

    ssm-document-not-public = {
      description = "Checks if AWS Systems Manager documents owned by the account are public. The rule is NON_COMPLIANT if Systems Manager documents with the owner Self are public."
      severity    = "Critical"
    }

    step-functions-state-machine-logging-enabled = {
      description          = "Checks if AWS Step Functions machine has logging enabled. The rule is NON_COMPLIANT if a state machine does not have logging enabled or the logging configuration is not at the minimum level provided."
      input_parameters     = var.step_functions_state_machine_logging_enabled_parameters
      resource_types_scope = ["AWS::StepFunctions::StateMachine"]
      severity             = "Medium"
    }

    storagegateway-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for AWS Storage Gateway volumes. The rule is NON_COMPLIANT if the Storage Gateway volume does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.storagegateway_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::StorageGateway::Volume"]
      severity             = "High"
    }

    storagegateway-resources-protected-by-backup-plan = {
      description          = "Checks if AWS Storage Gateway volumes are protected by a backup plan. The rule is NON_COMPLIANT if the Storage Gateway volume is not covered by a backup plan."
      input_parameters     = var.storagegateway_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::StorageGateway::Volume"]
      severity             = "Medium"
    }

    subnet-auto-assign-public-ip-disabled = {
      description          = "Checks if Amazon Virtual Private Cloud (Amazon VPC) subnets are assigned a public IP address. The rule is COMPLIANT if Amazon VPC does not have subnets that are assigned a public IP address. The rule is NON_COMPLIANT if Amazon VPC has subnets that are..."
      resource_types_scope = ["AWS::EC2::Subnet"]
      severity             = "Medium"
    }

    virtualmachine-last-backup-recovery-point-created = {
      description          = "Checks if a recovery point was created for AWS Backup-Gateway VirtualMachines. The rule is NON_COMPLIANT if an AWS Backup-Gateway VirtualMachines does not have a corresponding recovery point created within the specified time period."
      input_parameters     = var.virtualmachine_last_backup_recovery_point_created_parameters
      resource_types_scope = ["AWS::BackupGateway::VirtualMachine"]
      severity             = "High"
    }

    virtualmachine-resources-protected-by-backup-plan = {
      description          = "Checks if AWS Backup-Gateway VirtualMachines are protected by a backup plan. The rule is NON_COMPLIANT if the Backup-Gateway VirtualMachine is not covered by a backup plan."
      input_parameters     = var.virtualmachine_resources_protected_by_backup_plan_parameters
      resource_types_scope = ["AWS::BackupGateway::VirtualMachine"]
      severity             = "High"
    }

    vpc-default-security-group-closed = {
      description          = "Checks if the default security group of any Amazon Virtual Private Cloud (Amazon VPC) does not allow inbound or outbound traffic. The rule is NON_COMPLIANT if the default security group has one or more inbound or outbound traffic rules."
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "High"
    }

    vpc-flow-logs-enabled = {
      description      = "Checks if Amazon Virtual Private Cloud (Amazon VPC) flow logs are found and enabled for all Amazon VPCs. The rule is NON_COMPLIANT if flow logs are not enabled for at least one Amazon VPC."
      input_parameters = var.vpc_flow_logs_enabled_parameters
      severity         = "Medium"
    }

    vpc-network-acl-unused-check = {
      description          = "Checks if there are unused network access control lists (network ACLs). The rule is COMPLIANT if each network ACL is associated with a subnet. The rule is NON_COMPLIANT if a network ACL is not associated with a subnet."
      resource_types_scope = ["AWS::EC2::NetworkAcl"]
      severity             = "Low"
    }

    vpc-peering-dns-resolution-check = {
      description          = "Checks if DNS resolution from accepter/requester VPC to private IP is enabled. The rule is NON_COMPLIANT if DNS resolution from accepter/requester VPC to private IP is not enabled."
      input_parameters     = var.vpc_peering_dns_resolution_check_parameters
      resource_types_scope = ["AWS::EC2::VPCPeeringConnection"]
      severity             = "High"
    }

    vpc-sg-open-only-to-authorized-ports = {
      description          = "Checks if security groups allowing unrestricted incoming traffic ( 0.0.0.0/0 or ::/0 ) only allow inbound TCP or UDP connections on authorized ports. The rule is NON_COMPLIANT if such security groups do not have ports specified in the rule parameters."
      input_parameters     = var.vpc_sg_open_only_to_authorized_ports_parameters
      resource_types_scope = ["AWS::EC2::SecurityGroup"]
      severity             = "High"
    }

    vpc-vpn-2-tunnels-up = {
      description          = "Checks if both virtual private network (VPN) tunnels provided by AWS Site-to-Site VPN are in UP status. The rule is NON_COMPLIANT if one or both tunnels are in DOWN status."
      resource_types_scope = ["AWS::EC2::VPNConnection"]
      severity             = "Medium"
    }

    wafv2-logging-enabled = {
      description      = "Checks if logging is enabled on AWS WAFv2 regional and global web access control lists (web ACLs). The rule is NON_COMPLIANT if the logging is enabled but the logging destination does not match the value of the parameter."
      input_parameters = var.wafv2_logging_enabled_parameters
      severity         = "Medium"
    }

    wafv2-rulegroup-not-empty = {
      description          = "Checks if WAFv2 Rule Groups contain rules. The rule is NON_COMPLIANT if there are no rules in a WAFv2 Rule Group."
      resource_types_scope = ["AWS::WAFv2::RuleGroup"]
      severity             = "Medium"
    }

    wafv2-webacl-not-empty = {
      description          = "Checks if a WAFv2 Web ACL contains any WAF rules or WAF rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rules or WAF rule groups."
      resource_types_scope = ["AWS::WAFv2::WebACL"]
      severity             = "Medium"
    }

    waf-classic-logging-enabled = {
      description      = "Checks if logging is enabled on AWS WAF classic global web access control lists (web ACLs). The rule is NON_COMPLIANT for a global web ACL, if it does not have logging enabled."
      input_parameters = var.waf_classic_logging_enabled_parameters
      severity         = "Medium"
    }

    waf-global-rulegroup-not-empty = {
      description          = "Checks if an AWS WAF Classic rule group contains any rules. The rule is NON_COMPLIANT if there are no rules present within a rule group."
      resource_types_scope = ["AWS::WAF::RuleGroup"]
      severity             = "Medium"
    }

    waf-global-rule-not-empty = {
      description          = "Checks if an AWS WAF global rule contains any conditions. The rule is NON_COMPLIANT if no conditions are present within the WAF global rule."
      resource_types_scope = ["AWS::WAF::Rule"]
      severity             = "Medium"
    }

    waf-global-webacl-not-empty = {
      description          = "Checks whether a WAF Global Web ACL contains any WAF rules or rule groups. This rule is NON_COMPLIANT if a Web ACL does not contain any WAF rule or rule group."
      resource_types_scope = ["AWS::WAF::WebACL"]
      severity             = "Medium"
    }

    waf-regional-rulegroup-not-empty = {
      description          = "Checks if WAF Regional rule groups contain any rules. The rule is NON_COMPLIANT if there are no rules present within a WAF Regional rule group."
      resource_types_scope = ["AWS::WAFRegional::RuleGroup"]
      severity             = "Medium"
    }

    waf-regional-rule-not-empty = {
      description          = "Checks whether WAF regional rule contains conditions. This rule is COMPLIANT if the regional rule contains at least one condition and NON_COMPLIANT otherwise."
      resource_types_scope = ["AWS::WAFRegional::Rule"]
      severity             = "Medium"
    }

    waf-regional-webacl-not-empty = {
      description          = "Checks if a WAF regional Web ACL contains any WAF rules or rule groups. The rule is NON_COMPLIANT if there are no WAF rules or rule groups present within a Web ACL."
      resource_types_scope = ["AWS::WAFRegional::WebACL"]
      severity             = "Medium"
    }

  }
}
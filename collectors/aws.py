"""
AWS Cloud Resource Collector
Fetches diagnostic information from AWS resources.
Supports: EC2, ECS, EKS, Lambda, RDS, ALB, ECR, Fargate, Auto Scaling, and more.
Focuses on safe read-only operations.
"""
import os
from typing import Optional, Dict, Any, List

import structlog

from collectors.database_policy import check_database_access, filter_supported_types

log = structlog.get_logger()

# Supported resource types — see collectors/cloud_registry.py
SUPPORTED_TYPES = [
    "ec2", "ecs", "fargate", "eks", "eks_nodegroup", "ecr", "lambda", "rds",
    "elasticache", "dynamodb", "alb", "elb", "vpc", "s3", "sqs", "sns",
    "cloudwatch", "autoscaling", "elasticbeanstalk", "apprunner", "batch",
]


class AWSCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.region = os.getenv("AWS_REGION", "us-east-1")

    def list_supported_types(self) -> List[str]:
        return filter_supported_types(SUPPORTED_TYPES)

    async def collect(self, resource_type: str, resource_id: str, **kwargs) -> dict:
        """
        Collect diagnostic info for AWS resources.

        Args:
            resource_type: See SUPPORTED_TYPES / cloud_registry.AWS_SERVICES
            resource_id: Instance ID, cluster name, ARN, function name, etc.
            **kwargs: cluster, log_group, log_stream, vpc_id, etc.
        """
        resource_type = resource_type.lower()
        if resource_type == "fargate":
            resource_type = "ecs"

        blocked = check_database_access(resource_type, cloud="aws")
        if blocked:
            return blocked

        handlers = {
            "ec2": lambda: self._collect_ec2(resource_id),
            "ecs": lambda: self._collect_ecs(kwargs.get("cluster"), resource_id),
            "eks": lambda: self._collect_eks(resource_id),
            "eks_nodegroup": lambda: self._collect_eks_nodegroup(
                kwargs.get("cluster", resource_id), kwargs.get("nodegroup", resource_id)
            ),
            "ecr": lambda: self._collect_ecr(resource_id),
            "lambda": lambda: self._collect_lambda(resource_id),
            "rds": lambda: self._collect_rds(resource_id),
            "elasticache": lambda: self._collect_elasticache(resource_id),
            "dynamodb": lambda: self._collect_dynamodb(resource_id),
            "alb": lambda: self._collect_alb(resource_id),
            "elb": lambda: self._collect_elb(resource_id),
            "vpc": lambda: self._collect_vpc(resource_id or kwargs.get("vpc_id")),
            "s3": lambda: self._collect_s3(resource_id),
            "sqs": lambda: self._collect_sqs(resource_id),
            "sns": lambda: self._collect_sns(resource_id),
            "cloudwatch": lambda: self._collect_cloudwatch_logs(
                kwargs.get("log_group", resource_id), kwargs.get("log_stream")
            ),
            "autoscaling": lambda: self._collect_autoscaling(resource_id),
            "elasticbeanstalk": lambda: self._collect_elasticbeanstalk(resource_id),
            "apprunner": lambda: self._collect_apprunner(resource_id),
            "batch": lambda: self._collect_batch(resource_id, kwargs.get("job_queue")),
        }

        try:
            handler = handlers.get(resource_type)
            if not handler:
                return {
                    "error": f"Unsupported AWS resource type: {resource_type}",
                    "supported_types": SUPPORTED_TYPES,
                }
            return await handler()
        except Exception as e:
            log.error("AWS collection failed", resource_type=resource_type, error=str(e))
            return {"error": str(e)}

    def _boto3_error(self) -> dict:
        return {"error": "boto3 not installed. Run: pip install boto3 botocore"}

    async def _collect_ec2(self, instance_id: str) -> dict:
        """Collect EC2 VM diagnostics."""
        try:
            import boto3
            ec2 = boto3.client("ec2", region_name=self.region)

            response = ec2.describe_instances(InstanceIds=[instance_id])
            if not response["Reservations"]:
                return {"error": f"Instance {instance_id} not found"}

            instance = response["Reservations"][0]["Instances"][0]
            status = ec2.describe_instance_status(InstanceIds=[instance_id])
            status_checks = status["InstanceStatuses"][0] if status["InstanceStatuses"] else {}

            try:
                console_output = ec2.get_console_output(InstanceId=instance_id)
                console_text = console_output.get("Output", "")
                console_text = console_text[-4000:] if len(console_text) > 4000 else console_text
            except Exception:
                console_text = "Console output not available"

            return {
                "resource_type": "ec2",
                "instance_id": instance_id,
                "state": instance.get("State", {}).get("Name"),
                "instance_type": instance.get("InstanceType"),
                "availability_zone": instance.get("Placement", {}).get("AvailabilityZone"),
                "private_ip": instance.get("PrivateIpAddress"),
                "public_ip": instance.get("PublicIpAddress"),
                "launch_time": str(instance.get("LaunchTime")),
                "platform": instance.get("PlatformDetails", "Linux"),
                "tags": {tag["Key"]: tag["Value"] for tag in instance.get("Tags", [])},
                "status_checks": {
                    "system_status": status_checks.get("SystemStatus", {}).get("Status"),
                    "instance_status": status_checks.get("InstanceStatus", {}).get("Status"),
                },
                "console_output": console_text,
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"EC2 collection failed: {str(e)}"}

    async def _collect_eks(self, cluster_name: str) -> dict:
        """Collect Amazon EKS cluster diagnostics."""
        try:
            import boto3
            eks = boto3.client("eks", region_name=self.region)

            cluster = eks.describe_cluster(name=cluster_name)["cluster"]
            nodegroups = []
            for ng_name in eks.list_nodegroups(clusterName=cluster_name).get("nodegroups", []):
                ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=ng_name)["nodegroup"]
                nodegroups.append({
                    "name": ng_name,
                    "status": ng.get("status"),
                    "instance_types": ng.get("instanceTypes", []),
                    "scaling": ng.get("scalingConfig", {}),
                    "health": ng.get("health", {}).get("issues", []),
                    "disk_size": ng.get("diskSize"),
                    "ami_type": ng.get("amiType"),
                })

            addons = []
            try:
                for addon in eks.list_addons(clusterName=cluster_name).get("addons", []):
                    detail = eks.describe_addon(clusterName=cluster_name, addonName=addon)["addon"]
                    addons.append({
                        "name": addon,
                        "status": detail.get("status"),
                        "version": detail.get("addonVersion"),
                        "health": detail.get("health", {}).get("issues", []),
                    })
            except Exception:
                pass

            return {
                "resource_type": "eks",
                "cluster_name": cluster_name,
                "status": cluster.get("status"),
                "version": cluster.get("version"),
                "platform_version": cluster.get("platformVersion"),
                "endpoint": cluster.get("endpoint"),
                "region": self.region,
                "created_at": str(cluster.get("createdAt")),
                "logging": cluster.get("logging", {}).get("clusterLogging", []),
                "nodegroups": nodegroups,
                "addons": addons,
                "health_issues": cluster.get("health", {}).get("issues", []),
                "note": "Use K8s collector for pod-level diagnostics",
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"EKS collection failed: {str(e)}"}

    async def _collect_eks_nodegroup(self, cluster_name: str, nodegroup_name: str) -> dict:
        """Collect EKS node group diagnostics."""
        try:
            import boto3
            eks = boto3.client("eks", region_name=self.region)
            ng = eks.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)["nodegroup"]
            return {
                "resource_type": "eks_nodegroup",
                "cluster_name": cluster_name,
                "nodegroup_name": nodegroup_name,
                "status": ng.get("status"),
                "instance_types": ng.get("instanceTypes", []),
                "scaling": ng.get("scalingConfig", {}),
                "health_issues": ng.get("health", {}).get("issues", []),
                "resources": ng.get("resources", {}),
                "disk_size": ng.get("diskSize"),
                "ami_type": ng.get("amiType"),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"EKS nodegroup collection failed: {str(e)}"}

    async def _collect_ecs(self, cluster: str, task_arn: str) -> dict:
        """Collect ECS / Fargate task diagnostics."""
        try:
            import boto3
            ecs = boto3.client("ecs", region_name=self.region)

            tasks = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])
            if not tasks["tasks"]:
                return {"error": f"Task {task_arn} not found in cluster {cluster}"}

            task = tasks["tasks"][0]
            launch_type = task.get("launchType", "EC2")

            container_logs = {}
            for container in task.get("containers", []):
                container_name = container.get("name")
                if container.get("logConfiguration", {}).get("logDriver") == "awslogs":
                    log_options = container["logConfiguration"]["options"]
                    log_group = log_options.get("awslogs-group")
                    log_stream = log_options.get("awslogs-stream-prefix", "")
                    if log_group:
                        logs_data = await self._collect_cloudwatch_logs(
                            log_group,
                            f"{log_stream}/{container_name}/{task_arn.split('/')[-1]}",
                        )
                        container_logs[container_name] = logs_data.get("logs", "")

            return {
                "resource_type": "ecs",
                "launch_type": launch_type,
                "cluster": cluster,
                "task_arn": task_arn,
                "task_definition": task.get("taskDefinitionArn"),
                "last_status": task.get("lastStatus"),
                "desired_status": task.get("desiredStatus"),
                "started_at": str(task.get("startedAt")),
                "stopped_at": str(task.get("stoppedAt")) if task.get("stoppedAt") else None,
                "stopped_reason": task.get("stoppedReason"),
                "cpu": task.get("cpu"),
                "memory": task.get("memory"),
                "containers": [
                    {
                        "name": c.get("name"),
                        "status": c.get("lastStatus"),
                        "exit_code": c.get("exitCode"),
                        "reason": c.get("reason"),
                    }
                    for c in task.get("containers", [])
                ],
                "container_logs": container_logs,
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"ECS collection failed: {str(e)}"}

    async def _collect_ecr(self, repository_name: str) -> dict:
        """Collect ECR repository diagnostics."""
        try:
            import boto3
            ecr = boto3.client("ecr", region_name=self.region)

            repo = ecr.describe_repositories(repositoryNames=[repository_name])
            if not repo["repositories"]:
                return {"error": f"ECR repository {repository_name} not found"}

            repository = repo["repositories"][0]
            images = ecr.describe_images(
                repositoryName=repository_name, maxResults=10, filter={"tagStatus": "TAGGED"}
            )

            return {
                "resource_type": "ecr",
                "repository_name": repository_name,
                "uri": repository.get("repositoryUri"),
                "created_at": str(repository.get("createdAt")),
                "image_scanning": repository.get("imageScanningConfiguration", {}),
                "image_count": len(images.get("imageDetails", [])),
                "recent_images": [
                    {
                        "tags": img.get("imageTags", []),
                        "pushed_at": str(img.get("imagePushedAt")),
                        "size_mb": round(img.get("imageSizeInBytes", 0) / 1024 / 1024, 2),
                    }
                    for img in images.get("imageDetails", [])[:5]
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"ECR collection failed: {str(e)}"}

    async def _collect_lambda(self, function_name: str) -> dict:
        """Collect Lambda function diagnostics."""
        try:
            import boto3
            lambda_client = boto3.client("lambda", region_name=self.region)
            logs_client = boto3.client("logs", region_name=self.region)

            func = lambda_client.get_function(FunctionName=function_name)
            config = func["Configuration"]
            log_group = f"/aws/lambda/{function_name}"

            try:
                streams = logs_client.describe_log_streams(
                    logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=3
                )
                recent_logs = []
                for stream in streams.get("logStreams", [])[:2]:
                    events = logs_client.get_log_events(
                        logGroupName=log_group,
                        logStreamName=stream["logStreamName"],
                        limit=50,
                        startFromHead=False,
                    )
                    for event in events.get("events", []):
                        if "ERROR" in event.get("message", ""):
                            recent_logs.append(event.get("message"))
                log_summary = "\n".join(recent_logs[-10:])
            except Exception:
                log_summary = "Unable to fetch recent logs"

            return {
                "resource_type": "lambda",
                "function_name": function_name,
                "runtime": config.get("Runtime"),
                "state": config.get("State"),
                "last_update_status": config.get("LastUpdateStatus"),
                "memory_size": config.get("MemorySize"),
                "timeout": config.get("Timeout"),
                "handler": config.get("Handler"),
                "role": config.get("Role"),
                "recent_error_logs": log_summary,
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"Lambda collection failed: {str(e)}"}

    async def _collect_rds(self, db_instance_id: str) -> dict:
        """Collect RDS instance diagnostics."""
        try:
            import boto3
            rds = boto3.client("rds", region_name=self.region)

            response = rds.describe_db_instances(DBInstanceIdentifier=db_instance_id)
            if not response["DBInstances"]:
                return {"error": f"RDS instance {db_instance_id} not found"}

            db = response["DBInstances"][0]
            events = rds.describe_events(
                SourceIdentifier=db_instance_id, SourceType="db-instance", MaxRecords=20
            )

            return {
                "resource_type": "rds",
                "db_instance_id": db_instance_id,
                "status": db.get("DBInstanceStatus"),
                "engine": db.get("Engine"),
                "engine_version": db.get("EngineVersion"),
                "instance_class": db.get("DBInstanceClass"),
                "availability_zone": db.get("AvailabilityZone"),
                "multi_az": db.get("MultiAZ"),
                "storage_encrypted": db.get("StorageEncrypted"),
                "endpoint": db.get("Endpoint", {}).get("Address"),
                "port": db.get("Endpoint", {}).get("Port"),
                "recent_events": [
                    {"date": str(e.get("Date")), "message": e.get("Message")}
                    for e in events.get("Events", [])[:10]
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"RDS collection failed: {str(e)}"}

    async def _collect_elasticache(self, cluster_id: str) -> dict:
        """Collect ElastiCache cluster diagnostics."""
        try:
            import boto3
            client = boto3.client("elasticache", region_name=self.region)

            clusters = client.describe_cache_clusters(CacheClusterId=cluster_id, ShowCacheNodeInfo=True)
            if not clusters["CacheClusters"]:
                return {"error": f"ElastiCache cluster {cluster_id} not found"}

            cluster = clusters["CacheClusters"][0]
            return {
                "resource_type": "elasticache",
                "cluster_id": cluster_id,
                "status": cluster.get("CacheClusterStatus"),
                "engine": cluster.get("Engine"),
                "engine_version": cluster.get("EngineVersion"),
                "node_type": cluster.get("CacheNodeType"),
                "num_nodes": cluster.get("NumCacheNodes"),
                "endpoint": cluster.get("ConfigurationEndpoint") or cluster.get("CacheNodes", [{}])[0].get("Endpoint"),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"ElastiCache collection failed: {str(e)}"}

    async def _collect_dynamodb(self, table_name: str) -> dict:
        """Collect DynamoDB table status (read-only)."""
        try:
            import boto3
            dynamodb = boto3.client("dynamodb", region_name=self.region)
            table = dynamodb.describe_table(TableName=table_name)["Table"]
            return {
                "resource_type": "dynamodb",
                "table_name": table_name,
                "status": table.get("TableStatus"),
                "item_count": table.get("ItemCount"),
                "size_bytes": table.get("TableSizeBytes"),
                "billing_mode": table.get("BillingModeSummary", {}).get("BillingMode"),
                "stream_enabled": table.get("StreamSpecification", {}).get("StreamEnabled"),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"DynamoDB collection failed: {str(e)}"}

    async def _collect_alb(self, load_balancer_arn: str) -> dict:
        """Collect Application Load Balancer diagnostics."""
        try:
            import boto3
            elbv2 = boto3.client("elbv2", region_name=self.region)

            lbs = elbv2.describe_load_balancers(LoadBalancerArns=[load_balancer_arn])
            if not lbs["LoadBalancers"]:
                return {"error": f"ALB {load_balancer_arn} not found"}

            lb = lbs["LoadBalancers"][0]
            target_groups = elbv2.describe_target_groups(LoadBalancerArn=load_balancer_arn)

            unhealthy_targets = []
            for tg in target_groups.get("TargetGroups", [])[:5]:
                health = elbv2.describe_target_health(TargetGroupArn=tg["TargetGroupArn"])
                for target in health.get("TargetHealthDescriptions", []):
                    if target.get("TargetHealth", {}).get("State") != "healthy":
                        unhealthy_targets.append({
                            "target_group": tg.get("TargetGroupName"),
                            "target": target.get("Target", {}).get("Id"),
                            "state": target.get("TargetHealth", {}).get("State"),
                            "reason": target.get("TargetHealth", {}).get("Reason"),
                        })

            return {
                "resource_type": "alb",
                "name": lb.get("LoadBalancerName"),
                "dns_name": lb.get("DNSName"),
                "state": lb.get("State", {}).get("Code"),
                "scheme": lb.get("Scheme"),
                "type": lb.get("Type"),
                "availability_zones": [az.get("ZoneName") for az in lb.get("AvailabilityZones", [])],
                "target_group_count": len(target_groups.get("TargetGroups", [])),
                "unhealthy_targets": unhealthy_targets[:10],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"ALB collection failed: {str(e)}"}

    async def _collect_elb(self, load_balancer_name: str) -> dict:
        """Collect Classic/Network Load Balancer diagnostics."""
        try:
            import boto3
            elb = boto3.client("elb", region_name=self.region)
            lb = elb.describe_load_balancers(LoadBalancerNames=[load_balancer_name])
            if not lb["LoadBalancerDescriptions"]:
                return {"error": f"ELB {load_balancer_name} not found"}

            description = lb["LoadBalancerDescriptions"][0]
            health = elb.describe_instance_health(LoadBalancerName=load_balancer_name)

            return {
                "resource_type": "elb",
                "name": load_balancer_name,
                "dns_name": description.get("DNSName"),
                "scheme": description.get("Scheme"),
                "instances": len(description.get("Instances", [])),
                "unhealthy_instances": [
                    {
                        "instance_id": h.get("InstanceId"),
                        "state": h.get("State"),
                        "reason": h.get("Reason"),
                    }
                    for h in health.get("InstanceStates", [])
                    if h.get("State") != "InService"
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"ELB collection failed: {str(e)}"}

    async def _collect_vpc(self, vpc_id: str) -> dict:
        """Collect VPC summary (read-only)."""
        try:
            import boto3
            ec2 = boto3.client("ec2", region_name=self.region)

            vpcs = ec2.describe_vpcs(VpcIds=[vpc_id])
            if not vpcs["Vpcs"]:
                return {"error": f"VPC {vpc_id} not found"}

            vpc = vpcs["Vpcs"][0]
            subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])

            return {
                "resource_type": "vpc",
                "vpc_id": vpc_id,
                "state": vpc.get("State"),
                "cidr": vpc.get("CidrBlock"),
                "subnet_count": len(subnets.get("Subnets", [])),
                "subnets": [
                    {
                        "id": s.get("SubnetId"),
                        "az": s.get("AvailabilityZone"),
                        "available_ips": s.get("AvailableIpAddressCount"),
                    }
                    for s in subnets.get("Subnets", [])[:10]
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"VPC collection failed: {str(e)}"}

    async def _collect_s3(self, bucket_name: str) -> dict:
        """Collect S3 bucket status (read-only, no object listing)."""
        try:
            import boto3
            s3 = boto3.client("s3", region_name=self.region)

            location = s3.get_bucket_location(Bucket=bucket_name)
            try:
                versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            except Exception:
                versioning = {}

            return {
                "resource_type": "s3",
                "bucket_name": bucket_name,
                "region": location.get("LocationConstraint") or "us-east-1",
                "versioning": versioning.get("Status", "Disabled"),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"S3 collection failed: {str(e)}"}

    async def _collect_sqs(self, queue_url: str) -> dict:
        """Collect SQS queue diagnostics."""
        try:
            import boto3
            sqs = boto3.client("sqs", region_name=self.region)
            attrs = sqs.get_queue_attributes(
                QueueUrl=queue_url,
                AttributeNames=["ApproximateNumberOfMessages", "ApproximateNumberOfMessagesNotVisible", "QueueArn"],
            )
            return {
                "resource_type": "sqs",
                "queue_url": queue_url,
                "messages_visible": attrs["Attributes"].get("ApproximateNumberOfMessages"),
                "messages_in_flight": attrs["Attributes"].get("ApproximateNumberOfMessagesNotVisible"),
                "queue_arn": attrs["Attributes"].get("QueueArn"),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"SQS collection failed: {str(e)}"}

    async def _collect_sns(self, topic_arn: str) -> dict:
        """Collect SNS topic diagnostics."""
        try:
            import boto3
            sns = boto3.client("sns", region_name=self.region)
            attrs = sns.get_topic_attributes(TopicArn=topic_arn)
            subs = sns.list_subscriptions_by_topic(TopicArn=topic_arn)
            return {
                "resource_type": "sns",
                "topic_arn": topic_arn,
                "display_name": attrs["Attributes"].get("DisplayName"),
                "subscriptions_confirmed": attrs["Attributes"].get("SubscriptionsConfirmed"),
                "subscriptions_pending": attrs["Attributes"].get("SubscriptionsPending"),
                "subscription_count": len(subs.get("Subscriptions", [])),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"SNS collection failed: {str(e)}"}

    async def _collect_autoscaling(self, asg_name: str) -> dict:
        """Collect Auto Scaling group diagnostics."""
        try:
            import boto3
            asg = boto3.client("autoscaling", region_name=self.region)
            groups = asg.describe_auto_scaling_groups(AutoScalingGroupNames=[asg_name])
            if not groups["AutoScalingGroups"]:
                return {"error": f"Auto Scaling group {asg_name} not found"}

            group = groups["AutoScalingGroups"][0]
            activities = asg.describe_scaling_activities(AutoScalingGroupName=asg_name, MaxRecords=5)

            return {
                "resource_type": "autoscaling",
                "asg_name": asg_name,
                "desired_capacity": group.get("DesiredCapacity"),
                "min_size": group.get("MinSize"),
                "max_size": group.get("MaxSize"),
                "instance_count": len(group.get("Instances", [])),
                "health_check_type": group.get("HealthCheckType"),
                "instances": [
                    {"id": i.get("InstanceId"), "health": i.get("HealthStatus"), "az": i.get("AvailabilityZone")}
                    for i in group.get("Instances", [])[:20]
                ],
                "recent_activities": [
                    {"status": a.get("StatusCode"), "description": a.get("Description"), "time": str(a.get("StartTime"))}
                    for a in activities.get("Activities", [])
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"Auto Scaling collection failed: {str(e)}"}

    async def _collect_elasticbeanstalk(self, environment_name: str) -> dict:
        """Collect Elastic Beanstalk environment diagnostics."""
        try:
            import boto3
            eb = boto3.client("elasticbeanstalk", region_name=self.region)
            env = eb.describe_environments(EnvironmentNames=[environment_name])
            if not env["Environments"]:
                return {"error": f"EB environment {environment_name} not found"}

            environment = env["Environments"][0]
            events = eb.describe_events(EnvironmentName=environment_name, MaxRecords=10)

            return {
                "resource_type": "elasticbeanstalk",
                "environment_name": environment_name,
                "status": environment.get("Status"),
                "health": environment.get("Health"),
                "health_status": environment.get("HealthStatus"),
                "platform": environment.get("PlatformArn", "").split("/")[-1],
                "cname": environment.get("CNAME"),
                "recent_events": [
                    {"severity": e.get("Severity"), "message": e.get("Message"), "time": str(e.get("EventDate"))}
                    for e in events.get("Events", [])
                ],
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"Elastic Beanstalk collection failed: {str(e)}"}

    async def _collect_apprunner(self, service_arn: str) -> dict:
        """Collect App Runner service diagnostics."""
        try:
            import boto3
            apprunner = boto3.client("apprunner", region_name=self.region)
            service = apprunner.describe_service(ServiceArn=service_arn)["Service"]
            return {
                "resource_type": "apprunner",
                "service_arn": service_arn,
                "service_name": service.get("ServiceName"),
                "status": service.get("Status"),
                "service_url": service.get("ServiceUrl"),
                "created_at": str(service.get("CreatedAt")),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"App Runner collection failed: {str(e)}"}

    async def _collect_batch(self, job_id: str, job_queue: Optional[str] = None) -> dict:
        """Collect AWS Batch job diagnostics."""
        try:
            import boto3
            batch = boto3.client("batch", region_name=self.region)
            jobs = batch.describe_jobs(jobs=[job_id])
            if not jobs["jobs"]:
                return {"error": f"Batch job {job_id} not found"}

            job = jobs["jobs"][0]
            return {
                "resource_type": "batch",
                "job_id": job_id,
                "job_name": job.get("jobName"),
                "status": job.get("status"),
                "status_reason": job.get("statusReason"),
                "job_queue": job.get("jobQueue"),
                "started_at": str(job.get("startedAt")) if job.get("startedAt") else None,
                "stopped_at": str(job.get("stoppedAt")) if job.get("stoppedAt") else None,
                "container": job.get("container", {}),
            }
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"Batch collection failed: {str(e)}"}

    async def _collect_cloudwatch_logs(self, log_group: str, log_stream: Optional[str] = None) -> dict:
        """Collect recent CloudWatch logs."""
        try:
            import boto3
            logs = boto3.client("logs", region_name=self.region)

            if log_stream:
                events = logs.get_log_events(
                    logGroupName=log_group, logStreamName=log_stream, limit=100, startFromHead=False
                )
                log_lines = [e.get("message") for e in events.get("events", [])]
                log_text = "\n".join(log_lines[-50:])
            else:
                streams = logs.describe_log_streams(
                    logGroupName=log_group, orderBy="LastEventTime", descending=True, limit=1
                )
                if not streams.get("logStreams"):
                    return {"resource_type": "cloudwatch", "logs": "No log streams found"}

                stream_name = streams["logStreams"][0]["logStreamName"]
                events = logs.get_log_events(
                    logGroupName=log_group, logStreamName=stream_name, limit=100, startFromHead=False
                )
                log_lines = [e.get("message") for e in events.get("events", [])]
                log_text = "\n".join(log_lines[-50:])

            return {"resource_type": "cloudwatch", "log_group": log_group, "log_stream": log_stream, "logs": log_text}
        except ImportError:
            return self._boto3_error()
        except Exception as e:
            return {"error": f"CloudWatch logs collection failed: {str(e)}"}

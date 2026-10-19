"""
Cloud Provider Tools (AWS, GCP, Azure)
Provides SAFE operations for cloud resources.
Only includes non-destructive, monitoring, and light remediation actions.
"""
import os
from typing import Optional

import structlog

log = structlog.get_logger()


class CloudTools:
    """Unified cloud tools for AWS, GCP, and Azure."""
    
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.aws_region = os.getenv("AWS_REGION", "us-east-1")
        self.gcp_project = os.getenv("GCP_PROJECT_ID", "")
        self.azure_subscription = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    async def restart_instance(self, cloud: str, resource_id: str, **kwargs) -> dict:
        """
        Restart a cloud instance (safe operation).
        
        Args:
            cloud: 'aws', 'gcp', 'azure'
            resource_id: Instance ID/name
        """
        if cloud == "aws":
            return await self._restart_ec2_instance(resource_id)
        elif cloud == "gcp":
            return await self._restart_gce_instance(resource_id, kwargs.get("zone"))
        elif cloud == "azure":
            return await self._restart_azure_vm(resource_id, kwargs.get("resource_group"))
        else:
            return {"error": f"Unsupported cloud: {cloud}"}

    async def restart_service(self, cloud: str, service_type: str, service_id: str, **kwargs) -> dict:
        """
        Restart a cloud service (ECS task, Cloud Run, App Service, etc.).
        
        Args:
            cloud: 'aws', 'gcp', 'azure'
            service_type: 'ecs', 'lambda', 'cloud_run', 'app_service', etc.
            service_id: Service identifier
        """
        if cloud == "aws":
            if service_type == "ecs":
                return await self._restart_ecs_service(kwargs.get("cluster"), service_id)
            elif service_type == "lambda":
                return {"message": "Lambda functions restart automatically. Check recent error logs."}
        elif cloud == "gcp":
            if service_type == "cloud_run":
                return await self._restart_cloud_run(service_id, kwargs.get("region"))
        elif cloud == "azure":
            if service_type == "app_service":
                return await self._restart_app_service(service_id, kwargs.get("resource_group"))
            elif service_type == "function":
                return await self._restart_azure_function(service_id, kwargs.get("resource_group"))
        
        return {"error": f"Service type {service_type} not supported for {cloud}"}

    async def scale_service(
        self,
        cloud: str,
        service_type: str,
        service_id: str,
        desired_count: int,
        **kwargs
    ) -> dict:
        """
        Scale a cloud service (safe operation, only scale up or to specific count).
        
        Args:
            cloud: 'aws', 'gcp', 'azure'
            service_type: 'ecs', 'cloud_run', 'app_service', etc.
            service_id: Service identifier
            desired_count: Desired instance count
        """
        if desired_count < 1:
            return {"error": "Cannot scale to less than 1 instance. This is a safety check."}

        if cloud == "aws" and service_type == "ecs":
            return await self._scale_ecs_service(kwargs.get("cluster"), service_id, desired_count)
        elif cloud == "gcp" and service_type == "cloud_run":
            return {"message": "Cloud Run autoscales automatically. Check service configuration."}
        elif cloud == "azure" and service_type == "app_service":
            return await self._scale_app_service(service_id, kwargs.get("resource_group"), desired_count)
        
        return {"error": f"Scaling not supported for {cloud} {service_type}"}

    # ─── AWS Tools ────────────────────────────────────────────────────────────

    async def _restart_ec2_instance(self, instance_id: str) -> dict:
        """Reboot an EC2 instance (safe operation)."""
        try:
            import boto3
            ec2 = boto3.client("ec2", region_name=self.aws_region)
            
            response = ec2.reboot_instances(InstanceIds=[instance_id])
            
            return {
                "success": True,
                "message": f"EC2 instance {instance_id} reboot initiated",
                "instance_id": instance_id,
            }
        except ImportError:
            return {"error": "boto3 not installed. Run: pip install boto3"}
        except Exception as e:
            log.error("EC2 restart failed", error=str(e))
            return {"error": str(e)}

    async def _restart_ecs_service(self, cluster: str, service: str) -> dict:
        """Force new deployment of ECS service (safe operation)."""
        try:
            import boto3
            ecs = boto3.client("ecs", region_name=self.aws_region)
            
            response = ecs.update_service(
                cluster=cluster,
                service=service,
                forceNewDeployment=True
            )
            
            return {
                "success": True,
                "message": f"ECS service {service} force deployment initiated",
                "cluster": cluster,
                "service": service,
            }
        except ImportError:
            return {"error": "boto3 not installed"}
        except Exception as e:
            log.error("ECS restart failed", error=str(e))
            return {"error": str(e)}

    async def _scale_ecs_service(self, cluster: str, service: str, desired_count: int) -> dict:
        """Scale ECS service."""
        try:
            import boto3
            ecs = boto3.client("ecs", region_name=self.aws_region)
            
            response = ecs.update_service(
                cluster=cluster,
                service=service,
                desiredCount=desired_count
            )
            
            return {
                "success": True,
                "message": f"ECS service {service} scaled to {desired_count} tasks",
                "cluster": cluster,
                "service": service,
                "desired_count": desired_count,
            }
        except ImportError:
            return {"error": "boto3 not installed"}
        except Exception as e:
            log.error("ECS scale failed", error=str(e))
            return {"error": str(e)}

    # ─── GCP Tools ────────────────────────────────────────────────────────────

    async def _restart_gce_instance(self, instance_name: str, zone: str) -> dict:
        """Reset a GCE instance (safe operation)."""
        try:
            from google.cloud import compute_v1
            
            client = compute_v1.InstancesClient()
            
            operation = client.reset(
                project=self.gcp_project,
                zone=zone,
                instance=instance_name
            )
            
            return {
                "success": True,
                "message": f"GCE instance {instance_name} reset initiated",
                "instance": instance_name,
                "zone": zone,
            }
        except ImportError:
            return {"error": "google-cloud-compute not installed"}
        except Exception as e:
            log.error("GCE restart failed", error=str(e))
            return {"error": str(e)}

    async def _restart_cloud_run(self, service_name: str, region: str) -> dict:
        """Restart Cloud Run service by updating with latest image."""
        try:
            from google.cloud import run_v2
            
            client = run_v2.ServicesClient()
            service_path = f"projects/{self.gcp_project}/locations/{region}/services/{service_name}"
            
            # Get current service
            service = client.get_service(name=service_path)
            
            # Update service to trigger new revision (essentially a restart)
            # This is done by updating a label
            import time
            service.labels["restart-trigger"] = str(int(time.time()))
            
            operation = client.update_service(service=service)
            
            return {
                "success": True,
                "message": f"Cloud Run service {service_name} update initiated (will create new revision)",
                "service": service_name,
                "region": region,
            }
        except ImportError:
            return {"error": "google-cloud-run not installed"}
        except Exception as e:
            log.error("Cloud Run restart failed", error=str(e))
            return {"error": str(e)}

    # ─── Azure Tools ──────────────────────────────────────────────────────────

    async def _restart_azure_vm(self, vm_name: str, resource_group: str) -> dict:
        """Restart an Azure VM (safe operation)."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            
            credential = DefaultAzureCredential()
            compute_client = ComputeManagementClient(credential, self.azure_subscription)
            
            # Async operation - returns poller
            operation = compute_client.virtual_machines.begin_restart(
                resource_group_name=resource_group,
                vm_name=vm_name
            )
            
            return {
                "success": True,
                "message": f"Azure VM {vm_name} restart initiated",
                "vm_name": vm_name,
                "resource_group": resource_group,
            }
        except ImportError:
            return {"error": "azure-mgmt-compute and azure-identity not installed"}
        except Exception as e:
            log.error("Azure VM restart failed", error=str(e))
            return {"error": str(e)}

    async def _restart_app_service(self, app_name: str, resource_group: str) -> dict:
        """Restart an Azure App Service."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.web import WebSiteManagementClient
            
            credential = DefaultAzureCredential()
            web_client = WebSiteManagementClient(credential, self.azure_subscription)
            
            web_client.web_apps.restart(
                resource_group_name=resource_group,
                name=app_name
            )
            
            return {
                "success": True,
                "message": f"Azure App Service {app_name} restart initiated",
                "app_name": app_name,
                "resource_group": resource_group,
            }
        except ImportError:
            return {"error": "azure-mgmt-web and azure-identity not installed"}
        except Exception as e:
            log.error("App Service restart failed", error=str(e))
            return {"error": str(e)}

    async def _restart_azure_function(self, function_app_name: str, resource_group: str) -> dict:
        """Restart an Azure Function App."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.web import WebSiteManagementClient
            
            credential = DefaultAzureCredential()
            web_client = WebSiteManagementClient(credential, self.azure_subscription)
            
            # Function Apps are web apps
            web_client.web_apps.restart(
                resource_group_name=resource_group,
                name=function_app_name
            )
            
            return {
                "success": True,
                "message": f"Azure Function App {function_app_name} restart initiated",
                "function_app": function_app_name,
                "resource_group": resource_group,
            }
        except ImportError:
            return {"error": "azure-mgmt-web and azure-identity not installed"}
        except Exception as e:
            log.error("Function App restart failed", error=str(e))
            return {"error": str(e)}

    async def _scale_app_service(self, app_name: str, resource_group: str, instance_count: int) -> dict:
        """Scale an Azure App Service."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.web import WebSiteManagementClient
            from azure.mgmt.web.models import SiteConfig
            
            credential = DefaultAzureCredential()
            web_client = WebSiteManagementClient(credential, self.azure_subscription)
            
            # Get current app
            app = web_client.web_apps.get(
                resource_group_name=resource_group,
                name=app_name
            )
            
            # Update site config with new instance count
            site_config = SiteConfig(number_of_workers=instance_count)
            
            web_client.web_apps.update_configuration(
                resource_group_name=resource_group,
                name=app_name,
                site_config=site_config
            )
            
            return {
                "success": True,
                "message": f"Azure App Service {app_name} scaled to {instance_count} instances",
                "app_name": app_name,
                "instance_count": instance_count,
            }
        except ImportError:
            return {"error": "azure-mgmt-web and azure-identity not installed"}
        except Exception as e:
            log.error("App Service scale failed", error=str(e))
            return {"error": str(e)}

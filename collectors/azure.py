"""
Azure Cloud Resource Collector
Fetches diagnostic information from Azure resources.
Supports: VMs, AKS, ACI, Container Apps, App Service, Functions, SQL, and more.
Focuses on safe read-only operations.
"""
import os
from typing import Optional, List

import structlog

from collectors.database_policy import check_database_access, filter_supported_types

log = structlog.get_logger()

SUPPORTED_TYPES = [
    "vm", "vmss", "aks", "aci", "container_instance", "container_apps", "acr",
    "app_service", "function", "sql", "cosmosdb", "redis", "load_balancer",
    "application_gateway", "storage", "service_bus", "batch",
]


class AzureCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.subscription_id = os.getenv("AZURE_SUBSCRIPTION_ID", "")

    def list_supported_types(self) -> List[str]:
        return filter_supported_types(SUPPORTED_TYPES)

    async def collect(self, resource_type: str, resource_name: str, **kwargs) -> dict:
        """
        Collect diagnostic info for Azure resources.

        Args:
            resource_type: See SUPPORTED_TYPES / cloud_registry.AZURE_SERVICES
            resource_name: Resource name or ID
        """
        resource_type = resource_type.lower()
        if resource_type == "container_instance":
            resource_type = "aci"

        blocked = check_database_access(resource_type, cloud="azure")
        if blocked:
            return blocked

        rg = kwargs.get("resource_group")

        handlers = {
            "vm": lambda: self._collect_vm(resource_name, rg),
            "vmss": lambda: self._collect_vmss(resource_name, rg),
            "aks": lambda: self._collect_aks(resource_name, rg),
            "aci": lambda: self._collect_aci(resource_name, rg),
            "container_apps": lambda: self._collect_container_apps(resource_name, rg),
            "acr": lambda: self._collect_acr(resource_name, rg),
            "app_service": lambda: self._collect_app_service(resource_name, rg),
            "function": lambda: self._collect_function(resource_name, rg),
            "sql": lambda: self._collect_sql(resource_name, rg, kwargs.get("database_name")),
            "cosmosdb": lambda: self._collect_cosmosdb(resource_name, rg),
            "redis": lambda: self._collect_redis(resource_name, rg),
            "load_balancer": lambda: self._collect_load_balancer(resource_name, rg),
            "application_gateway": lambda: self._collect_application_gateway(resource_name, rg),
            "storage": lambda: self._collect_storage(resource_name, rg),
            "service_bus": lambda: self._collect_service_bus(resource_name, rg, kwargs.get("entity_type", "queue")),
            "batch": lambda: self._collect_batch(resource_name, rg),
        }

        try:
            handler = handlers.get(resource_type)
            if not handler:
                return {
                    "error": f"Unsupported Azure resource type: {resource_type}",
                    "supported_types": SUPPORTED_TYPES,
                }
            return await handler()
        except Exception as e:
            log.error("Azure collection failed", resource_type=resource_type, error=str(e))
            return {"error": str(e)}

    def _azure_import_error(self, packages: str) -> dict:
        return {"error": f"{packages} not installed. Run: pip install {packages}"}

    async def _collect_vm(self, vm_name: str, resource_group: str) -> dict:
        """Collect Azure Virtual Machine diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient
            from azure.mgmt.monitor import MonitorManagementClient
            from datetime import datetime, timedelta

            credential = DefaultAzureCredential()
            compute_client = ComputeManagementClient(credential, self.subscription_id)
            monitor_client = MonitorManagementClient(credential, self.subscription_id)

            vm = compute_client.virtual_machines.get(
                resource_group_name=resource_group, vm_name=vm_name, expand="instanceView"
            )
            instance_view = vm.instance_view

            end_time = datetime.utcnow()
            start_time = end_time - timedelta(hours=1)
            filter_str = f"eventTimestamp ge '{start_time.isoformat()}' and resourceUri eq '{vm.id}'"

            activity_logs = []
            try:
                logs = monitor_client.activity_logs.list(filter=filter_str)
                for log_entry in logs:
                    if log_entry.level in ["Error", "Critical", "Warning"]:
                        activity_logs.append({
                            "timestamp": str(log_entry.event_timestamp),
                            "level": log_entry.level,
                            "operation": log_entry.operation_name.localized_value,
                            "status": log_entry.status.localized_value,
                        })
            except Exception:
                activity_logs = [{"error": "Unable to fetch activity logs"}]

            return {
                "resource_type": "vm",
                "vm_name": vm_name,
                "resource_group": resource_group,
                "location": vm.location,
                "vm_size": vm.hardware_profile.vm_size,
                "os_type": vm.storage_profile.os_disk.os_type,
                "provisioning_state": vm.provisioning_state,
                "power_state": instance_view.statuses[-1].code if instance_view and instance_view.statuses else "Unknown",
                "vm_agent_status": instance_view.vm_agent.statuses[0].display_status
                if instance_view and instance_view.vm_agent
                else "Unknown",
                "disks": [
                    {"name": disk.name, "size_gb": disk.disk_size_gb, "caching": disk.caching}
                    for disk in ([vm.storage_profile.os_disk] + list(vm.storage_profile.data_disks))
                ],
                "recent_activity": activity_logs[:10],
                "tags": vm.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-compute azure-identity azure-mgmt-monitor")
        except Exception as e:
            return {"error": f"Azure VM collection failed: {str(e)}"}

    async def _collect_vmss(self, vmss_name: str, resource_group: str) -> dict:
        """Collect Virtual Machine Scale Set diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.compute import ComputeManagementClient

            credential = DefaultAzureCredential()
            compute_client = ComputeManagementClient(credential, self.subscription_id)

            vmss = compute_client.virtual_machine_scale_sets.get(
                resource_group_name=resource_group, vm_scale_set_name=vmss_name
            )
            instances = list(
                compute_client.virtual_machine_scale_set_vms.list(
                    resource_group_name=resource_group, virtual_machine_scale_set_name=vmss_name
                )
            )

            return {
                "resource_type": "vmss",
                "vmss_name": vmss_name,
                "resource_group": resource_group,
                "location": vmss.location,
                "sku": vmss.sku.name if vmss.sku else None,
                "capacity": vmss.sku.capacity if vmss.sku else None,
                "provisioning_state": vmss.provisioning_state,
                "instance_count": len(instances),
                "instances": [
                    {"name": i.name, "provisioning_state": i.provisioning_state, "instance_id": i.instance_id}
                    for i in instances[:20]
                ],
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-compute azure-identity")
        except Exception as e:
            return {"error": f"VMSS collection failed: {str(e)}"}

    async def _collect_aks(self, cluster_name: str, resource_group: str) -> dict:
        """Collect AKS cluster diagnostics including node pools and agent pools."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.containerservice import ContainerServiceClient

            credential = DefaultAzureCredential()
            aks_client = ContainerServiceClient(credential, self.subscription_id)

            cluster = aks_client.managed_clusters.get(
                resource_group_name=resource_group, resource_name=cluster_name
            )
            node_pools = list(
                aks_client.agent_pools.list(resource_group_name=resource_group, resource_name=cluster_name)
            )

            return {
                "resource_type": "aks",
                "cluster_name": cluster_name,
                "resource_group": resource_group,
                "location": cluster.location,
                "kubernetes_version": cluster.kubernetes_version,
                "provisioning_state": cluster.provisioning_state,
                "power_state": cluster.power_state.code if cluster.power_state else "Unknown",
                "fqdn": cluster.fqdn,
                "node_resource_group": cluster.node_resource_group,
                "network_profile": {
                    "network_plugin": cluster.network_profile.network_plugin if cluster.network_profile else None,
                    "network_policy": cluster.network_profile.network_policy if cluster.network_profile else None,
                    "service_cidr": cluster.network_profile.service_cidr if cluster.network_profile else None,
                    "dns_service_ip": cluster.network_profile.dns_service_ip if cluster.network_profile else None,
                },
                "node_pools": [
                    {
                        "name": pool.name,
                        "count": pool.count,
                        "vm_size": pool.vm_size,
                        "os_type": pool.os_type,
                        "provisioning_state": pool.provisioning_state,
                        "mode": pool.mode,
                        "max_pods": pool.max_pods,
                    }
                    for pool in node_pools
                ],
                "addon_profiles": list(cluster.addon_profiles.keys()) if cluster.addon_profiles else [],
                "tags": cluster.tags or {},
                "note": "Use K8s collector for pod-level diagnostics",
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-containerservice azure-identity")
        except Exception as e:
            return {"error": f"AKS collection failed: {str(e)}"}

    async def _collect_aci(self, container_group_name: str, resource_group: str) -> dict:
        """Collect Azure Container Instances diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.containerinstance import ContainerInstanceManagementClient

            credential = DefaultAzureCredential()
            client = ContainerInstanceManagementClient(credential, self.subscription_id)

            group = client.container_groups.get(resource_group_name=resource_group, container_group_name=container_group_name)

            return {
                "resource_type": "aci",
                "container_group_name": container_group_name,
                "resource_group": resource_group,
                "location": group.location,
                "provisioning_state": group.provisioning_state,
                "instance_view_state": group.instance_view.state if group.instance_view else None,
                "ip_address": group.ip_address.ip if group.ip_address else None,
                "containers": [
                    {
                        "name": c.name,
                        "image": c.image,
                        "cpu": c.resources.requests.cpu if c.resources and c.resources.requests else None,
                        "memory": c.resources.requests.memory_in_gb if c.resources and c.resources.requests else None,
                        "state": c.instance_view.current_state.state if c.instance_view and c.instance_view.current_state else None,
                        "restart_count": c.instance_view.restart_count if c.instance_view else 0,
                    }
                    for c in group.containers
                ],
                "tags": group.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-containerinstance azure-identity")
        except Exception as e:
            return {"error": f"ACI collection failed: {str(e)}"}

    async def _collect_container_apps(self, app_name: str, resource_group: str) -> dict:
        """Collect Azure Container Apps diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.appcontainers import ContainerAppsAPIClient

            credential = DefaultAzureCredential()
            client = ContainerAppsAPIClient(credential, self.subscription_id)

            app = client.container_apps.get(resource_group_name=resource_group, container_app_name=app_name)

            return {
                "resource_type": "container_apps",
                "app_name": app_name,
                "resource_group": resource_group,
                "location": app.location,
                "provisioning_state": app.provisioning_state,
                "latest_revision_name": app.latest_revision_name,
                "latest_ready_revision_name": app.latest_ready_revision_name,
                "running_status": app.running_status,
                "outbound_ip_addresses": app.outbound_ip_addresses or [],
                "tags": app.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-appcontainers azure-identity")
        except Exception as e:
            return {"error": f"Container Apps collection failed: {str(e)}"}

    async def _collect_acr(self, registry_name: str, resource_group: str) -> dict:
        """Collect Azure Container Registry diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.containerregistry import ContainerRegistryManagementClient

            credential = DefaultAzureCredential()
            client = ContainerRegistryManagementClient(credential, self.subscription_id)

            registry = client.registries.get(resource_group_name=resource_group, registry_name=registry_name)

            return {
                "resource_type": "acr",
                "registry_name": registry_name,
                "resource_group": resource_group,
                "location": registry.location,
                "login_server": registry.login_server,
                "provisioning_state": registry.provisioning_state,
                "status": registry.status.display_status if registry.status else None,
                "sku": registry.sku.name if registry.sku else None,
                "admin_user_enabled": registry.admin_user_enabled,
                "tags": registry.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-containerregistry azure-identity")
        except Exception as e:
            return {"error": f"ACR collection failed: {str(e)}"}

    async def _collect_app_service(self, app_name: str, resource_group: str) -> dict:
        """Collect Azure App Service diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.web import WebSiteManagementClient
            import httpx

            credential = DefaultAzureCredential()
            web_client = WebSiteManagementClient(credential, self.subscription_id)

            app = web_client.web_apps.get(resource_group_name=resource_group, name=app_name)
            logs_summary = "Use Azure Portal or Kudu API for detailed logs"

            try:
                creds = web_client.web_apps.list_publishing_credentials(
                    resource_group_name=resource_group, name=app_name
                ).result()
                kudu_url = f"https://{app_name}.scm.azurewebsites.net/api/logs/recent"
                async with httpx.AsyncClient(
                    auth=(creds.publishing_user_name, creds.publishing_password), timeout=30
                ) as client:
                    logs_resp = await client.get(kudu_url)
                    if logs_resp.status_code == 200:
                        logs_data = logs_resp.json()
                        logs_summary = "\n".join([entry.get("message", "") for entry in logs_data[:20]])
            except Exception:
                pass

            return {
                "resource_type": "app_service",
                "app_name": app_name,
                "resource_group": resource_group,
                "location": app.location,
                "state": app.state,
                "enabled": app.enabled,
                "default_host_name": app.default_host_name,
                "runtime_stack": app.site_config.linux_fx_version if app.site_config else "Unknown",
                "https_only": app.https_only,
                "recent_logs": logs_summary,
                "tags": app.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-web azure-identity")
        except Exception as e:
            return {"error": f"App Service collection failed: {str(e)}"}

    async def _collect_function(self, function_app_name: str, resource_group: str) -> dict:
        """Collect Azure Function App diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.web import WebSiteManagementClient

            credential = DefaultAzureCredential()
            web_client = WebSiteManagementClient(credential, self.subscription_id)

            func_app = web_client.web_apps.get(resource_group_name=resource_group, name=function_app_name)
            functions = list(
                web_client.web_apps.list_functions(resource_group_name=resource_group, name=function_app_name)
            )

            return {
                "resource_type": "function",
                "function_app_name": function_app_name,
                "resource_group": resource_group,
                "location": func_app.location,
                "state": func_app.state,
                "enabled": func_app.enabled,
                "default_host_name": func_app.default_host_name,
                "runtime": func_app.site_config.linux_fx_version or func_app.site_config.windows_fx_version
                if func_app.site_config
                else "Unknown",
                "functions": [{"name": f.name} for f in functions[:20]],
                "tags": func_app.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-web azure-identity")
        except Exception as e:
            return {"error": f"Function App collection failed: {str(e)}"}

    async def _collect_sql(self, server_name: str, resource_group: str, database_name: Optional[str] = None) -> dict:
        """Collect Azure SQL diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.sql import SqlManagementClient

            credential = DefaultAzureCredential()
            sql_client = SqlManagementClient(credential, self.subscription_id)

            server = sql_client.servers.get(resource_group_name=resource_group, server_name=server_name)
            databases = list(
                sql_client.databases.list_by_server(resource_group_name=resource_group, server_name=server_name)
            )

            result = {
                "resource_type": "sql",
                "server_name": server_name,
                "resource_group": resource_group,
                "location": server.location,
                "state": server.state,
                "version": server.version,
                "fully_qualified_domain_name": server.fully_qualified_domain_name,
                "databases": [
                    {"name": db.name, "status": db.status, "sku": db.sku.name if db.sku else "Unknown"}
                    for db in databases
                    if db.name != "master"
                ][:10],
                "tags": server.tags or {},
            }

            if database_name:
                db = sql_client.databases.get(
                    resource_group_name=resource_group, server_name=server_name, database_name=database_name
                )
                result["database_details"] = {
                    "name": db.name,
                    "status": db.status,
                    "sku": db.sku.name if db.sku else "Unknown",
                    "max_size_bytes": db.max_size_bytes,
                }

            return result
        except ImportError:
            return self._azure_import_error("azure-mgmt-sql azure-identity")
        except Exception as e:
            return {"error": f"Azure SQL collection failed: {str(e)}"}

    async def _collect_cosmosdb(self, account_name: str, resource_group: str) -> dict:
        """Collect Cosmos DB diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.cosmosdb import CosmosDBManagementClient

            credential = DefaultAzureCredential()
            client = CosmosDBManagementClient(credential, self.subscription_id)

            account = client.database_accounts.get(resource_group_name=resource_group, account_name=account_name)

            return {
                "resource_type": "cosmosdb",
                "account_name": account_name,
                "resource_group": resource_group,
                "location": account.location,
                "provisioning_state": account.provisioning_state,
                "document_endpoint": account.document_endpoint,
                "enable_automatic_failover": account.enable_automatic_failover,
                "tags": account.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-cosmosdb azure-identity")
        except Exception as e:
            return {"error": f"Cosmos DB collection failed: {str(e)}"}

    async def _collect_redis(self, cache_name: str, resource_group: str) -> dict:
        """Collect Azure Cache for Redis diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.redis import RedisManagementClient

            credential = DefaultAzureCredential()
            client = RedisManagementClient(credential, self.subscription_id)

            cache = client.redis.get(resource_group_name=resource_group, name=cache_name)

            return {
                "resource_type": "redis",
                "cache_name": cache_name,
                "resource_group": resource_group,
                "location": cache.location,
                "provisioning_state": cache.provisioning_state,
                "redis_version": cache.redis_version,
                "sku": cache.sku.name if cache.sku else None,
                "capacity": cache.sku.capacity if cache.sku else None,
                "host_name": cache.host_name,
                "port": cache.port,
                "ssl_port": cache.ssl_port,
                "tags": cache.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-redis azure-identity")
        except Exception as e:
            return {"error": f"Redis cache collection failed: {str(e)}"}

    async def _collect_load_balancer(self, lb_name: str, resource_group: str) -> dict:
        """Collect Azure Load Balancer diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient

            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.subscription_id)

            lb = client.load_balancers.get(resource_group_name=resource_group, load_balancer_name=lb_name)

            backend_pools = [
                {"name": pool.name, "backend_count": len(pool.backend_ip_configurations or [])}
                for pool in (lb.backend_address_pools or [])
            ]

            return {
                "resource_type": "load_balancer",
                "name": lb_name,
                "resource_group": resource_group,
                "location": lb.location,
                "provisioning_state": lb.provisioning_state,
                "sku": lb.sku.name if lb.sku else None,
                "frontend_ips": len(lb.frontend_ip_configurations or []),
                "backend_pools": backend_pools,
                "tags": lb.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-network azure-identity")
        except Exception as e:
            return {"error": f"Load balancer collection failed: {str(e)}"}

    async def _collect_application_gateway(self, gateway_name: str, resource_group: str) -> dict:
        """Collect Application Gateway diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient

            credential = DefaultAzureCredential()
            client = NetworkManagementClient(credential, self.subscription_id)

            gw = client.application_gateways.get(resource_group_name=resource_group, application_gateway_name=gateway_name)

            return {
                "resource_type": "application_gateway",
                "name": gateway_name,
                "resource_group": resource_group,
                "location": gw.location,
                "provisioning_state": gw.provisioning_state,
                "operational_state": gw.operational_state,
                "sku": gw.sku.name if gw.sku else None,
                "backend_pool_count": len(gw.backend_address_pools or []),
                "listener_count": len(gw.http_listeners or []),
                "tags": gw.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-network azure-identity")
        except Exception as e:
            return {"error": f"Application Gateway collection failed: {str(e)}"}

    async def _collect_storage(self, storage_account_name: str, resource_group: str) -> dict:
        """Collect Storage Account diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient

            credential = DefaultAzureCredential()
            client = StorageManagementClient(credential, self.subscription_id)

            account = client.storage_accounts.get_properties(
                resource_group_name=resource_group, account_name=storage_account_name
            )

            return {
                "resource_type": "storage",
                "storage_account_name": storage_account_name,
                "resource_group": resource_group,
                "location": account.location,
                "provisioning_state": account.provisioning_state,
                "status_of_primary": account.status_of_primary,
                "kind": account.kind,
                "sku": account.sku.name if account.sku else None,
                "https_only": account.enable_https_traffic_only,
                "tags": account.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-storage azure-identity")
        except Exception as e:
            return {"error": f"Storage account collection failed: {str(e)}"}

    async def _collect_service_bus(self, namespace_name: str, resource_group: str, entity_type: str = "queue") -> dict:
        """Collect Service Bus namespace diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.servicebus import ServiceBusManagementClient

            credential = DefaultAzureCredential()
            client = ServiceBusManagementClient(credential, self.subscription_id)

            namespace = client.namespaces.get(resource_group_name=resource_group, namespace_name=namespace_name)

            return {
                "resource_type": "service_bus",
                "namespace_name": namespace_name,
                "resource_group": resource_group,
                "location": namespace.location,
                "provisioning_state": namespace.provisioning_state,
                "status": namespace.status,
                "sku": namespace.sku.name if namespace.sku else None,
                "tags": namespace.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-servicebus azure-identity")
        except Exception as e:
            return {"error": f"Service Bus collection failed: {str(e)}"}

    async def _collect_batch(self, batch_account_name: str, resource_group: str) -> dict:
        """Collect Azure Batch account diagnostics."""
        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.batch import BatchManagementClient

            credential = DefaultAzureCredential()
            client = BatchManagementClient(credential, self.subscription_id)

            account = client.batch_account.get(resource_group_name=resource_group, account_name=batch_account_name)

            return {
                "resource_type": "batch",
                "account_name": batch_account_name,
                "resource_group": resource_group,
                "location": account.location,
                "provisioning_state": account.provisioning_state,
                "account_endpoint": account.account_endpoint,
                "pool_quota": account.pool_quota,
                "active_job_count": account.active_job_and_job_schedule_quota,
                "tags": account.tags or {},
            }
        except ImportError:
            return self._azure_import_error("azure-mgmt-batch azure-identity")
        except Exception as e:
            return {"error": f"Batch account collection failed: {str(e)}"}

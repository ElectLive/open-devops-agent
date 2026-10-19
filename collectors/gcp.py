"""
GCP Cloud Resource Collector
Fetches diagnostic information from GCP resources.
Supports: GCE VMs, GKE, Cloud Run, Cloud Functions, Cloud SQL, Load Balancers, and more.
Focuses on safe read-only operations.
"""
import os
from typing import Optional, List

import structlog

from collectors.database_policy import check_database_access, filter_supported_types

log = structlog.get_logger()

SUPPORTED_TYPES = [
    "gce", "compute", "gke", "gke_nodepool", "cloud_run", "cloud_function",
    "cloud_sql", "artifact_registry", "cloud_storage", "load_balancer",
    "memorystore", "pubsub", "cloud_composer", "instance_group", "firestore",
]


class GCPCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.project_id = os.getenv("GCP_PROJECT_ID", "")

    def list_supported_types(self) -> List[str]:
        return filter_supported_types(SUPPORTED_TYPES)

    async def collect(self, resource_type: str, resource_id: str, **kwargs) -> dict:
        """
        Collect diagnostic info for GCP resources.

        Args:
            resource_type: See SUPPORTED_TYPES / cloud_registry.GCP_SERVICES
            resource_id: Instance name, cluster name, service name, etc.
        """
        resource_type = resource_type.lower()
        if resource_type == "compute":
            resource_type = "gce"

        blocked = check_database_access(resource_type, cloud="gcp")
        if blocked:
            return blocked

        handlers = {
            "gce": lambda: self._collect_gce(resource_id, kwargs.get("zone")),
            "gke": lambda: self._collect_gke(
                kwargs.get("cluster", resource_id),
                kwargs.get("zone") or kwargs.get("region"),
                kwargs.get("namespace", "default"),
                kwargs.get("pod_name"),
            ),
            "gke_nodepool": lambda: self._collect_gke_nodepool(
                kwargs.get("cluster"), kwargs.get("zone") or kwargs.get("region"), resource_id
            ),
            "cloud_run": lambda: self._collect_cloud_run(resource_id, kwargs.get("region")),
            "cloud_function": lambda: self._collect_cloud_function(resource_id, kwargs.get("region")),
            "cloud_sql": lambda: self._collect_cloud_sql(resource_id),
            "artifact_registry": lambda: self._collect_artifact_registry(resource_id, kwargs.get("location")),
            "cloud_storage": lambda: self._collect_cloud_storage(resource_id),
            "load_balancer": lambda: self._collect_load_balancer(resource_id, kwargs.get("region")),
            "memorystore": lambda: self._collect_memorystore(resource_id, kwargs.get("region")),
            "pubsub": lambda: self._collect_pubsub(resource_id, kwargs.get("subscription")),
            "cloud_composer": lambda: self._collect_cloud_composer(resource_id, kwargs.get("region")),
            "instance_group": lambda: self._collect_instance_group(resource_id, kwargs.get("zone")),
            "firestore": lambda: self._collect_firestore(resource_id),
        }

        try:
            handler = handlers.get(resource_type)
            if not handler:
                return {
                    "error": f"Unsupported GCP resource type: {resource_type}",
                    "supported_types": SUPPORTED_TYPES,
                }
            return await handler()
        except Exception as e:
            log.error("GCP collection failed", resource_type=resource_type, error=str(e))
            return {"error": str(e)}

    async def _collect_gce(self, instance_name: str, zone: str) -> dict:
        """Collect Compute Engine VM diagnostics."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.InstancesClient()
            instance = client.get(project=self.project_id, zone=zone, instance=instance_name)

            try:
                serial_output = client.get_serial_port_output(
                    project=self.project_id, zone=zone, instance=instance_name, port=1
                )
                console_text = (
                    serial_output.contents[-4000:]
                    if len(serial_output.contents) > 4000
                    else serial_output.contents
                )
            except Exception:
                console_text = "Serial port output not available"

            return {
                "resource_type": "gce",
                "instance_name": instance_name,
                "zone": zone,
                "status": instance.status,
                "machine_type": instance.machine_type.split("/")[-1],
                "creation_timestamp": instance.creation_timestamp,
                "network_interfaces": [
                    {
                        "network": ni.network.split("/")[-1],
                        "internal_ip": ni.network_i_p,
                        "external_ip": ni.access_configs[0].nat_i_p if ni.access_configs else None,
                    }
                    for ni in instance.network_interfaces
                ],
                "labels": dict(instance.labels) if instance.labels else {},
                "console_output": console_text,
            }
        except ImportError:
            return {"error": "google-cloud-compute not installed. Run: pip install google-cloud-compute"}
        except Exception as e:
            return {"error": f"GCE collection failed: {str(e)}"}

    async def _collect_gke(
        self, cluster: str, location: str, namespace: str = "default", pod_name: Optional[str] = None
    ) -> dict:
        """Collect GKE cluster diagnostics including node pools and addons."""
        try:
            from google.cloud import container_v1

            client = container_v1.ClusterManagerClient()
            cluster_path = f"projects/{self.project_id}/locations/{location}/clusters/{cluster}"
            cluster_info = client.get_cluster(name=cluster_path)

            node_pools = []
            for pool in cluster_info.node_pools:
                node_pools.append({
                    "name": pool.name,
                    "status": pool.status.name if pool.status else None,
                    "version": pool.version,
                    "machine_type": pool.config.machine_type if pool.config else None,
                    "disk_size_gb": pool.config.disk_size_gb if pool.config else None,
                    "initial_node_count": pool.initial_node_count,
                    "autoscaling": {
                        "enabled": pool.autoscaling.enabled if pool.autoscaling else False,
                        "min": pool.autoscaling.min_node_count if pool.autoscaling else None,
                        "max": pool.autoscaling.max_node_count if pool.autoscaling else None,
                    },
                })

            return {
                "resource_type": "gke",
                "cluster": cluster,
                "location": location,
                "status": cluster_info.status.name,
                "current_master_version": cluster_info.current_master_version,
                "current_node_version": cluster_info.current_node_version,
                "endpoint": cluster_info.endpoint,
                "node_pool_count": len(node_pools),
                "node_pools": node_pools,
                "addons": {
                    "http_load_balancing": cluster_info.addons_config.http_load_balancing.disabled
                    if cluster_info.addons_config and cluster_info.addons_config.http_load_balancing
                    else None,
                    "network_policy": cluster_info.addons_config.network_policy_config.disabled
                    if cluster_info.addons_config and cluster_info.addons_config.network_policy_config
                    else None,
                },
                "autopilot": cluster_info.autopilot.enabled if cluster_info.autopilot else False,
                "pod_name": pod_name,
                "namespace": namespace,
                "note": "Use K8s collector for detailed pod logs and events",
            }
        except ImportError:
            return {"error": "google-cloud-container not installed. Run: pip install google-cloud-container"}
        except Exception as e:
            return {"error": f"GKE collection failed: {str(e)}"}

    async def _collect_gke_nodepool(self, cluster: str, location: str, nodepool_name: str) -> dict:
        """Collect GKE node pool diagnostics."""
        try:
            from google.cloud import container_v1

            client = container_v1.ClusterManagerClient()
            path = f"projects/{self.project_id}/locations/{location}/clusters/{cluster}/nodePools/{nodepool_name}"
            pool = client.get_node_pool(name=path)

            return {
                "resource_type": "gke_nodepool",
                "cluster": cluster,
                "location": location,
                "nodepool_name": nodepool_name,
                "status": pool.status.name if pool.status else None,
                "version": pool.version,
                "machine_type": pool.config.machine_type if pool.config else None,
                "disk_size_gb": pool.config.disk_size_gb if pool.config else None,
                "initial_node_count": pool.initial_node_count,
            }
        except ImportError:
            return {"error": "google-cloud-container not installed"}
        except Exception as e:
            return {"error": f"GKE nodepool collection failed: {str(e)}"}

    async def _collect_cloud_run(self, service_name: str, region: str) -> dict:
        """Collect Cloud Run container service diagnostics."""
        try:
            from google.cloud import run_v2
            from google.cloud import logging as cloud_logging

            client = run_v2.ServicesClient()
            service_path = f"projects/{self.project_id}/locations/{region}/services/{service_name}"
            service = client.get_service(name=service_path)

            logging_client = cloud_logging.Client(project=self.project_id)
            filter_str = (
                f'resource.type="cloud_run_revision" AND '
                f'resource.labels.service_name="{service_name}" AND severity>=ERROR'
            )

            recent_errors = []
            try:
                entries = logging_client.list_entries(filter_=filter_str, page_size=20)
                for entry in entries:
                    recent_errors.append({
                        "timestamp": str(entry.timestamp),
                        "severity": entry.severity,
                        "message": entry.payload[:500] if isinstance(entry.payload, str) else str(entry.payload)[:500],
                    })
            except Exception:
                recent_errors = [{"error": "Unable to fetch logs"}]

            return {
                "resource_type": "cloud_run",
                "service_name": service_name,
                "region": region,
                "uri": service.uri,
                "latest_ready_revision": service.latest_ready_revision,
                "latest_created_revision": service.latest_created_revision,
                "ingress": service.ingress.name if service.ingress else None,
                "labels": dict(service.labels) if service.labels else {},
                "recent_errors": recent_errors[:10],
            }
        except ImportError:
            return {"error": "google-cloud-run or google-cloud-logging not installed"}
        except Exception as e:
            return {"error": f"Cloud Run collection failed: {str(e)}"}

    async def _collect_cloud_function(self, function_name: str, region: str) -> dict:
        """Collect Cloud Function diagnostics."""
        try:
            from google.cloud import functions_v2
            from google.cloud import logging as cloud_logging

            client = functions_v2.FunctionServiceClient()
            function_path = f"projects/{self.project_id}/locations/{region}/functions/{function_name}"
            function = client.get_function(name=function_path)

            logging_client = cloud_logging.Client(project=self.project_id)
            filter_str = (
                f'resource.type="cloud_function" AND '
                f'resource.labels.function_name="{function_name}" AND severity>=ERROR'
            )

            recent_errors = []
            try:
                entries = logging_client.list_entries(filter_=filter_str, page_size=20)
                for entry in entries:
                    recent_errors.append({
                        "timestamp": str(entry.timestamp),
                        "severity": entry.severity,
                        "message": entry.payload[:500] if isinstance(entry.payload, str) else str(entry.payload)[:500],
                    })
            except Exception:
                recent_errors = [{"error": "Unable to fetch logs"}]

            return {
                "resource_type": "cloud_function",
                "function_name": function_name,
                "region": region,
                "state": function.state.name,
                "runtime": function.build_config.runtime,
                "entry_point": function.build_config.entry_point,
                "url": function.service_config.uri if hasattr(function.service_config, "uri") else None,
                "labels": dict(function.labels) if function.labels else {},
                "recent_errors": recent_errors[:10],
            }
        except ImportError:
            return {"error": "google-cloud-functions or google-cloud-logging not installed"}
        except Exception as e:
            return {"error": f"Cloud Function collection failed: {str(e)}"}

    async def _collect_cloud_sql(self, instance_name: str) -> dict:
        """Collect Cloud SQL diagnostics."""
        try:
            from google.cloud.sql_v1 import SqlInstancesServiceClient

            client = SqlInstancesServiceClient()
            instance = client.get(project=self.project_id, instance=instance_name)

            return {
                "resource_type": "cloud_sql",
                "instance_name": instance_name,
                "state": instance.state.name,
                "database_version": instance.database_version.name,
                "region": instance.region,
                "tier": instance.settings.tier,
                "availability_type": instance.settings.availability_type.name,
                "backup_enabled": instance.settings.backup_configuration.enabled
                if instance.settings.backup_configuration
                else False,
                "ip_addresses": [
                    {"type": ip.type_.name, "address": ip.ip_address}
                    for ip in instance.ip_addresses
                ],
            }
        except ImportError:
            return {"error": "google-cloud-sql not installed. Run: pip install google-cloud-sql"}
        except Exception as e:
            return {"error": f"Cloud SQL collection failed: {str(e)}"}

    async def _collect_artifact_registry(self, repository_name: str, location: str) -> dict:
        """Collect Artifact Registry / GCR diagnostics."""
        try:
            from google.cloud import artifactregistry_v1

            client = artifactregistry_v1.ArtifactRegistryClient()
            repo_path = f"projects/{self.project_id}/locations/{location}/repositories/{repository_name}"
            repo = client.get_repository(name=repo_path)

            return {
                "resource_type": "artifact_registry",
                "repository_name": repository_name,
                "location": location,
                "format": repo.format_.name if repo.format_ else None,
                "create_time": str(repo.create_time) if repo.create_time else None,
                "size_bytes": repo.size_bytes if hasattr(repo, "size_bytes") else None,
            }
        except ImportError:
            return {"error": "google-cloud-artifact-registry not installed"}
        except Exception as e:
            return {"error": f"Artifact Registry collection failed: {str(e)}"}

    async def _collect_cloud_storage(self, bucket_name: str) -> dict:
        """Collect Cloud Storage bucket status (read-only)."""
        try:
            from google.cloud import storage

            client = storage.Client(project=self.project_id)
            bucket = client.get_bucket(bucket_name)

            return {
                "resource_type": "cloud_storage",
                "bucket_name": bucket_name,
                "location": bucket.location,
                "storage_class": bucket.storage_class,
                "versioning_enabled": bucket.versioning_enabled,
                "lifecycle_rules": len(bucket.lifecycle_rules) if bucket.lifecycle_rules else 0,
            }
        except ImportError:
            return {"error": "google-cloud-storage not installed. Run: pip install google-cloud-storage"}
        except Exception as e:
            return {"error": f"Cloud Storage collection failed: {str(e)}"}

    async def _collect_load_balancer(self, forwarding_rule_name: str, region: str) -> dict:
        """Collect Cloud Load Balancing diagnostics."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.ForwardingRulesClient()
            if region:
                rule = client.get(project=self.project_id, region=region, forwarding_rule=forwarding_rule_name)
            else:
                rule = client.get(project=self.project_id, forwarding_rule=forwarding_rule_name)

            return {
                "resource_type": "load_balancer",
                "name": forwarding_rule_name,
                "region": region,
                "ip_address": rule.I_p_address if hasattr(rule, "I_p_address") else getattr(rule, "ip_address", None),
                "port_range": rule.port_range,
                "target": rule.target.split("/")[-1] if rule.target else None,
                "load_balancing_scheme": rule.load_balancing_scheme,
            }
        except ImportError:
            return {"error": "google-cloud-compute not installed"}
        except Exception as e:
            return {"error": f"Load balancer collection failed: {str(e)}"}

    async def _collect_memorystore(self, instance_name: str, region: str) -> dict:
        """Collect Memorystore (Redis) diagnostics."""
        try:
            from google.cloud import redis_v1

            client = redis_v1.CloudRedisClient()
            instance_path = f"projects/{self.project_id}/locations/{region}/instances/{instance_name}"
            instance = client.get_instance(name=instance_path)

            return {
                "resource_type": "memorystore",
                "instance_name": instance_name,
                "region": region,
                "state": instance.state.name if instance.state else None,
                "tier": instance.tier.name if instance.tier else None,
                "memory_size_gb": instance.memory_size_gb,
                "host": instance.host,
                "port": instance.port,
                "redis_version": instance.redis_version,
            }
        except ImportError:
            return {"error": "google-cloud-redis not installed. Run: pip install google-cloud-redis"}
        except Exception as e:
            return {"error": f"Memorystore collection failed: {str(e)}"}

    async def _collect_pubsub(self, topic_name: str, subscription: Optional[str] = None) -> dict:
        """Collect Pub/Sub topic and subscription diagnostics."""
        try:
            from google.cloud import pubsub_v1

            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(self.project_id, topic_name)

            result = {"resource_type": "pubsub", "topic_name": topic_name, "topic_path": topic_path}

            if subscription:
                subscriber = pubsub_v1.SubscriberClient()
                sub_path = subscriber.subscription_path(self.project_id, subscription)
                sub_info = subscriber.get_subscription(request={"subscription": sub_path})
                result["subscription"] = {
                    "name": subscription,
                    "ack_deadline_seconds": sub_info.ack_deadline_seconds,
                    "message_retention_duration": str(sub_info.message_retention_duration),
                }

            return result
        except ImportError:
            return {"error": "google-cloud-pubsub not installed. Run: pip install google-cloud-pubsub"}
        except Exception as e:
            return {"error": f"Pub/Sub collection failed: {str(e)}"}

    async def _collect_cloud_composer(self, environment_name: str, region: str) -> dict:
        """Collect Cloud Composer (Airflow) environment diagnostics."""
        try:
            from google.cloud.orchestration.airflow import service_v1

            client = service_v1.EnvironmentsClient()
            env_path = f"projects/{self.project_id}/locations/{region}/environments/{environment_name}"
            env = client.get_environment(name=env_path)

            return {
                "resource_type": "cloud_composer",
                "environment_name": environment_name,
                "region": region,
                "state": env.state.name if env.state else None,
                "airflow_uri": env.config.airflow_uri if env.config else None,
                "node_count": env.config.node_count if env.config else None,
            }
        except ImportError:
            return {"error": "google-cloud-orchestration-airflow not installed"}
        except Exception as e:
            return {"error": f"Cloud Composer collection failed: {str(e)}"}

    async def _collect_instance_group(self, instance_group_name: str, zone: str) -> dict:
        """Collect managed instance group diagnostics."""
        try:
            from google.cloud import compute_v1

            client = compute_v1.InstanceGroupManagersClient()
            group = client.get(project=self.project_id, zone=zone, instance_group_manager=instance_group_name)

            return {
                "resource_type": "instance_group",
                "name": instance_group_name,
                "zone": zone,
                "target_size": group.target_size,
                "current_actions": {
                    "creating": group.current_actions.creating if group.current_actions else 0,
                    "deleting": group.current_actions.deleting if group.current_actions else 0,
                    "recreating": group.current_actions.recreating if group.current_actions else 0,
                },
            }
        except ImportError:
            return {"error": "google-cloud-compute not installed"}
        except Exception as e:
            return {"error": f"Instance group collection failed: {str(e)}"}

    async def _collect_firestore(self, database_name: str) -> dict:
        """Collect Firestore database status."""
        try:
            from google.cloud import firestore_admin_v1

            client = firestore_admin_v1.FirestoreAdminClient()
            db_path = f"projects/{self.project_id}/databases/{database_name}"
            db = client.get_database(name=db_path)

            return {
                "resource_type": "firestore",
                "database_name": database_name,
                "type": db.type_.name if db.type_ else None,
                "location_id": db.location_id,
                "point_in_time_recovery": db.point_in_time_recovery_enablement.name
                if db.point_in_time_recovery_enablement
                else None,
            }
        except ImportError:
            return {"error": "google-cloud-firestore not installed"}
        except Exception as e:
            return {"error": f"Firestore collection failed: {str(e)}"}

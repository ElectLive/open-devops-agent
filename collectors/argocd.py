"""
ArgoCD Collector and Tools
Fetches ArgoCD application status, sync status, and health information.
Can trigger safe sync operations.
"""
import os
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


# SSL verification helper - set ARGOCD_INSECURE_SKIP_VERIFY=true only for self-signed certs
def _get_verify_ssl():
    return os.getenv('ARGOCD_INSECURE_SKIP_VERIFY', 'false').lower() != 'true'


class ArgoCDCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.server_url = os.getenv("ARGOCD_SERVER_URL", "")
        self.auth_token = os.getenv("ARGOCD_AUTH_TOKEN", "")
        self.headers = {
            "Authorization": f"Bearer {self.auth_token}",
            "Content-Type": "application/json",
        } if self.auth_token else {}

    async def collect(self, app_name: str) -> dict:
        """Fetch ArgoCD application status and diagnostics."""
        if not self.server_url:
            return {"error": "ARGOCD_SERVER_URL not configured"}

        async with httpx.AsyncClient(headers=self.headers, timeout=30, verify=_get_verify_ssl()) as client:
            # Get application details
            app_url = f"{self.server_url}/api/v1/applications/{app_name}"
            
            try:
                app_resp = await client.get(app_url)
                if app_resp.status_code != 200:
                    return {"error": f"Could not fetch application: {app_resp.status_code}"}

                app = app_resp.json()
                
                # Extract key information
                status = app.get("status", {})
                spec = app.get("spec", {})
                
                # Get resource details
                resources = status.get("resources", [])
                unhealthy_resources = [
                    r for r in resources
                    if r.get("health", {}).get("status") not in ["Healthy", ""]
                ]
                out_of_sync_resources = [
                    r for r in resources
                    if r.get("status") != "Synced"
                ]
                
                # Get recent operation (sync) status
                operation_state = status.get("operationState", {})
                recent_sync = None
                if operation_state:
                    recent_sync = {
                        "phase": operation_state.get("phase"),
                        "message": operation_state.get("message"),
                        "started_at": operation_state.get("startedAt"),
                        "finished_at": operation_state.get("finishedAt"),
                    }
                
                # Get sync status
                sync_status = status.get("sync", {})
                
                return {
                    "app_name": app_name,
                    "namespace": app.get("metadata", {}).get("namespace"),
                    "server": spec.get("destination", {}).get("server"),
                    "destination_namespace": spec.get("destination", {}).get("namespace"),
                    "repo_url": spec.get("source", {}).get("repoURL"),
                    "path": spec.get("source", {}).get("path"),
                    "target_revision": spec.get("source", {}).get("targetRevision"),
                    "health": {
                        "status": status.get("health", {}).get("status"),
                        "message": status.get("health", {}).get("message"),
                    },
                    "sync": {
                        "status": sync_status.get("status"),
                        "revision": sync_status.get("revision"),
                        "compared_to": {
                            "revision": sync_status.get("comparedTo", {}).get("revision"),
                            "source": sync_status.get("comparedTo", {}).get("source", {}).get("repoURL"),
                        },
                    },
                    "recent_sync_operation": recent_sync,
                    "total_resources": len(resources),
                    "unhealthy_resources": [
                        {
                            "kind": r.get("kind"),
                            "name": r.get("name"),
                            "namespace": r.get("namespace"),
                            "health_status": r.get("health", {}).get("status"),
                            "health_message": r.get("health", {}).get("message"),
                        }
                        for r in unhealthy_resources[:10]
                    ],
                    "out_of_sync_resources": [
                        {
                            "kind": r.get("kind"),
                            "name": r.get("name"),
                            "namespace": r.get("namespace"),
                            "sync_status": r.get("status"),
                        }
                        for r in out_of_sync_resources[:10]
                    ],
                    "conditions": status.get("conditions", []),
                }
            except Exception as e:
                log.error("ArgoCD collection failed", app=app_name, error=str(e))
                return {"error": str(e)}

    async def sync_app(self, app_name: str, prune: bool = False, dry_run: bool = False) -> dict:
        """
        Trigger an ArgoCD sync operation.
        
        Args:
            app_name: Application name
            prune: Whether to prune resources not in git
            dry_run: If true, only preview the sync
        """
        if not self.server_url:
            return {"error": "ARGOCD_SERVER_URL not configured"}

        sync_url = f"{self.server_url}/api/v1/applications/{app_name}/sync"
        
        payload = {
            "prune": prune,
            "dryRun": dry_run,
            "strategy": {
                "hook": {}
            }
        }

        async with httpx.AsyncClient(headers=self.headers, timeout=60, verify=_get_verify_ssl()) as client:
            try:
                sync_resp = await client.post(sync_url, json=payload)
                
                if sync_resp.status_code not in [200, 201]:
                    return {"error": f"Sync failed: {sync_resp.status_code}", "detail": sync_resp.text}

                result = sync_resp.json()
                
                return {
                    "app_name": app_name,
                    "dry_run": dry_run,
                    "sync_triggered": True,
                    "operation": result.get("status", {}).get("operationState", {}),
                    "message": "Sync operation initiated successfully",
                }
            except Exception as e:
                log.error("ArgoCD sync failed", app=app_name, error=str(e))
                return {"error": str(e)}

    async def rollback_app(self, app_name: str, revision: str) -> dict:
        """
        Rollback ArgoCD application to a specific revision.
        
        Args:
            app_name: Application name
            revision: Git commit SHA or tag to rollback to
        """
        if not self.server_url:
            return {"error": "ARGOCD_SERVER_URL not configured"}

        # Update application spec to target the specific revision
        app_url = f"{self.server_url}/api/v1/applications/{app_name}"
        
        async with httpx.AsyncClient(headers=self.headers, timeout=30, verify=_get_verify_ssl()) as client:
            try:
                # First, get current app spec
                app_resp = await client.get(app_url)
                if app_resp.status_code != 200:
                    return {"error": f"Could not fetch application: {app_resp.status_code}"}

                app = app_resp.json()
                
                # Update target revision
                app["spec"]["source"]["targetRevision"] = revision
                
                # Update the application
                update_resp = await client.put(app_url, json=app)
                
                if update_resp.status_code != 200:
                    return {"error": f"Rollback failed: {update_resp.status_code}", "detail": update_resp.text}

                # Trigger sync
                sync_result = await self.sync_app(app_name, prune=False, dry_run=False)
                
                return {
                    "app_name": app_name,
                    "rolled_back_to": revision,
                    "sync_result": sync_result,
                    "message": f"Application rolled back to revision {revision} and sync triggered",
                }
            except Exception as e:
                log.error("ArgoCD rollback failed", app=app_name, error=str(e))
                return {"error": str(e)}

    async def get_app_history(self, app_name: str, limit: int = 10) -> dict:
        """Get deployment history for an ArgoCD application."""
        if not self.server_url:
            return {"error": "ARGOCD_SERVER_URL not configured"}

        app_url = f"{self.server_url}/api/v1/applications/{app_name}"
        
        async with httpx.AsyncClient(headers=self.headers, timeout=30, verify=_get_verify_ssl()) as client:
            try:
                app_resp = await client.get(app_url)
                if app_resp.status_code != 200:
                    return {"error": f"Could not fetch application: {app_resp.status_code}"}

                app = app_resp.json()
                history = app.get("status", {}).get("history", [])
                
                return {
                    "app_name": app_name,
                    "history": [
                        {
                            "id": h.get("id"),
                            "revision": h.get("revision"),
                            "deployed_at": h.get("deployedAt"),
                            "source": h.get("source", {}).get("repoURL"),
                        }
                        for h in history[-limit:]
                    ]
                }
            except Exception as e:
                log.error("ArgoCD history fetch failed", app=app_name, error=str(e))
                return {"error": str(e)}

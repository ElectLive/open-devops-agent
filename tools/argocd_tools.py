"""
ArgoCD Tools
Safe operations for ArgoCD applications.
"""
import os
from typing import Optional

from collectors.argocd import ArgoCDCollector
import structlog

log = structlog.get_logger()


class ArgoCDTools:
    """Tools for ArgoCD application management."""
    
    def __init__(self):
        self.collector = ArgoCDCollector()

    def refresh_credentials(self) -> None:
        self.collector.refresh_credentials()

    async def sync_application(
        self,
        app_name: str,
        prune: bool = False,
        dry_run: bool = True,
        auto_apply: bool = False,
        notifier = None
    ) -> dict:
        """
        Sync an ArgoCD application.
        
        Args:
            app_name: Application name
            prune: Whether to prune resources not in Git
            dry_run: If true, only preview the sync
            auto_apply: If false and not dry_run, require approval
            notifier: Slack notifier for approval requests
        """
        # Safety check: always dry_run first unless explicitly disabled
        if not dry_run and not auto_apply:
            if notifier:
                await notifier.send_message(
                    f"⚠️ ArgoCD sync for `{app_name}` requires approval.\n"
                    f"Prune: {prune}",
                    severity="warning",
                    requires_approval=True,
                    approval_command=f"argocd_sync:{app_name}:{prune}"
                )
            return {
                "blocked": True,
                "requires_approval": True,
                "app_name": app_name,
                "message": "Sync requires approval (AUTO_APPLY=false)",
            }

        result = await self.collector.sync_app(app_name, prune=prune, dry_run=dry_run)
        return result

    async def rollback_application(
        self,
        app_name: str,
        revision: Optional[str] = None,
        auto_apply: bool = False,
        notifier = None
    ) -> dict:
        """
        Rollback an ArgoCD application to a previous revision.
        
        Args:
            app_name: Application name
            revision: Git revision to rollback to (if None, uses previous in history)
            auto_apply: If false, require approval
            notifier: Slack notifier for approval requests
        """
        # Get history if no revision specified
        if not revision:
            history = await self.collector.get_app_history(app_name, limit=5)
            if "error" in history:
                return history
            
            if len(history.get("history", [])) < 2:
                return {"error": "No previous revision found to rollback to"}
            
            # Get the second-to-last revision (current is last)
            revision = history["history"][-2]["revision"]

        if not auto_apply:
            if notifier:
                await notifier.send_message(
                    f"⚠️ ArgoCD rollback for `{app_name}` to revision `{revision[:8]}` requires approval.",
                    severity="warning",
                    requires_approval=True,
                    approval_command=f"argocd_rollback:{app_name}:{revision}"
                )
            return {
                "blocked": True,
                "requires_approval": True,
                "app_name": app_name,
                "target_revision": revision,
                "message": "Rollback requires approval (AUTO_APPLY=false)",
            }

        result = await self.collector.rollback_app(app_name, revision)
        return result

    async def get_application_status(self, app_name: str) -> dict:
        """Get detailed status of an ArgoCD application."""
        return await self.collector.collect(app_name)

    async def get_application_history(self, app_name: str, limit: int = 10) -> dict:
        """Get deployment history for an ArgoCD application."""
        return await self.collector.get_app_history(app_name, limit)

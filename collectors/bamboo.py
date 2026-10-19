"""
Bamboo CI/CD Log Collector
Fetches failed build logs from Bamboo API.
"""
import os
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


class BambooCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.url = os.getenv("BAMBOO_URL", "")
        self.username = os.getenv("BAMBOO_USERNAME", "")
        self.password = os.getenv("BAMBOO_PASSWORD", "")
        self.auth = (self.username, self.password) if self.username and self.password else None

    async def collect(self, plan_key: str, build_number: Optional[int] = None) -> dict:
        """Fetch logs for a failed Bamboo build."""
        if not self.url:
            return {"error": "BAMBOO_URL not configured"}

        # If no build number, use 'latest'
        build_key = f"{plan_key}-{build_number}" if build_number else f"{plan_key}/latest"

        async with httpx.AsyncClient(auth=self.auth, timeout=60) as client:
            # Get build result details
            result_url = f"{self.url}/rest/api/latest/result/{build_key}?expand=stages.stage.results.result,changes,metadata"
            result_resp = await client.get(result_url)
            
            if result_resp.status_code != 200:
                return {"error": f"Could not fetch build result: {result_resp.status_code}"}

            result_data = result_resp.json()

            # Get build logs
            log_url = f"{self.url}/rest/api/latest/result/{build_key}/log"
            log_resp = await client.get(log_url)
            
            build_log = ""
            if log_resp.status_code == 200:
                build_log = log_resp.text
                # Truncate to last 8000 chars
                build_log = build_log[-8000:] if len(build_log) > 8000 else build_log

            result = {
                "plan_key": plan_key,
                "build_number": result_data.get("buildNumber"),
                "build_state": result_data.get("buildState"),
                "build_result": result_data.get("buildResultKey"),
                "life_cycle_state": result_data.get("lifeCycleState"),
                "build_duration": result_data.get("buildDuration"),
                "build_started_time": result_data.get("buildStartedTime"),
                "link": result_data.get("link", {}).get("href"),
                "branch": self._extract_branch(result_data),
                "commit": self._extract_commit(result_data),
                "build_log": build_log,
                "failed_jobs": self._extract_failed_jobs(result_data),
            }

            return result

    def _extract_branch(self, result: dict) -> str:
        """Extract branch name from result."""
        plan_name = result.get("planName", "")
        # Bamboo branch builds usually have branch in plan name
        if " - " in plan_name:
            return plan_name.split(" - ")[-1]
        return result.get("plan", {}).get("shortName", "")

    def _extract_commit(self, result: dict) -> str:
        """Extract commit SHA from changes."""
        changes = result.get("changes", {}).get("change", [])
        if changes and len(changes) > 0:
            change_set_id = changes[0].get("changesetId", "")
            return change_set_id[:8] if change_set_id else ""
        return ""

    def _extract_failed_jobs(self, result: dict) -> list:
        """Extract information about failed jobs."""
        failed_jobs = []
        stages = result.get("stages", {}).get("stage", [])
        
        for stage in stages:
            stage_results = stage.get("results", {}).get("result", [])
            for job_result in stage_results:
                if job_result.get("state") == "Failed":
                    failed_jobs.append({
                        "stage": stage.get("name"),
                        "job": job_result.get("key"),
                        "state": job_result.get("state"),
                        "duration": job_result.get("buildDuration"),
                    })
        
        return failed_jobs

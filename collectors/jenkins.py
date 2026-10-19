"""
Jenkins CI/CD Log Collector
Fetches failed build logs from Jenkins API.
"""
import os
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


class JenkinsCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.url = os.getenv("JENKINS_URL", "")
        self.username = os.getenv("JENKINS_USERNAME", "")
        self.token = os.getenv("JENKINS_API_TOKEN", "")
        self.auth = (self.username, self.token) if self.username and self.token else None

    async def collect(self, job_name: str, build_number: Optional[int] = None) -> dict:
        """Fetch logs for a failed Jenkins build."""
        if not self.url:
            return {"error": "JENKINS_URL not configured"}

        # If no build number, get the latest failed build
        if build_number is None:
            build_number = await self._get_last_failed_build(job_name)
            if not build_number:
                return {"error": "No failed builds found"}

        async with httpx.AsyncClient(auth=self.auth, timeout=60) as client:
            # Get build details
            build_url = f"{self.url}/job/{job_name}/{build_number}/api/json"
            build_resp = await client.get(build_url)
            
            if build_resp.status_code != 200:
                return {"error": f"Could not fetch build: {build_resp.status_code}"}

            build = build_resp.json()

            # Get console logs
            console_url = f"{self.url}/job/{job_name}/{build_number}/consoleText"
            console_resp = await client.get(console_url)
            
            console_text = ""
            if console_resp.status_code == 200:
                console_text = console_resp.text
                # Truncate to last 8000 chars
                console_text = console_text[-8000:] if len(console_text) > 8000 else console_text

            result = {
                "job_name": job_name,
                "build_number": build_number,
                "result": build.get("result"),
                "duration": build.get("duration"),
                "timestamp": build.get("timestamp"),
                "url": build.get("url"),
                "commit": self._extract_commit(build),
                "branch": self._extract_branch(build),
                "console_log": console_text,
                "failed_stages": self._extract_failed_stages(build),
            }

            return result

    async def _get_last_failed_build(self, job_name: str) -> Optional[int]:
        """Get the build number of the last failed build."""
        try:
            async with httpx.AsyncClient(auth=self.auth, timeout=30) as client:
                url = f"{self.url}/job/{job_name}/lastFailedBuild/api/json"
                resp = await client.get(url)
                if resp.status_code == 200:
                    return resp.json().get("number")
        except Exception as e:
            log.warning("Could not fetch last failed build", error=str(e))
        return None

    def _extract_commit(self, build: dict) -> str:
        """Extract commit SHA from build actions."""
        for action in build.get("actions", []):
            if "lastBuiltRevision" in action:
                sha = action["lastBuiltRevision"].get("SHA1", "")
                return sha[:8] if sha else ""
        return ""

    def _extract_branch(self, build: dict) -> str:
        """Extract branch name from build actions."""
        for action in build.get("actions", []):
            if "lastBuiltRevision" in action:
                branches = action["lastBuiltRevision"].get("branch", [])
                if branches:
                    return branches[0].get("name", "").replace("origin/", "")
        return ""

    def _extract_failed_stages(self, build: dict) -> list:
        """Extract information about failed stages/steps."""
        failed_stages = []
        for action in build.get("actions", []):
            if action.get("_class") == "org.jenkinsci.plugins.workflow.job.views.FlowGraphAction":
                # Try to extract stage information if available
                nodes = action.get("nodes", [])
                for node in nodes:
                    if node.get("status") in ["FAILED", "UNSTABLE"]:
                        failed_stages.append({
                            "name": node.get("displayName"),
                            "status": node.get("status"),
                            "duration": node.get("durationMillis"),
                        })
        return failed_stages

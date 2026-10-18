"""
Azure DevOps CI/CD Log Collector
Fetches failed pipeline logs from Azure DevOps API.
"""
import os
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


class AzureDevOpsCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.org = os.getenv("AZURE_DEVOPS_ORG", "")
        self.pat = os.getenv("AZURE_DEVOPS_PAT", "")
        self.headers = {
            "Authorization": f"Basic {self._encode_pat()}",
            "Content-Type": "application/json",
        } if self.pat else {}

    def _encode_pat(self) -> str:
        """Encode PAT for Basic Auth (Azure DevOps uses :{PAT} format)."""
        import base64
        auth_string = f":{self.pat}"
        return base64.b64encode(auth_string.encode()).decode()

    async def collect(self, project: str, pipeline_id: int, run_id: int) -> dict:
        """Fetch logs for a failed Azure DevOps pipeline run."""
        if not self.org or not self.pat:
            return {"error": "AZURE_DEVOPS_ORG and AZURE_DEVOPS_PAT must be configured"}

        base_url = f"https://dev.azure.com/{self.org}/{project}/_apis"

        async with httpx.AsyncClient(headers=self.headers, timeout=60) as client:
            # Get pipeline run details
            run_url = f"{base_url}/pipelines/{pipeline_id}/runs/{run_id}?api-version=7.0"
            run_resp = await client.get(run_url)
            
            if run_resp.status_code != 200:
                return {"error": f"Could not fetch pipeline run: {run_resp.status_code}"}

            run_data = run_resp.json()

            # Get build/timeline for the run to find failed tasks
            build_id = run_data.get("id")
            timeline_url = f"https://dev.azure.com/{self.org}/{project}/_apis/build/builds/{build_id}/timeline?api-version=7.0"
            timeline_resp = await client.get(timeline_url)
            
            failed_tasks = []
            if timeline_resp.status_code == 200:
                timeline = timeline_resp.json()
                records = timeline.get("records", [])
                
                for record in records:
                    if record.get("result") in ["failed", "Failed"]:
                        task_info = {
                            "name": record.get("name"),
                            "type": record.get("type"),
                            "result": record.get("result"),
                            "state": record.get("state"),
                            "issues": record.get("issues", []),
                        }
                        
                        # Get task logs if available
                        if record.get("log", {}).get("id"):
                            log_id = record["log"]["id"]
                            log_url = f"https://dev.azure.com/{self.org}/{project}/_apis/build/builds/{build_id}/logs/{log_id}?api-version=7.0"
                            log_resp = await client.get(log_url)
                            
                            if log_resp.status_code == 200:
                                log_text = log_resp.text
                                # Truncate to last 5000 chars per task
                                task_info["logs"] = log_text[-5000:] if len(log_text) > 5000 else log_text
                        
                        failed_tasks.append(task_info)

            result = {
                "project": project,
                "pipeline_id": pipeline_id,
                "run_id": run_id,
                "state": run_data.get("state"),
                "result": run_data.get("result"),
                "pipeline_name": run_data.get("pipeline", {}).get("name"),
                "created_date": run_data.get("createdDate"),
                "finished_date": run_data.get("finishedDate"),
                "url": run_data.get("url"),
                "web_url": run_data.get("_links", {}).get("web", {}).get("href"),
                "source_branch": run_data.get("resources", {}).get("repositories", {}).get("self", {}).get("refName", ""),
                "failed_tasks": failed_tasks,
            }

            return result

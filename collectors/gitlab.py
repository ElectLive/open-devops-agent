"""
GitLab CI/CD Log Collector
Fetches failed pipeline/job logs from GitLab API.
"""
import os
from typing import Optional

import httpx
import structlog

log = structlog.get_logger()


class GitLabCollector:
    def __init__(self):
        self.refresh_credentials()

    def refresh_credentials(self) -> None:
        self.token = os.getenv("GITLAB_TOKEN", "")
        self.base_url = os.getenv("GITLAB_URL", "https://gitlab.com")
        self.headers = {
            "PRIVATE-TOKEN": self.token,
            "Content-Type": "application/json",
        }

    async def collect(self, project_id: str, pipeline_id: int) -> dict:
        """Fetch full logs for a failed pipeline."""
        async with httpx.AsyncClient(headers=self.headers, timeout=30) as client:
            # Get pipeline details
            pipeline_url = f"{self.base_url}/api/v4/projects/{project_id}/pipelines/{pipeline_id}"
            pipeline_resp = await client.get(pipeline_url)
            
            if pipeline_resp.status_code != 200:
                return {"error": f"Could not fetch pipeline: {pipeline_resp.status_code}"}

            pipeline = pipeline_resp.json()

            # Get jobs for this pipeline
            jobs_url = f"{self.base_url}/api/v4/projects/{project_id}/pipelines/{pipeline_id}/jobs"
            jobs_resp = await client.get(jobs_url)
            
            if jobs_resp.status_code != 200:
                return {"error": f"Could not fetch jobs: {jobs_resp.status_code}"}

            jobs = jobs_resp.json()
            failed_jobs = [j for j in jobs if j.get("status") == "failed"]

            result = {
                "pipeline_id": pipeline_id,
                "project_id": project_id,
                "status": pipeline.get("status"),
                "ref": pipeline.get("ref"),
                "commit": pipeline.get("sha", "")[:8],
                "web_url": pipeline.get("web_url"),
                "failed_jobs": [],
            }

            # Fetch logs for each failed job (limit to 3)
            for job in failed_jobs[:3]:
                job_info = {
                    "id": job["id"],
                    "name": job["name"],
                    "stage": job.get("stage"),
                    "status": job.get("status"),
                    "web_url": job.get("web_url"),
                }

                # Get job trace (logs)
                try:
                    trace_url = f"{self.base_url}/api/v4/projects/{project_id}/jobs/{job['id']}/trace"
                    trace_resp = await client.get(trace_url)
                    
                    if trace_resp.status_code == 200:
                        log_text = trace_resp.text
                        # Truncate to last 6000 chars to focus on the error
                        job_info["logs"] = log_text[-6000:] if len(log_text) > 6000 else log_text
                    else:
                        job_info["logs_error"] = f"Status {trace_resp.status_code}"
                except Exception as e:
                    job_info["logs_error"] = str(e)

                result["failed_jobs"].append(job_info)

            return result

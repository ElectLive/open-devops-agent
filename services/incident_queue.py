"""
Durable incident queue backed by cloud storage.
Survives process restarts — pending incidents are re-processed on startup.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import structlog

from storage.base import StorageProvider
from storage.factory import get_storage

log = structlog.get_logger()

QUEUE_PENDING = "pending"
QUEUE_PROCESSING = "processing"
QUEUE_COMPLETED = "completed"
QUEUE_FAILED = "failed"


class IncidentQueue:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()

    def enqueue(self, org_id: str, context: dict, incident_id: Optional[str] = None) -> str:
        incident_id = incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
        entry = {
            "incident_id": incident_id,
            "org_id": org_id,
            "context": context,
            "status": QUEUE_PENDING,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attempts": 0,
        }
        review_key = None
        identity = [
            org_id,
            context.get("scm_platform"),
            context.get("repo"),
            context.get("change_id"),
            context.get("head_sha"),
        ]
        if context.get("type") == "code_review" and all(identity):
            digest = hashlib.sha256(
                json.dumps(identity, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            # Keep the head reservation when the incident moves between queue states.
            review_key = self.storage.org_prefix(org_id, "review_heads", f"{digest}.json")
            if not self.storage.put_json_if_absent(review_key, {"incident_id": incident_id}):
                existing = self.storage.get_json(review_key)
                log.info(
                    "Review head already queued",
                    incident_id=existing["incident_id"],
                    org_id=org_id,
                )
                return existing["incident_id"]
        key = self.storage.queue_key(org_id, QUEUE_PENDING, incident_id)
        try:
            self.storage.put_json(key, entry)
        except Exception:
            if review_key:
                self.storage.delete(review_key)
            raise
        log.info("Incident enqueued", incident_id=incident_id, org_id=org_id)
        return incident_id

    def claim_next(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Claim one pending incident. A second caller cannot receive the same id."""
        prefix = self.storage.org_prefix(org_id, "queue", QUEUE_PENDING)
        for key in self.storage.list_keys(prefix):
            entry = self.storage.get_json(key)
            if not entry:
                continue

            incident_id = entry["incident_id"]
            entry["status"] = QUEUE_PROCESSING
            entry["claimed_at"] = datetime.now(timezone.utc).isoformat()
            entry["attempts"] = entry.get("attempts", 0) + 1

            proc_key = self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id)
            if not self.storage.put_json_if_absent(proc_key, entry):
                continue
            if not self.storage.delete(key):
                self.storage.delete(proc_key)
                continue
            return entry
        return None

    def recover_stale_processing(self, org_id: str) -> int:
        """Move processing items back to pending (e.g. after crash mid-run)."""
        prefix = self.storage.org_prefix(org_id, "queue", QUEUE_PROCESSING)
        recovered = 0
        for key in self.storage.list_keys(prefix):
            entry = self.storage.get_json(key)
            if not entry:
                continue
            incident_id = entry["incident_id"]
            entry["status"] = QUEUE_PENDING
            entry["recovered_at"] = datetime.now(timezone.utc).isoformat()
            pending_key = self.storage.queue_key(org_id, QUEUE_PENDING, incident_id)
            self.storage.put_json(pending_key, entry)
            self.storage.delete(key)
            recovered += 1
            log.warning("Recovered stale incident", incident_id=incident_id, org_id=org_id)
        return recovered

    def mark_completed(self, org_id: str, incident_id: str, result: dict):
        entry = self._get_processing(org_id, incident_id) or {"incident_id": incident_id, "org_id": org_id}
        entry["status"] = QUEUE_COMPLETED
        entry["completed_at"] = datetime.now(timezone.utc).isoformat()
        entry["result_summary"] = {
            "resolved": result.get("resolved"),
            "steps": result.get("steps"),
        }
        key = self.storage.queue_key(org_id, QUEUE_COMPLETED, incident_id)
        self.storage.put_json(key, entry)
        self._delete_processing(org_id, incident_id)

    def mark_failed(self, org_id: str, incident_id: str, error: str):
        entry = self._get_processing(org_id, incident_id) or {"incident_id": incident_id, "org_id": org_id}
        entry["status"] = QUEUE_FAILED
        entry["failed_at"] = datetime.now(timezone.utc).isoformat()
        entry["error"] = error
        key = self.storage.queue_key(org_id, QUEUE_FAILED, incident_id)
        self.storage.put_json(key, entry)
        self._delete_processing(org_id, incident_id)

    def list_pending_org_ids(self) -> List[str]:
        """Orgs to poll: env config plus any org with pending/processing queue items."""
        orgs = set()
        org_id = os.getenv("ORG_ID", "default")
        orgs.add(org_id)
        extra = os.getenv("ORG_IDS", "")
        for o in extra.split(","):
            o = o.strip()
            if o:
                orgs.add(o)

        # Discover orgs from queue keys (e.g. webhook X-Org-ID differs from ORG_ID)
        for key in self.storage.list_keys(""):
            parts = key.split("/")
            if len(parts) >= 4 and parts[1] == "queue" and parts[2] in (QUEUE_PENDING, QUEUE_PROCESSING):
                orgs.add(parts[0])

        return list(orgs)

    def _get_processing(self, org_id: str, incident_id: str) -> Optional[dict]:
        return self.storage.get_json(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))

    def _delete_processing(self, org_id: str, incident_id: str):
        self.storage.delete(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))

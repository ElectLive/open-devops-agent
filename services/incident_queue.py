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
QUEUE_REVIEWS = "reviews"


class IncidentQueue:
    def __init__(self, storage: Optional[StorageProvider] = None):
        self.storage = storage or get_storage()

    def enqueue(self, org_id: str, context: dict, incident_id: Optional[str] = None) -> str:
        identity = [
            org_id,
            context.get("scm_platform"),
            context.get("repo"),
            context.get("change_id"),
            context.get("head_sha"),
        ]
        is_review = context.get("type") == "code_review" and all(identity)
        if is_review:
            digest = hashlib.sha256(
                json.dumps(identity, separators=(",", ":")).encode("utf-8")
            ).hexdigest()
            incident_id = f"INC-review-{digest}"
        else:
            incident_id = incident_id or f"INC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}-{uuid4().hex[:6]}"
        entry = {
            "incident_id": incident_id,
            "org_id": org_id,
            "context": context,
            "status": QUEUE_PENDING,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "attempts": 0,
        }
        if is_review:
            # This durable queue entry is also the dedupe record, in every state.
            key = self.storage.queue_key(org_id, QUEUE_REVIEWS, incident_id)
            try:
                created = self.storage.put_json_if_absent(key, entry)
            except Exception:
                # Resolve an ambiguous write only by confirming real queued work.
                if not self.storage.exists(key):
                    raise
                created = False
            if not created:
                log.info("Review head already queued", incident_id=incident_id, org_id=org_id)
                return incident_id
        else:
            key = self.storage.queue_key(org_id, QUEUE_PENDING, incident_id)
            self.storage.put_json(key, entry)
        log.info("Incident enqueued", incident_id=incident_id, org_id=org_id)
        return incident_id

    def claim_next(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Claim one pending incident. A second caller cannot receive the same id."""
        prefix = self.storage.org_prefix(org_id, "queue", QUEUE_PENDING)
        review_prefix = self.storage.org_prefix(org_id, "queue", QUEUE_REVIEWS)
        for key in self.storage.list_keys(prefix) + self.storage.list_keys(review_prefix):
            entry = self.storage.get_json(key)
            if not entry or entry.get("status") != QUEUE_PENDING:
                continue

            incident_id = entry["incident_id"]
            entry["status"] = QUEUE_PROCESSING
            entry["claimed_at"] = datetime.now(timezone.utc).isoformat()
            entry["attempts"] = entry.get("attempts", 0) + 1

            is_review = key.startswith(review_prefix + "/")
            proc_key = (
                self._review_claim_key(org_id, incident_id)
                if is_review
                else self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id)
            )
            if not self.storage.put_json_if_absent(proc_key, entry):
                continue
            if is_review:
                self.storage.put_json(key, entry)
                return entry
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
        review_prefix = self.storage.org_prefix(org_id, "queue", QUEUE_REVIEWS)
        for key in self.storage.list_keys(review_prefix):
            entry = self.storage.get_json(key)
            if not entry or entry.get("status") not in (QUEUE_PENDING, QUEUE_PROCESSING):
                continue
            claim_key = self._review_claim_key(org_id, entry["incident_id"])
            claim = self.storage.get_json(claim_key)
            if not claim or claim.get("status") != QUEUE_PROCESSING:
                continue
            # The claim can survive a stop before the queue's status update.
            entry = claim
            entry["status"] = QUEUE_PENDING
            entry["recovered_at"] = datetime.now(timezone.utc).isoformat()
            self.storage.put_json(key, entry)
            self.storage.delete(claim_key)
            recovered += 1
            log.warning("Recovered stale incident", incident_id=entry["incident_id"], org_id=org_id)
        return recovered

    def mark_completed(self, org_id: str, incident_id: str, result: dict):
        entry = self._get_processing(org_id, incident_id) or {"incident_id": incident_id, "org_id": org_id}
        entry["status"] = QUEUE_COMPLETED
        entry["completed_at"] = datetime.now(timezone.utc).isoformat()
        entry["result_summary"] = {
            "resolved": result.get("resolved"),
            "steps": result.get("steps"),
        }
        key = self._state_key(org_id, QUEUE_COMPLETED, incident_id)
        self.storage.put_json(key, entry)
        self._delete_processing(org_id, incident_id)

    def mark_failed(self, org_id: str, incident_id: str, error: str):
        entry = self._get_processing(org_id, incident_id) or {"incident_id": incident_id, "org_id": org_id}
        entry["status"] = QUEUE_FAILED
        entry["failed_at"] = datetime.now(timezone.utc).isoformat()
        entry["error"] = error
        key = self._state_key(org_id, QUEUE_FAILED, incident_id)
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
            elif len(parts) >= 4 and parts[1:3] == ["queue", QUEUE_REVIEWS]:
                entry = self.storage.get_json(key)
                if entry and entry.get("status") in (QUEUE_PENDING, QUEUE_PROCESSING):
                    orgs.add(parts[0])

        return list(orgs)

    def _get_processing(self, org_id: str, incident_id: str) -> Optional[dict]:
        entry = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))
        if entry:
            return entry
        entry = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_REVIEWS, incident_id))
        return entry if entry and entry.get("status") == QUEUE_PROCESSING else None

    def _state_key(self, org_id: str, status: str, incident_id: str) -> str:
        review_key = self.storage.queue_key(org_id, QUEUE_REVIEWS, incident_id)
        return (
            review_key
            if self.storage.exists(review_key)
            else self.storage.queue_key(org_id, status, incident_id)
        )

    def _review_claim_key(self, org_id: str, incident_id: str) -> str:
        return self.storage.org_prefix(org_id, "review_claims", f"{incident_id}.json")

    def _delete_processing(self, org_id: str, incident_id: str):
        self.storage.delete(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))

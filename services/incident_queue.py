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
            review_id = f"INC-review-{digest}"
            incident_id = f"{review_id}-{uuid4().hex}"
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
            key = self.storage.review_dedupe_key(org_id, review_id)
            legacy_key = self.storage.queue_key(org_id, QUEUE_REVIEWS, review_id)
            legacy = self.storage.get_json(legacy_key)
            if legacy:
                if legacy.get("status") not in (QUEUE_COMPLETED, QUEUE_FAILED):
                    legacy["review_key"] = legacy_key
                    self.storage.put_json_if_absent(
                        self.storage.queue_key(org_id, QUEUE_PENDING, legacy["incident_id"]), legacy
                    )
                return legacy["incident_id"]
            winner = self.storage.get_json(key)
            if not winner:
                entry["review_key"] = key
                try:
                    # Resolve the head before publishing work; workers never recreate it.
                    self.storage.put_json_if_absent(key, entry)
                except Exception:
                    if self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, incident_id)):
                        return incident_id
                    if not self.storage.get_json(key):
                        raise
                winner = self.storage.get_json(key)
                if not winner:
                    if self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, incident_id)):
                        return incident_id
                    raise RuntimeError("Review admission changed; retry delivery")
            incident_id = winner["incident_id"]
            if winner.get("status") in (QUEUE_PROCESSING, QUEUE_COMPLETED, QUEUE_FAILED):
                return incident_id
            winner["review_key"] = key
            pending_key = self.storage.queue_key(org_id, QUEUE_PENDING, incident_id)
            try:
                # A marker alone is a reservation: retries must finish publication.
                self.storage.put_json_if_absent(pending_key, winner)
            except Exception:
                failed = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, incident_id))
                claim = self.storage.get_json(self.storage.review_claim_key(org_id, incident_id))
                if not failed and not claim and not self.storage.exists(pending_key):
                    raise
            current = self.storage.get_json(key)
            if not current or current["incident_id"] != incident_id:
                # A delayed index write must not resurrect a released attempt.
                self.storage.delete(pending_key)
                if not self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, incident_id)):
                    raise RuntimeError("Review admission changed; retry delivery")
            elif current.get("status") == QUEUE_COMPLETED:
                self.storage.delete(pending_key)
        else:
            key = self.storage.queue_key(org_id, QUEUE_PENDING, incident_id)
            self.storage.put_json(key, entry)
        log.info("Incident enqueued", incident_id=incident_id, org_id=org_id)
        return incident_id

    def claim_next(self, org_id: str) -> Optional[Dict[str, Any]]:
        """Claim one pending incident. A second caller cannot receive the same id."""
        prefix = self.storage.org_prefix(org_id, "queue", QUEUE_PENDING)
        for key in self.storage.list_keys(prefix):
            entry = self.storage.get_json(key)
            if not entry:
                continue
            review_key = entry.get("review_key")
            if review_key:
                failed = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, entry["incident_id"]))
                if failed:
                    continue
                canonical = self.storage.get_json(review_key)
                if not canonical or canonical["incident_id"] != entry["incident_id"]:
                    self.storage.delete(key)
                    continue
                entry = canonical
                entry["review_key"] = review_key
                if entry.get("status") in (QUEUE_COMPLETED, QUEUE_FAILED):
                    self.storage.delete(key)
                    continue
            if entry.get("status") != QUEUE_PENDING:
                continue

            incident_id = entry["incident_id"]
            entry["status"] = QUEUE_PROCESSING
            entry["claimed_at"] = datetime.now(timezone.utc).isoformat()
            entry["attempts"] = entry.get("attempts", 0) + 1
            proc_key = (
                self.storage.review_claim_key(org_id, incident_id)
                if review_key
                else self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id)
            )
            if review_key and not self.storage.exists(key):
                continue
            if not self.storage.put_json_if_absent(proc_key, entry):
                continue
            if review_key:
                # The head may belong to a later attempt by this point.
                current = self.storage.get_json(review_key)
                if not current or current["incident_id"] != incident_id or current.get("status") != QUEUE_PENDING:
                    continue
                self.storage.put_json(review_key, entry)
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
        pending_prefix = self.storage.org_prefix(org_id, "queue", QUEUE_PENDING)
        for key in self.storage.list_keys(pending_prefix):
            index = self.storage.get_json(key)
            if not index or not index.get("review_key"):
                continue
            review_key = index["review_key"]
            failed = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, index["incident_id"]))
            if failed:
                self.mark_failed(org_id, index["incident_id"], failed.get("error", "Review failed"))
                continue
            entry = self.storage.get_json(review_key)
            if not entry:
                continue  # A failed publication is resumed by webhook redelivery.
            if entry["incident_id"] != index["incident_id"]:
                self.storage.delete(key)
                continue
            entry["review_key"] = review_key
            failed = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, entry["incident_id"]))
            if failed or entry.get("status") == QUEUE_FAILED:
                self.mark_failed(org_id, entry["incident_id"], (failed or entry).get("error", "Review failed"))
                continue
            if entry.get("status") == QUEUE_COMPLETED:
                self._finish_review(org_id, entry)
                continue
            claim_key = self.storage.review_claim_key(org_id, entry["incident_id"])
            claim = self.storage.get_json(claim_key)
            if not claim or claim.get("status") != QUEUE_PROCESSING:
                continue
            current = self.storage.get_json(review_key)
            if not current or current["incident_id"] != entry["incident_id"] or current.get("status") in (QUEUE_COMPLETED, QUEUE_FAILED):
                continue
            # The worker serializes recovery and incident processing.
            entry = claim
            entry["status"] = QUEUE_PENDING
            entry["recovered_at"] = datetime.now(timezone.utc).isoformat()
            self.storage.put_json(review_key, entry)
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
        if entry.get("review_key"):
            current = self.storage.get_json(entry["review_key"])
            if current and current["incident_id"] == incident_id:
                self.storage.put_json(entry["review_key"], entry)
            self._finish_review(org_id, entry)
        else:
            self.storage.put_json(self.storage.queue_key(org_id, QUEUE_COMPLETED, incident_id), entry)
            self._delete_processing(org_id, incident_id)

    def mark_failed(self, org_id: str, incident_id: str, error: str):
        entry = self._get_processing(org_id, incident_id) or {"incident_id": incident_id, "org_id": org_id}
        if entry.get("status") != QUEUE_FAILED:
            entry["status"] = QUEUE_FAILED
            entry["failed_at"] = datetime.now(timezone.utc).isoformat()
            entry["error"] = error
        # Persist failure before releasing any review reservation.
        key = self.storage.queue_key(org_id, QUEUE_FAILED, incident_id)
        self.storage.put_json(key, entry)
        if entry.get("review_key"):
            current = self.storage.get_json(entry["review_key"])
            if current and current["incident_id"] == incident_id:
                self.storage.put_json(entry["review_key"], entry)
            self._finish_review(org_id, entry)
        else:
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
        entry = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))
        if entry:
            return entry
        # Terminal failure context belongs to an attempt, even after marker release.
        failed = self.storage.get_json(self.storage.queue_key(org_id, QUEUE_FAILED, incident_id))
        if failed and failed.get("review_key"):
            return failed
        entry = self.storage.get_json(self.storage.review_claim_key(org_id, incident_id))
        if entry:
            entry.setdefault("review_key", self.storage.queue_key(org_id, QUEUE_REVIEWS, incident_id))
            return entry
        legacy_key = self.storage.queue_key(org_id, QUEUE_REVIEWS, incident_id)
        entry = self.storage.get_json(legacy_key)
        if entry:
            entry["review_key"] = legacy_key
        return entry

    def _finish_review(self, org_id: str, entry: dict):
        # Persist terminal evidence before removing the active index.
        incident_id = entry["incident_id"]
        self.storage.put_json(self.storage.review_claim_key(org_id, incident_id), entry)
        if entry["status"] == QUEUE_FAILED:
            self.storage.delete(self.storage.review_claim_key(org_id, incident_id))
            current = self.storage.get_json(entry["review_key"])
            if current and current["incident_id"] == incident_id:
                # Release only after failure persists; failed deletion stays deduped.
                self.storage.delete(entry["review_key"])
        self.storage.delete(self.storage.queue_key(org_id, QUEUE_PENDING, incident_id))

    def _delete_processing(self, org_id: str, incident_id: str):
        self.storage.delete(self.storage.queue_key(org_id, QUEUE_PROCESSING, incident_id))

"""Abstract storage interface — org-scoped paths on any cloud backend."""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, BinaryIO, List, Optional, Union


class StorageProvider(ABC):
    """Org-scoped object storage. All paths are relative to the bucket/container."""

    @abstractmethod
    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        """Store raw bytes. Returns the storage key."""

    @abstractmethod
    def put_json(self, key: str, data: Any) -> str:
        """Store JSON-serializable data."""

    def put_json_if_absent(self, key: str, data: Any) -> bool:
        """Return True when this caller creates a previously missing JSON key.

        Subclasses must override this fallback with an atomic conditional create
        for concurrent claims; this check-then-write implementation is not atomic.
        """
        if self.exists(key):
            return False
        self.put_json(key, data)
        return True

    @abstractmethod
    def get_bytes(self, key: str) -> Optional[bytes]:
        """Fetch raw bytes or None if missing."""

    @abstractmethod
    def get_json(self, key: str) -> Optional[Any]:
        """Fetch and parse JSON or None if missing."""

    @abstractmethod
    def list_keys(self, prefix: str) -> List[str]:
        """List object keys under a prefix."""

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete an object. Returns True if deleted."""

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if an object exists."""

    # ─── Org-scoped path helpers ─────────────────────────────────────────────

    def org_prefix(self, org_id: str, *parts: str) -> str:
        safe_org = _safe_path_segment(org_id)
        segments = [safe_org] + [_safe_path_segment(p) for p in parts if p]
        return "/".join(segments)

    def audit_key(self, org_id: str, incident_id: str) -> str:
        now = datetime.now(timezone.utc)
        return self.org_prefix(
            org_id, "audit", str(now.year), f"{now.month:02d}", f"{incident_id}.json"
        )

    def log_key(self, org_id: str, incident_id: str, filename: str) -> str:
        now = datetime.now(timezone.utc)
        return self.org_prefix(
            org_id, "logs", str(now.year), f"{now.month:02d}", incident_id, filename
        )

    def checkpoint_key(self, org_id: str, incident_id: str) -> str:
        return self.org_prefix(org_id, "checkpoints", f"{incident_id}.json")

    def queue_key(self, org_id: str, status: str, incident_id: str) -> str:
        return self.org_prefix(org_id, "queue", status, f"{incident_id}.json")

    def review_dedupe_key(self, org_id: str, incident_id: str) -> str:
        return self.org_prefix(org_id, "review_dedupe", f"{incident_id}.json")

    def review_slot_key(self, org_id: str, review_id: str, sequence: int) -> str:
        return self.org_prefix(org_id, "review_heads", review_id, f"{sequence:020d}.json")

    def review_release_key(self, org_id: str, incident_id: str) -> str:
        return self.org_prefix(org_id, "review_releases", f"{incident_id}.json")

    def review_claim_key(self, org_id: str, incident_id: str) -> str:
        return self.org_prefix(org_id, "review_claims", f"{incident_id}.json")

    def doc_key(self, org_id: str, doc_path: str) -> str:
        safe_path = "/".join(_safe_path_segment(p) for p in doc_path.split("/") if p)
        return self.org_prefix(org_id, "docs", safe_path)

    def put_json_org(self, org_id: str, category: str, incident_id: str, filename: str, data: Any) -> str:
        key = self.org_prefix(org_id, category, incident_id, filename)
        return self.put_json(key, data)


def _safe_path_segment(value: str) -> str:
    """Prevent path traversal in org/doc segments."""
    cleaned = (value or "default").strip().replace("..", "").replace("\\", "/")
    return cleaned or "default"

"""In-memory storage for local dev and tests."""
from __future__ import annotations

import json
import threading
from typing import Any, Dict, List, Optional

from storage.base import StorageProvider


class MemoryStorage(StorageProvider):
    """Dict-backed storage — survives within process, not across restarts."""

    def __init__(self):
        self._objects: Dict[str, bytes] = {}
        self._lock = threading.Lock()

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        self._objects[key] = data
        return key

    def put_json(self, key: str, data: Any) -> str:
        return self.put_bytes(key, json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json")

    def get_bytes(self, key: str) -> Optional[bytes]:
        return self._objects.get(key)

    def get_json(self, key: str) -> Optional[Any]:
        raw = self.get_bytes(key)
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    def list_keys(self, prefix: str) -> List[str]:
        return sorted(k for k in self._objects if k.startswith(prefix))

    def put_json_if_absent(self, key: str, data: Any) -> bool:
        payload = json.dumps(data, indent=2, default=str).encode("utf-8")
        with self._lock:
            if key in self._objects:
                return False
            self._objects[key] = payload
            return True

    def delete(self, key: str) -> bool:
        with self._lock:
            if key in self._objects:
                del self._objects[key]
                return True
            return False

    def exists(self, key: str) -> bool:
        return key in self._objects

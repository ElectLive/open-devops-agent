"""Google Cloud Storage backend."""
from __future__ import annotations

import json
import os
from typing import Any, List, Optional

from storage.base import StorageProvider


class GCSStorage(StorageProvider):
    def __init__(self, bucket: str, project: Optional[str] = None):
        from google.cloud import storage

        self.bucket_name = bucket
        project_id = project or os.getenv("GCP_PROJECT_ID")
        self._client = storage.Client(project=project_id)
        self._bucket = self._client.bucket(bucket)

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        blob = self._bucket.blob(key)
        blob.upload_from_string(data, content_type=content_type)
        return key

    def put_json(self, key: str, data: Any) -> str:
        return self.put_bytes(key, json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json")

    def put_json_if_absent(self, key: str, data: Any) -> bool:
        from google.api_core.exceptions import PreconditionFailed

        blob = self._bucket.blob(key)
        body = json.dumps(data, indent=2, default=str)
        try:
            blob.upload_from_string(body, content_type="application/json", if_generation_match=0)
            return True
        except PreconditionFailed:
            return False

    def get_bytes(self, key: str) -> Optional[bytes]:
        blob = self._bucket.blob(key)
        if not blob.exists():
            return None
        return blob.download_as_bytes()

    def get_json(self, key: str) -> Optional[Any]:
        raw = self.get_bytes(key)
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    def list_keys(self, prefix: str) -> List[str]:
        return sorted(blob.name for blob in self._client.list_blobs(self.bucket_name, prefix=prefix))

    def delete(self, key: str) -> bool:
        blob = self._bucket.blob(key)
        if not blob.exists():
            return False
        blob.delete()
        return True

    def exists(self, key: str) -> bool:
        return self._bucket.blob(key).exists()

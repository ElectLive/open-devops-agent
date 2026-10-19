"""Azure Blob Storage backend."""
from __future__ import annotations

import json
import os
from typing import Any, List, Optional

from storage.base import StorageProvider


class AzureBlobStorage(StorageProvider):
    def __init__(self, container: str, connection_string: Optional[str] = None, account_url: Optional[str] = None):
        from azure.storage.blob import BlobServiceClient

        conn = connection_string or os.getenv("AZURE_STORAGE_CONNECTION_STRING")
        if conn:
            self._service = BlobServiceClient.from_connection_string(conn)
        elif account_url:
            from azure.identity import DefaultAzureCredential
            self._service = BlobServiceClient(account_url=account_url, credential=DefaultAzureCredential())
        else:
            account = os.getenv("AZURE_STORAGE_ACCOUNT")
            if not account:
                raise ValueError("AZURE_STORAGE_CONNECTION_STRING or AZURE_STORAGE_ACCOUNT required")
            url = f"https://{account}.blob.core.windows.net"
            from azure.identity import DefaultAzureCredential
            self._service = BlobServiceClient(account_url=url, credential=DefaultAzureCredential())

        self.container = container
        self._container_client = self._service.get_container_client(container)
        if not self._container_client.exists():
            self._container_client.create_container()

    def put_bytes(self, key: str, data: bytes, content_type: str = "application/octet-stream") -> str:
        blob = self._container_client.get_blob_client(key)
        blob.upload_blob(data, overwrite=True, content_type=content_type)
        return key

    def put_json(self, key: str, data: Any) -> str:
        return self.put_bytes(key, json.dumps(data, indent=2, default=str).encode("utf-8"), "application/json")

    def put_json_if_absent(self, key: str, data: Any) -> bool:
        from azure.core.exceptions import ResourceExistsError

        blob = self._container_client.get_blob_client(key)
        body = json.dumps(data, indent=2, default=str).encode("utf-8")
        try:
            blob.upload_blob(body, overwrite=False, content_type="application/json")
            return True
        except ResourceExistsError:
            return False

    def get_bytes(self, key: str) -> Optional[bytes]:
        blob = self._container_client.get_blob_client(key)
        if not blob.exists():
            return None
        return blob.download_blob().readall()

    def get_json(self, key: str) -> Optional[Any]:
        raw = self.get_bytes(key)
        if raw is None:
            return None
        return json.loads(raw.decode("utf-8"))

    def list_keys(self, prefix: str) -> List[str]:
        return sorted(b.name for b in self._container_client.list_blobs(name_starts_with=prefix))

    def delete(self, key: str) -> bool:
        blob = self._container_client.get_blob_client(key)
        if not blob.exists():
            return False
        blob.delete_blob()
        return True

    def exists(self, key: str) -> bool:
        return self._container_client.get_blob_client(key).exists()
